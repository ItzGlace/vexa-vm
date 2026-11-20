//! Host-only support operations. All disk writes share the lifecycle mutation lock.
use super::*;
use crate::hypervisor::RecoveryRequest;

pub(crate) fn validate_recovery(request: &RecoveryRequest) -> HypervisorResult<()> {
    let user = &request.username;
    if user.is_empty()
        || user.len() > 64
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-$".contains(&b))
    {
        return Err(HypervisorError::InvalidInput(
            "use a local account name with safe ASCII characters".into(),
        ));
    }
    if !request.backup_confirmed {
        return Err(HypervisorError::InvalidInput(
            "a tested disk backup must be acknowledged before recovery".into(),
        ));
    }
    match request.method.as_str() {
        "linux-libguestfs" | "linux-shadow" => {
            let password = request.password.as_deref().unwrap_or_default();
            if !(12..=256).contains(&password.len()) || password.chars().any(char::is_control) {
                return Err(HypervisorError::InvalidInput(
                    "password must contain 12–256 bytes without control characters".into(),
                ));
            }
        }
        "windows-sam" if request.password.is_none() => {}
        _ => {
            return Err(HypervisorError::InvalidInput(
                "choose linux-libguestfs, linux-shadow, or windows-sam (no password)".into(),
            ))
        }
    }
    Ok(())
}

// Discard tool stderr: a utility may echo a password, hash, or registry contents.
async fn utility(binary: &str, args: &[&str], input: Option<&[u8]>) -> HypervisorResult<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let program = find_binary(binary).ok_or_else(|| {
        HypervisorError::BackendUnavailable(format!("{binary} is not installed on the hypervisor"))
    })?;
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("LIBGUESTFS_BACKEND", "direct")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let input = input.unwrap_or_default().to_vec();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let task = async {
        let write = async {
            stdin.write_all(&input).await?;
            drop(stdin);
            Ok::<_, std::io::Error>(())
        };
        let read = async {
            let mut bytes = Vec::new();
            stdout.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes).await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let (_, bytes) = tokio::try_join!(write, read)?;
        let status = child.wait().await?;
        if !(status.success() || (binary == "chntpw" && status.code() == Some(2)))
            || bytes.len() > 16 * 1024 * 1024
        {
            return Err(HypervisorError::CommandFailed { operation: binary.into(), message: "support utility failed; disk may be partially changed, inspect the backup before retrying".into() });
        }
        Ok(bytes)
    };
    timeout(Duration::from_secs(150), task)
        .await
        .map_err(|_| HypervisorError::Timeout(binary.into()))?
}

impl LibvirtHypervisor {
    pub(super) async fn recover_password_impl(
        &self,
        name: &str,
        request: &RecoveryRequest,
    ) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        validate_recovery(request)?;
        if request.confirmation != name {
            return Err(HypervisorError::InvalidInput(
                "confirmation must match the VM name".into(),
            ));
        }
        let _guard = self.mutation_lock.lock().await;
        let vm = self.inspect_vm(name).await?;
        if vm.state != VmPowerState::ShutOff {
            return Err(HypervisorError::Conflict(
                "shut down the VM completely before offline recovery; paused and suspended guests are unsafe"
                    .into(),
            ));
        }
        let disk = self
            .validate_managed_existing_disk(
                vm.disk_path
                    .as_deref()
                    .ok_or_else(|| HypervisorError::InvalidInput("VM has no managed system disk".into()))?,
            )
            .await?;
        // Refuse shared managed disks. Out-of-band libvirt operations must be quiesced by the operator.
        let domains = self
            .virsh("recovery-check-domains", &["list", "--all", "--name"])
            .await?;
        for other in domains
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && *line != name)
        {
            validate_vm_name(other)?;
            let disks = self
                .virsh("recovery-check-sharing", &["domblklist", other, "--details"])
                .await?;
            for line in disks.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() >= 4
                    && fields[1] == "disk"
                    && matches!(fields[0], "file" | "block")
                    && fields[3] != "-"
                {
                    let other_disk = tokio::fs::canonicalize(fields[3..].join(" ")).await.map_err(|_| HypervisorError::Conflict("cannot verify disk sharing; resolve inaccessible domain disks before recovery".into()))?;
                    use std::os::unix::fs::MetadataExt;
                    let selected = tokio::fs::metadata(&disk).await?;
                    let candidate = tokio::fs::metadata(other_disk).await?;
                    if (selected.dev(), selected.ino()) == (candidate.dev(), candidate.ino()) {
                        return Err(HypervisorError::Conflict(
                            "recovery refuses a shared system disk".into(),
                        ));
                    }
                }
            }
        }
        let temporary = tempfile::tempdir()?;
        let disk = disk
            .to_str()
            .ok_or_else(|| HypervisorError::InvalidInput("disk path is not UTF-8".into()))?;
        match request.method.as_str() {
            "linux-libguestfs" => {
                let file = temporary.path().join("password");
                use std::os::unix::fs::OpenOptionsExt;
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&file)?;
                std::io::Write::write_all(&mut output, request.password.as_ref().unwrap().as_bytes())?;
                let selector = format!("{}:file:{}", request.username, file.display());
                utility(
                    "virt-customize",
                    &[
                        "--no-network",
                        "-a",
                        disk,
                        "--password-crypto",
                        "sha512",
                        "--password",
                        &selector,
                    ],
                    None,
                )
                .await?;
            }
            "linux-shadow" => {
                let password = format!("{}\n", request.password.as_ref().unwrap());
                let hash = utility("openssl", &["passwd", "-6", "-stdin"], Some(password.as_bytes())).await?;
                let hash = String::from_utf8(hash)
                    .map_err(|_| HypervisorError::InvalidResponse("invalid password hash".into()))?;
                let shadow = temporary.path().join("shadow");
                let local = shadow.to_str().unwrap();
                utility(
                    "guestfish",
                    &["--ro", "-a", disk, "-i", "download", "/etc/shadow", local],
                    None,
                )
                .await?;
                let current = std::fs::read_to_string(&shadow)?;
                let replaced = replace_shadow(&current, &request.username, hash.trim())?;
                std::fs::write(&shadow, replaced)?;
                utility(
                    "guestfish",
                    &["--rw", "-a", disk, "-i", "upload", local, "/etc/shadow"],
                    None,
                )
                .await?;
            }
            "windows-sam" => {
                // chntpw edits only the copied local SAM; upload only after successful edit.
                let sam = temporary.path().join("SAM");
                let local = sam.to_str().unwrap();
                let path = utility(
                    "guestfish",
                    &[
                        "--ro",
                        "-a",
                        disk,
                        "-i",
                        "case-sensitive-path",
                        "/Windows/System32/config/SAM",
                    ],
                    None,
                )
                .await?;
                let path = String::from_utf8(path)
                    .map_err(|_| HypervisorError::InvalidResponse("invalid SAM path".into()))?;
                let path = path.trim();
                if !path.starts_with('/') || path.contains('\n') {
                    return Err(HypervisorError::InvalidResponse("invalid SAM path".into()));
                }
                utility(
                    "guestfish",
                    &["--ro", "-a", disk, "-i", "download", path, local],
                    None,
                )
                .await?;
                let original = std::fs::read(&sam)?;
                utility("chntpw", &["-u", &request.username, local], Some(b"1\nq\ny\n")).await?;
                if std::fs::read(&sam)? == original {
                    return Err(HypervisorError::Conflict(
                        "SAM was not changed; verify the local account and disk backup".into(),
                    ));
                }
                utility(
                    "guestfish",
                    &["--rw", "-a", disk, "-i", "upload", local, path],
                    None,
                )
                .await?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    pub(super) async fn console_screenshot_impl(&self, name: &str) -> HypervisorResult<Vec<u8>> {
        validate_vm_name(name)?;
        let _guard = self.mutation_lock.lock().await;
        self.ensure_domain(name).await?;
        let directory = tempfile::tempdir()?;
        let image = directory.path().join("screen");
        self.virsh(
            "console-screenshot",
            &["screenshot", name, image.to_str().unwrap(), "--screen", "0"],
        )
        .await?;
        if tokio::fs::metadata(&image).await?.len() > 16 * 1024 * 1024 {
            return Err(HypervisorError::InvalidResponse(
                "screenshot exceeds 16 MiB".into(),
            ));
        }
        Ok(tokio::fs::read(image).await?)
    }

    pub(super) async fn console_keys_impl(&self, name: &str, keys: &[String]) -> HypervisorResult<()> {
        validate_vm_name(name)?;
        if keys.is_empty() || keys.len() > 16 || keys.iter().any(|key| !valid_console_key(key)) {
            return Err(HypervisorError::InvalidInput(
                "send 1–16 Linux KEY_ codes from the documented allowlist".into(),
            ));
        }
        let _guard = self.mutation_lock.lock().await;
        self.ensure_domain(name).await?;
        let mut args = vec![
            "send-key".to_owned(),
            name.to_owned(),
            "--codeset".into(),
            "linux".into(),
            "--holdtime".into(),
            "100".into(),
        ];
        args.extend_from_slice(keys);
        self.virsh_owned("console-keys", &args).await?;
        Ok(())
    }
}

pub(crate) fn valid_console_key(key: &str) -> bool {
    matches!(
        key,
        "KEY_ESC"
            | "KEY_ENTER"
            | "KEY_TAB"
            | "KEY_BACKSPACE"
            | "KEY_DELETE"
            | "KEY_INSERT"
            | "KEY_HOME"
            | "KEY_END"
            | "KEY_PAGEUP"
            | "KEY_PAGEDOWN"
            | "KEY_UP"
            | "KEY_DOWN"
            | "KEY_LEFT"
            | "KEY_RIGHT"
            | "KEY_SPACE"
            | "KEY_LEFTCTRL"
            | "KEY_LEFTALT"
            | "KEY_LEFTSHIFT"
            | "KEY_F1"
            | "KEY_F2"
            | "KEY_F3"
            | "KEY_F4"
            | "KEY_F5"
            | "KEY_F6"
            | "KEY_F7"
            | "KEY_F8"
            | "KEY_F9"
            | "KEY_F10"
            | "KEY_F11"
            | "KEY_F12"
    ) || key
        .strip_prefix("KEY_")
        .is_some_and(|k| k.len() == 1 && k.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
}

fn replace_shadow(current: &str, username: &str, hash: &str) -> HypervisorResult<String> {
    if !hash.starts_with("$6$") || hash.contains([':', '\n', '\r']) {
        return Err(HypervisorError::InvalidInput(
            "expected a SHA-512 crypt hash".into(),
        ));
    }
    let mut found = 0;
    let mut lines = Vec::new();
    for line in current.lines() {
        let mut fields: Vec<_> = line.split(':').map(str::to_owned).collect();
        if fields.first().map(String::as_str) == Some(username) {
            if fields.len() != 9 {
                return Err(HypervisorError::InvalidResponse("invalid shadow record".into()));
            }
            fields[1] = hash.into();
            fields[2] = (Utc::now().timestamp() / 86400).to_string();
            found += 1;
        }
        lines.push(fields.join(":"));
    }
    if found != 1 {
        return Err(HypervisorError::InvalidInput(
            "expected exactly one matching shadow account".into(),
        ));
    }
    Ok(lines.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shadow_edit_preserves_other_accounts_and_policy() {
        let result = replace_shadow(
            "root:!:1:0:99999:7:::\nother:!:2:0:9:7:::\n",
            "root",
            "$6$salt$hash",
        )
        .unwrap();
        assert!(result.starts_with("root:$6$salt$hash:"));
        assert!(result.ends_with("other:!:2:0:9:7:::\n"));
        assert!(replace_shadow("root:!:1\n", "root", "$6$x").is_err());
        assert!(replace_shadow("", "missing", "$6$x").is_err());
        assert!(replace_shadow("root:!:1:0:9:7:::\n", "root", "$6$x\nroot:x").is_err());
    }
    #[test]
    fn recovery_and_keys_reject_unsafe_input() {
        let mut request = RecoveryRequest {
            method: "windows-sam".into(),
            username: "Administrator".into(),
            password: None,
            confirmation: "vm".into(),
            backup_confirmed: true,
        };
        assert!(validate_recovery(&request).is_ok());
        request.backup_confirmed = false;
        assert!(validate_recovery(&request).is_err());
        request.backup_confirmed = true;
        request.username = "root:malicious".into();
        assert!(validate_recovery(&request).is_err());
        assert!(valid_console_key("KEY_F2"));
        assert!(!valid_console_key("--help"));
    }
}
