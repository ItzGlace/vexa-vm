# Offline account recovery

Vexa 0.2.0 can edit a stopped guest's managed system disk from the hypervisor. No Vexa Guest
Tools, QEMU guest agent, known guest password, or working guest network is required. This is
account reset, not retrieval of the old password. Recovery remains unavailable on the mock backend.

## Prepare the host

On Debian/Ubuntu install the optional host tools from your distribution's signed repositories:

```sh
sudo apt update
sudo apt install libguestfs-tools chntpw
sudo -u vexa libguestfs-test-tool
```

RHEL-family distributions need their supported libguestfs utilities and a trusted chntpw package
for Windows. Package availability varies; do not download an unaudited recovery executable. The
service account needs access to `/dev/kvm`, a readable libguestfs appliance/kernel, and read/write
access to the configured VM disk directory. Keep the existing systemd sandbox. Diagnose access
with `journalctl -u vexa-vm`; grant access only to the intended VM storage, not the whole host.
Libguestfs uses the direct backend with no appliance network. Its guestfs appliance is separate
from the target VM. Disk encryption still requires the appropriate unlock key; this release does
not provide an unlock-key input.

## Recovery procedure

1. Identify the correct VM and **local** account. Verify the customer is authorized to recover it.
2. Shut down completely. Paused/suspended guests and unknown power states are rejected. Quiesce
   external libvirt automation: Vexa serializes its own lifecycle/disk changes, not another root
   process. Do not start the guest outside Vexa while recovery is running.
3. Take a full, restorable disk backup and test your restore procedure. Include backing files when
   applicable. Recovery does not automatically create a backup or roll back partial writes.
4. In VM details choose **Offline password recovery**. Enter the account, recovery method, exact VM
   name, and backup acknowledgment. Do not disconnect or retry while the operation is running.
5. Boot the guest and verify login using VNC. Confirm application health and data access. For
   Windows, immediately set a strong new local password before allowing network access.

A failed or timed-out disk edit may leave a partially modified disk. Inspect/restore the backup
before retrying. The panel never silently runs another recovery method after a failure.

### Linux methods

- `linux-libguestfs`: `virt-customize --no-network --password-crypto sha512 --password USER:file:…`.
  The new password travels through a private temporary file, never a process argument. Libguestfs
  performs OS-aware password modification.
- `linux-shadow`: explicit fallback for conventional Linux `/etc/shadow` systems. A fresh salted
  SHA-512 crypt hash is generated with OpenSSL over stdin; only the exact account's password and
  last-change fields are replaced. Other accounts and policy fields stay unchanged. The shadow
  file is downloaded read-only, validated, then uploaded to the stopped disk. This does not change
  SSH `PasswordAuthentication`, PAM policy, root SSH policy, or unlock a separately disabled account.

Both methods require a 12–256 byte password without control characters. Test compatibility on a
clone first; some guests have different account stores or authentication policy. The hash method
is not a Windows SAM hash-swap implementation.

### Windows method

`windows-sam` downloads the offline local SAM hive through libguestfs, uses `chntpw` to clear the
selected local account's password, verifies the copied hive changed, then uploads it. It does not
set an arbitrary new Windows password offline. Set one in Windows through the graphical console.

This is for supported, unencrypted, cleanly shut-down Windows disks with a conventional local SAM.
It does not reset Active Directory/domain, Microsoft cloud-account, Windows Hello/PIN, or BitLocker
credentials. It does not enable disabled accounts or change group membership. Modern Windows/SAM
formats can differ; validate your guest OS and chntpw version on a disposable clone before use.
Password reset can make EFS files, DPAPI-protected secrets, stored credentials, and certificates
inaccessible. Preserve recovery keys and backups first. A blank password may be prohibited for
remote logins; use VNC. Keep networking isolated during recovery.

## API and permissions

Admin: `POST /api/v1/vms/{id}/recovery`, requiring `vms:recovery` (or superadmin `*`). Legacy
`vms:write` does **not** grant this permission. Browser requests retain normal session/CSRF checks;
API clients use a scoped bearer key. Linux request:

```json
{
  "method": "linux-libguestfs",
  "username": "root",
  "password": "a-new-strong-password",
  "confirmation": "exact-vm-name",
  "backup_confirmed": true
}
```

For Windows use `"method":"windows-sam"`, the local account name, and **omit** `password`.
Safe account names use ASCII letters, digits, `_`, `.`, `-`, and `$`; names with spaces or other
characters need an operator's offline recovery procedure. The primary managed disk must be inside
Vexa's configured storage root. Disks attached to another domain (including hard links and secondary attachments) are refused when visible in its current block-device list. External inactive-definition changes and backing-file sharing still require operator review. Multi-disk guest root volumes,
external writers, unusual backing chains, hibernated NTFS, and encrypted filesystems require separate
operator investigation. Never interpret this endpoint as proof a disk layout is recoverable.

Recovery waits for completion (HTTP limit ten minutes); if the HTTP client disconnects, the owned
operation continues with its lifecycle lock and completion audit. Inspect the audit log before any retry.
Recovery is rate-limited to two attempts per VM per five
minutes, and audited before editing and on completion. Passwords and hashes are excluded from
support audit records and tool error output. Temporary recovery data is removed after the operation;
this is not a guarantee of forensic erasure on a host filesystem. The stored Vexa credential is
updated only after successful Linux recovery of the VM's configured login account; Windows clearing
removes that stored credential. A different recovered local account does not replace it.

Customer: `POST /api/public/vm/recovery` uses the VM-bound status cookie, CSRF, maintenance checks,
and the explicit `recovery:write` scope. This scope is absent from default links and is not implied by
`password:write`. An administrator can enable it when creating a customer status link.

## Validation limits

Automated checks cover request validation, shadow transformations, authorization/CSRF, failed-backend
behavior, and secret-record preservation. They do not boot a Windows guest or prove real disk
recovery. This cloud development host has no KVM device. Before production use, validate each method
on disposable Linux/Windows clones on your actual hypervisor, including restore after an interrupted
operation, guest login, permissions/SELinux labels, and preservation of other users and encrypted data.
