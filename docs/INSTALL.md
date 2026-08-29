# Installation and operations

## Host requirements

- Linux on x86_64 with hardware virtualization enabled.
- KVM/QEMU, libvirt, `virsh`, `virt-install`, `qemu-img`, cloud-image-utils and iproute2.
- A dedicated storage path with enough free capacity for all VM disks and snapshots.
- A correctly configured bridge or routed TAP design. Do not change the host's main route remotely
  without out-of-band console access.
- TLS at the reverse proxy. Direct plain HTTP is appropriate only for isolated evaluation.

The service detects capabilities; it does not silently reconfigure the host's physical network.

## Single-command install

```bash
curl -fsSL https://raw.githubusercontent.com/ItzGlace/vexa-vm/main/install.sh | sudo bash
```

Useful environment overrides:

```bash
curl -fsSL https://raw.githubusercontent.com/ItzGlace/vexa-vm/main/install.sh | \
  sudo VEXA_VERSION=v1.7.0 VEXA_BIND=127.0.0.1:8080 VEXA_PUBLIC_URL=https://vm.example.com bash
```

To enable signed in-panel updates during bootstrap, pin the release publisher's raw 32-byte Ed25519
public key and its published key ID through the root installer environment:

```bash
curl -fsSL https://raw.githubusercontent.com/ItzGlace/vexa-vm/main/install.sh | \
  sudo VEXA_UPDATE_KEY_ID=vexa-release-2026-01 \
  VEXA_UPDATE_PUBLIC_KEY_B64='BASE64_OF_RAW_32_BYTE_PUBLIC_KEY' bash
```

Obtain and verify that key through a channel independent from the GitHub release download. If it is
omitted, installation succeeds but the privileged update units remain disabled and the panel must
show updates as unavailable. The private signing key never belongs on a managed node.

To pin or rotate keys later, install the reviewed JSON trust store at
`/etc/vexa-vm/update-trusted-keys.json` as root:root mode 0644, then run:

```bash
sudo systemctl enable --now vexa-update-executor-ready.service
sudo systemctl enable --now vexa-update-dispatch.service vexa-update-dispatch.path
```

If the executor self-check fails, the first command fails and the readiness marker remains absent;
inspect `journalctl -u vexa-update-executor-ready.service` rather than bypassing the check.

The installer creates the `vexa` service account, private state/storage directories, a root-owned
mode-0640 environment file readable only by the `vexa` service group, an immutable AGPL release under
`/opt/vexa-vm/releases/<version>`, an atomic
`/opt/vexa-vm/current` link, and hardened systemd units. It generates the encryption key and first
administrator password locally. Record the password, then change it in **Settings -> Security**.
The bootstrap installer refuses to replace an existing versioned install; use the explicitly
approved, signed panel updater for subsequent releases.

## Reverse proxy

Install `deploy/nginx.conf` as a site after replacing the hostname, then issue a certificate with your
normal ACME client. VNC uses WebSocket upgrade and must remain same-origin. Preserve `X-Real-IP` (or
`X-Forwarded-For`) on the proxy hop. Vexa-VM trusts those headers only when the immediate socket peer
is loopback; otherwise it ignores them and uses the peer address. The proxy must therefore connect to
the application over `127.0.0.1` or `::1`. Set `VEXA_SECURE_COOKIES=true` when the public URL is HTTPS.

## Manual source install

```bash
sudo apt-get install -y build-essential pkg-config libvirt-daemon-system qemu-kvm qemu-utils p7zip-full \
  virtinst cloud-image-utils sqlite3 nftables iproute2
npm ci && npm run build
cargo build --locked --release
sudo install -Dm0755 target/release/vexa-vm /opt/vexa-vm/releases/1.7.0/bin/vexa-vm
sudo install -Dm0755 target/release/vexa-update-helper \
  /opt/vexa-vm/releases/1.7.0/bin/vexa-update-helper
sudo ln -s releases/1.7.0 /opt/vexa-vm/current
```

Copy `templates`, `static`, `migrations`, `deploy`, and `VERSION` into the same versioned release
directory, install the systemd units, and create `/etc/vexa-vm/vexa-vm.env` from the deployment
example.

Tagged GitHub releases are built for x86_64 by
`.github/workflows/release.yml`. Each archive contains the binary, templates,
self-hosted Tailwind/noVNC assets, migrations, deployment files and manuals; the
single-command bootstrap installer verifies its adjacent SHA-256 file and validates archive paths and
types before extraction. The adjacent checksum protects transfer integrity; it is not the updater's
authorization mechanism. In-panel updates require the separately pinned Ed25519 key and signed
manifest described in [Signed updates](UPDATES.md).

## Backup and restore

Back up all three of the following:

1. `/var/lib/vexa-vm/vexa.db` using SQLite's online backup command, not a plain copy while running;
2. `/etc/vexa-vm/vexa-vm.env`, especially `VEXA_MASTER_KEY`;
3. the VM disk/image storage and any external snapshot/backup target.

Example database backup:

```bash
sudo -u vexa sqlite3 /var/lib/vexa-vm/vexa.db ".backup '/var/backups/vexa-vm-$(date +%F).db'"
```

Restore the DB and matching encryption key together. If the master key is lost, encrypted guest
passwords cannot be recovered. Set a new provisioning value and reinstall a cloud image, or recover
the guest independently through its console.

## Upgrade

Use the panel updater. It requires an Ed25519-signed manifest, explicit component selection and a
short-lived maintenance acknowledgement; creates an online SQLite snapshot; switches the versioned
`current` symlink atomically; and requires both `/healthz` and `/readyz`. Failed application readiness
restores the previous release and matching DB automatically. SQLite migrations are forward-only, so
manual binary-only replacement is unsupported. See [Signed updates](UPDATES.md) for trust, exact APT
handling, durable status and rollback limits.

## Troubleshooting

- `hypervisor_ready=false`: check `/dev/kvm`, `systemctl status libvirtd`, group membership and the
  configured libvirt URI.
- VM create fails before define: verify image checksum/format and storage permissions/free space.
- VM starts but has no network: verify the configured bridge, guest interface, DHCP/static cloud-init,
  forwarding and nftables. Do not mark an IP free until the failed job has released its reservation.
- Console cannot connect: ensure QEMU VNC listens on loopback, the domain exposes a VNC display, the
  proxy forwards WebSockets, and the VNC link has not expired or already been exchanged.
- Guest Tools reports a missing or denied channel: inspect the VM's
  `com.vexa.guest_tools.0` bind socket, QEMU/libvirt account, `vexa` supplementary `kvm` group, and
  AppArmor/SELinux denials. The packaged setgid directory is necessary but socket modes differ by
  libvirt policy; add only a narrow host-specific group/MAC rule and never make the directory or
  socket world-writable.
