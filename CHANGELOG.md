# Changelog

All notable changes to Vexa-VM are documented here. The project follows Semantic Versioning after
the first stable release.

## 0.1.7 - 2026-08-29

### Security

- Enforce finite traffic allowances in-kernel with a shared nftables byte quota across ingress and
  egress, independently of optional VM firewall and DDoS switches.
- Reassert over-quota link shutdown every five seconds and persist the down state in both live and
  saved libvirt definitions, preventing host restarts or external link changes from reopening access.
- Disable unlimited VM traffic by default. Only a signed-in super administrator can enable it at
  node level; otherwise legacy zero/null allowances receive a positive 1 TiB fallback quota.

### Fixed

- Treat reaching the configured byte limit as exhausted instead of waiting for one additional byte.
- Persist detected TAP names during VM updates and return deterministic libvirt TAP targets during
  first provisioning, preserving fail-closed network policy across stopped-domain creation races.

## 0.1.6 - 2026-08-18

### Fixed

- Reconcile routed public IPv4 `/32` routes immediately when an address is assigned, moved, or
  released, and remove stale per-VM host routes during periodic convergence.
- Safely adopt unambiguous routed topology metadata for legacy libvirt imports so migrated VMs no
  longer fall outside network reconciliation.
- Keep Linux routed guests' public primary address as their outbound source while retaining the
  link-local gateway as an explicit on-link route.
- Allow the hardened Linux Vexa Guest Tools service to open its virtio serial channel.
- Let Guest Tools identify the sole non-loopback NIC when a broken guest has no default route, and
  safely take ownership of cloud-init-generated netplan configuration with rollback on failure.

## 0.1.5 - 2026-08-13

### Added

- Backward-compatible optional `disk_gib` support on administrator reinstall requests. This permits
  a smaller replacement system disk only as part of an explicitly destructive reinstall, while the
  normal VM resize endpoint remains grow-only.
- Host capability flags for safe orchestration of reinstall-time disk replacement and full-memory
  entitlement behavior.

### Fixed

- Memory overcommit now affects admission accounting only: every guest starts with its complete
  configured RAM entitlement instead of a ratio-reduced balloon target.
- Existing running guests whose balloon target was reduced by 0.1.4 are automatically restored to
  their full configured memory, both live and persistently across reboots.
- Removed automatic host-pressure balloon reclamation so a 4 GiB VM remains a 4 GiB VM inside the
  guest while still retaining the VirtIO balloon device for telemetry and explicit repair.

## 0.1.4 - 2026-08-13

### Added

- Configurable CPU and memory overcommit ratios with 4× CPU and 1.5× memory defaults, additive host
  capacity fields, and a Settings panel for live policy changes without altering existing API routes
  or request envelopes.
- Balloon-backed VM admission that preserves each VM's maximum memory entitlement while defining a
  bounded VirtIO balloon floor and retaining host memory headroom.

### Fixed

- Prevented cumulative libvirt interface counters from being charged a second time after a
  temporary zero-counter gap, avoiding false traffic-limit exhaustion and network cutoff after VM
  rebuilds, reboots, or interface sampling gaps.
- Added a regression test covering counter recovery after a zero sample.
- Corrected the remaining legacy repository references in the signed updater manifest and private
  security-report link.

## 0.1.3 - 2026-08-11

### Changed

- Corrected the canonical GitHub repository name from `vaxa-vm` to `vexa-vm` across the signed
  updater, installer, packages, service metadata, documentation, badges, and release links.

## 0.1.2 - 2026-08-11

### Added

- Authoritative live network reconciliation through Vexa Guest Tools for Linux netplan, Windows
  networking, and RouterOS whenever VM addresses are assigned or released.
- Automatic guest address, route, and DNS updates while preserving the same inventory for future
  cloud-init and unattended reinstall provisioning.
- Signed GitHub release delivery configuration for secure one-click updates from the Settings page.

### Changed

- VM address APIs now return the guest-application result and clearly report pending changes when
  an older or disconnected guest agent must be upgraded or reinstalled.

## 0.1.1 - 2026-08-11

### Added

- Default-on managed IP ownership enforcement that binds each VM TAP interface to the public IPv4
  and IPv6 addresses assigned by Vexa-VM, independently from the optional BCP38 policy.
- Shared-bridge and routed per-VM bridge enforcement for inbound and outbound managed-subnet
  traffic, including IPv4 ARP sender-address protection.
- An administrator setting and API field to explicitly disable or re-enable the ownership guard.

### Changed

- IP-pool and address changes now reconcile the ownership rules atomically, with rollback where a
  newly created pool cannot be enforced.
- VM network startup remains fail-closed when required ownership rules cannot be installed.

## 0.1.0 - 2026-08-10

### Added

- Rust/Axum single-node KVM control plane with mock and libvirt hypervisor backends.
- Responsive Tailwind administration panel and versioned REST/OpenAPI interface.
- VM lifecycle, provisioning, snapshots, resize, maintenance, pause/suspend, reinstall and deletion.
- IPv4/IPv6 inventory, routed networking, rate limits, enforced traffic quotas and opt-in firewall,
  DDoS, BCP38, disk-protection and network-protection controls.
- Scoped customer status links and one-time ten-minute same-origin noVNC sessions.
- AES-256-GCM guest secrets, Argon2id accounts, role-based administrators and scoped API keys.
- Linux and Windows Vexa Guest Tools over an authenticated VM-bound virtio-serial channel.
- Host/guest metrics history, durable jobs, activity audit and IP abuse evidence records.
- Verified remote image downloads, signed in-panel update workflow and rollback checks.
- Immutable release archives, one-line installer, Debian packaging and signed APT publication tooling.
