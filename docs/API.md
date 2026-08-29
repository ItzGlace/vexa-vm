# Vexa-VM API

Vexa-VM exposes a versioned administrator API at `/api/v1` and a deliberately
smaller customer API at `/api/public`. The browser panel uses the same service
layer, but its HTML routes (`/overall`, `/vms`, `/network`, `/isos`, `/settings`
and `/docs`) are not API endpoints.

The machine-readable OpenAPI 3.1 contract is in [`openapi.json`](openapi.json).
The contract is the source of truth for request fields, response schemas and
status codes.

## Base URL and media types

Examples use `https://vm.example.com`; replace it with the HTTPS URL of the
node. JSON requests must send `Content-Type: application/json`. Uploads use
`multipart/form-data`. Responses use UTF-8 JSON unless an endpoint explicitly
upgrades to a websocket.

Do not expose the application's plain HTTP listen port directly to the
internet. Terminate TLS at a trusted reverse proxy and forward only to the
configured Vexa-VM listener.

## Authentication realms

The three authentication mechanisms are intentionally separate.

### Administrator browser session

`POST /api/v1/auth/login` creates the `HttpOnly`, `SameSite=Strict`
`vexa_session` cookie and the readable `vexa_csrf` cookie. They also carry the
`Secure` attribute when secure cookies are enabled, as required in production.
State-changing requests authenticated by the session must copy the CSRF cookie
value into `X-CSRF-Token`. `POST /api/v1/auth/logout` invalidates the
server-side session and returns `{"success":true}`. A bearer API key may also
call logout; because it has no browser session, that authenticated call only
clears any session cookies in the response.

Administrator passwords are Argon2id hashes. They are never encrypted for
later recovery and are never returned by the API.

### Administrator API key

Automation sends an API key as a bearer credential:

```http
Authorization: Bearer vxa_REDACTED
```

The secret is shown only in the response that creates the key. Vexa-VM stores
only its hash. Keys can have an expiry, an optional IPv4/IPv6 CIDR allowlist,
and one or more scopes:

| Scope | Allows |
|---|---|
| `host:read` | Host inventory and host metrics |
| `vms:read` | VM inventory, configuration and metrics |
| `vms:write` | Create, edit and delete VMs; resource changes |
| `vms:power` | Start, stop, reboot, reset, suspend and resume |
| `vms:reinstall` | Reinstall a VM from an enabled ISO/image |
| `vms:password:read` | Reveal a recoverable guest password |
| `vms:password:write` | Replace the encrypted password and apply it live when Vexa Guest Tools is connected |
| `vms:vnc` | Issue a short-lived VNC link |
| `network:read`, `network:write` | IP inventory, DNS defaults, blacklist entries, VM firewall policy and host BCP38 policy |
| `isos:read`, `isos:write` | ISO catalog and image ingestion |
| `settings:read`, `settings:write` | Node settings |
| `admins:read`, `admins:write` | Administrator accounts and credentials |
| `api_keys:read`, `api_keys:write` | API-key lifecycle |
| `audit:read` | Audit events |
| `updates:read` | Signed-update capability, verification, staging and queue status |
| `updates:write` | Check signed releases and stage components; activation and rollback approval additionally require a `super_admin` browser session |
| `jobs:read`, `jobs:write` | Job status and cancellation |
| `*` | Every administrator operation; reserve for super administrators |

Roles place an upper bound on key scopes: `super_admin` can grant all scopes,
`admin` cannot create a more privileged administrator, and `read_only` can use
read scopes only.

`ip_allowlist` on API-key creation is an optional array of IPv4 or IPv6 CIDRs.
When it is non-empty, every bearer-key request must originate from one of those
networks. Vexa-VM uses the socket peer as the source address. It considers
`X-Real-IP`, or the first value in `X-Forwarded-For`, only when the immediate
socket peer is loopback. A reverse proxy that is not connected through
`127.0.0.0/8` or `::1` therefore cannot supply the address used by the
allowlist, rate limiter, audit log, or IP-bound token checks.

### Customer status session

An administrator creates a VM-specific status link with
`POST /api/v1/vms/{vm_id}/status-tokens`. Only the plaintext link returned by
that call contains the secret. The browser flow is:

1. The customer opens `GET /status/{token}`.
2. That server-side handler exchanges the one-time token, sets a VM-scoped
   `HttpOnly` cookie, and redirects to `/status/session`. The browser does not
   make a later API exchange request.
3. The redirect removes the token from the address bar and from subsequent
   history/referrer entries. The original path can still appear in reverse-proxy
   or access logs, so configure those layers to redact status- and VNC-token
   paths.
4. `/api/public` calls can affect only that token's VM and only the granted
   customer scopes.

`POST /api/public/session/exchange` is the JSON-client equivalent and also
accepts one-time VNC link tokens. Likewise, `GET /vnc/{token}` performs the VNC
exchange server-side and redirects to `/vnc/session`.

Customer endpoints never permit changing vCPU, RAM, disk capacity, network
speed, or traffic allowance. A status token may grant these scopes:
`vm:read`, `vm:power`, `vm:reinstall`, `vm:dns`, `vm:password:read`,
`vm:password:write`, `ssh:write`, `firewall:read`, `firewall:write`, and
`vm:vnc`. Firewall scopes are never granted by the default scope set; an
administrator must select them explicitly when creating the link.

Protected `/api/public` endpoints accept only the exchanged `vexa_status`
cookie; the one-time status token is not a bearer credential. Customer writes
also require `X-CSRF-Token` to match `vexa_status_csrf`. Public logout is the
exception: it accepts no authentication or CSRF requirement, revokes any
presented public session cookies, clears them, and returns `204`.

## Guest passwords

Guest passwords must be recoverable for the requested panel feature, so they
are encrypted at rest with AES-256-GCM rather than hashed. Each value has a
unique nonce and VM-bound associated data. The versioned master key is stored
outside SQLite with root-only permissions.

Password reveal endpoints require a dedicated read scope, emit an audit event,
return `Cache-Control: no-store`, and never include the password in VM list or
detail responses. Administrator VM responses expose only `password_present`;
the customer VM response does not include a password-presence flag.

The stored value remains the durable provisioning credential and is not a live
query of the guest. `PUT` first replaces the encrypted database value, then
attempts an authenticated live change when Vexa Guest Tools is connected. The
response's `guest_tools.applied` and `guest_tools.pending` fields distinguish
those outcomes; `guest_agent_applied` is retained as a compatibility boolean.
When live application is unavailable, cloud-image reinstall uses the saved
value in its next seed. For an image whose `install_mode` is `manual`, VM creation
and both administrator and customer reinstall reject a supplied `password`.
Manual creation neither generates nor stores one (`generated_password` is
`null`), and a successful manual reinstall clears any previously stored
provisioning password. The guest credential must be set inside the installer
and is not recoverable by Vexa-VM. A password changed from inside any guest can
likewise differ from the value shown by the reveal endpoint.

An automated reinstall may omit `password` only when the VM already has an
encrypted credential. Otherwise the API rejects the request before queuing a
job; this prevents a delayed provisioning failure after the existing disk has
entered the reinstall workflow. After libvirt accepts the destructive
replacement, Vexa commits the staged credential before applying later network,
power, traffic, and bootstrap steps. If one of those post-steps fails, the job
reports that failure but password reveal continues to return the credential for
the replacement guest; the reinstall itself is not automatically repeated.

## Vexa Guest Tools

Vexa Guest Tools is Vexa-VM's authenticated in-guest control channel for Linux
and Windows. It replaces a dependency on the QEMU guest agent for supported
password, hostname, DNS, SSH-key, and health operations. Protocol v2 sends
AES-256-GCM-encrypted commands and responses over a per-VM virtio-serial socket,
with an outer HMAC and direction-separated keys derived from the per-VM encrypted
secret. It also checks timestamps and nonces to reject stale or replayed requests.
Protocol v1 is not accepted, and channel secrets are never returned by the API.

Installation is opt-in. Set `install_guest_tools: true` on VM creation or
reinstall, or select the equivalent checkbox in the panel. It defaults to
`false`. Linux automated images use cloud-init. Windows automated images must
declare `guest_tools_provisioner=cloudbase-init-nocloud` and
`virtio_serial_driver=installed_signed` in image metadata, include Cloudbase-Init
NoCloud support, and have a provider-supplied trusted, signed virtio-serial driver
already installed. Vexa does not bundle that driver. Only `x86_64`/`amd64`
artifacts are currently supplied. Manual installers and images without automated
cloud initialization are reported as unsupported. The `guest_tools` object
returned with image records states `supported`, `artifact_available`, the
detected `platform`/`provisioner`, and a reason when installation is unavailable.

Creation installs the selected artifact in the guest seed. Reinstall preserves
and reinstalls Guest Tools when it was already enabled, even if the reinstall
request omits the opt-in field. Reinstall stages a fresh channel secret and promotes it only after
the replacement service returns an authenticated health response with the expected version and the
exact credential-bearing seed has been verified detached from live and persistent libvirt state and
unlinked; an
installed-but-offline replacement remains visibly pending. VM detail and customer status responses contain
a safe status object. Administrators can also use
`GET /api/v1/vms/{vm_id}/guest-tools` and
`POST /api/v1/vms/{vm_id}/guest-tools/probe`. A configured status includes
`desired_version`, optional `installed_version`, a `pending`, `ready`, `offline`,
`unavailable`, or `error` state, connection state, and last-seen time; only the
administrator view exposes `last_error`.

Hostname patches and password, DNS, and SSH-key writes persist the desired value
first and then try the live channel. Inspect the returned `guest_tools` result:

- `applied: true`, `pending: false`, `mechanism: "vexa_guest_tools"` means the
  running guest acknowledged the change;
- `applied: false`, `pending: true`, `mechanism: "provisioning"` means the value
  is safely stored for a compatible reinstall but was not changed live.

`guest_agent_applied` remains as a legacy boolean alias for
`guest_tools.applied`; it no longer means that QEMU Guest Agent performed the
operation. An empty DNS list is stored for reinstall and currently returns a
pending result rather than clearing live guest DNS.

## Common behavior

### Errors

Every error has the same shape:

```json
{
  "success": false,
  "error": {
    "code": "validation_error",
    "message": "memory_mib must be at least 256",
    "request_id": "00000000-0000-4000-8000-000000000000"
  }
}
```

Common codes are `validation_error`, `unauthorized`, `forbidden`, `not_found`,
`conflict`, `rate_limited`, `hypervisor_error`, and `internal_error`. Failures in
configuration, SQLite, templates, or filesystem I/O use `configuration_error`,
`database_error`, `template_error`, or `io_error`.
Unknown routes use the same envelope. Report `request_id` when requesting
support.

### Long-running operations

VM creation, deletion, reinstall, power actions, resource resize, and snapshot
creation use durable jobs. A queued operation is returned under the
`operation` property, normally with `202 Accepted`; VM patch always returns
`200 OK` and its `operation` is either a job or `null`. Poll
`GET /api/v1/jobs/{job_id}` until the operation is `succeeded`, `failed`, or
`cancelled`. Snapshot revert and deletion run synchronously and return `200`
and `204`, respectively.

VM-create capacity admission is serialized through publication of the
provisional `creating` row and its job. CPU and RAM allocations in all
non-error VM rows are counted against the administrator's `general.cpu_overcommit_ratio`
and `general.memory_overcommit_ratio`. The host response adds `capacity_policy`,
`schedulable_vcpus`, `available_vcpus`, `schedulable_memory_bytes`, and
`available_memory_bytes`; existing fields, routes, and create payloads are unchanged.
Memory overcommit changes admission accounting only. Libvirt starts every guest at its complete
configured entitlement and Vexa never automatically lowers the guest-visible balloon target. A
`creating` row also reserves its requested
disk capacity until provisioning materializes the disk, preventing concurrent
requests from both consuming the same reported filesystem headroom. The
reservation lock is not held while the job performs hypervisor work.

If libvirt, `/dev/kvm`, or required host privileges are missing,
the API fails the relevant job or returns `503 hypervisor_error`; it does
not pretend that a host operation succeeded.

VM deletion accepts an already-missing libvirt domain and performs up to three
bounded attempts for transient hypervisor, seed-filesystem, or database errors.
The VM database row remains present until its managed credential-bearing
cloud-init seed is absent and that directory entry has been synchronized. Poll
the original job through any scheduled retry; a terminal cleanup error leaves
the row in place so an administrator can correct the host issue and submit a
new delete request.

### Idempotency

`Idempotency-Key` is optional and accepted only by administrator VM
create/patch/delete/power/reinstall, administrator snapshot creation, and
customer reinstall. It is not accepted by IP assignment/release, snapshot
revert/delete, or customer power actions. Keys contain 8-128 safe printable
ASCII characters. VM create and snapshot-create retries with the same key and
request replay the original result. VM deletion also replays its original job
after the VM row has been removed, so a lost `202` response can be retried
safely. Conflicting key reuse returns `409 conflict`.
Other accepting job endpoints pass the key to the durable job store, whose
unique constraint prevents duplicate keys.

```http
Idempotency-Key: provision-customer-42-2026-08-03
```

### Collection and metrics queries

There is no global pagination contract and no endpoint defines or reads
`cursor`. VM,
IP-range, ISO, administrator, and API-key lists are returned in full. The VM
list includes `page.next_cursor: null` only as a compatibility marker; it does
not paginate.

Only the following query parameters are read:

- `GET /api/v1/host/metrics` and
  `GET /api/v1/vms/{vm_id}/metrics`: `since` (Unix seconds), `range`
  (`15m`, `6h`, `24h`/`1d`, or `7d`), and `limit`. When `since` is absent,
  `range` determines the start; the default is one hour.
- `GET /api/v1/ip-addresses`: `family` (`4` or `6`), `scope` (`public` or
  `private`), and `status` (`free`, `reserved`, `used`, or `main`).
- `GET /api/v1/jobs`: `status`, `vm_id`, and `limit` (default 100).
- `GET /api/v1/audit`: `before_id`, `resource_type`, `resource_id`, and
  `limit` (default 100).
- `GET /api/v1/network/blacklist`: `active_only` (default `false`).
- `GET /api/v1/network/abuse-records`: `address`, `vm_id`,
  `unresolved_only` (default `false`), and `limit` (default 100).

Customer metrics accept no query parameters and return the most recent 24
hours, capped at 2,000 stored samples. Unknown query parameters must not be used
as filters because handlers ignore them.

### Time, sizes and percentages

Persisted timestamps are Unix seconds in UTC. Durations ending in `_seconds`
are seconds. Storage and traffic totals ending in `_bytes` are bytes. Guest
memory is MiB and virtual disk capacity is GiB where the field explicitly ends
in `_mib` or `_gib`. Rates ending in `_bps` are bytes per second unless a field
explicitly says `_mbps`. Percentages range from 0 through 100.

`traffic_used_bytes` is accounting data sampled from the VM's cumulative RX
and TX interface counters. Counter resets are treated as zero delta. A null or
zero `traffic_limit_bytes` is unlimited. Once sampled usage exceeds a positive
limit, Vexa-VM sets the VM's primary libvirt link down in both the live and
persistent domain. Raising/removing the limit or calling the traffic reset
endpoint restores only a link that Vexa-VM previously disabled.

## Administrator endpoints

### Authentication and health

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/health` | Public | Process/database/libvirt readiness without sensitive host data |
| `POST` | `/api/v1/auth/login` | Public | Create an administrator browser session |
| `GET` | `/api/v1/auth/me` | Administrator credential | Return actor type/ID, optional administrator record, and permissions |
| `POST` | `/api/v1/auth/logout` | Administrator credential; session writes require CSRF | Revoke the current browser session; an API-key call is an authenticated no-op |

### Host

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/host` | `host:read` | Detected hostname, OS, CPU, RAM, KVM, interfaces, link speeds, IPv4/IPv6 and filesystems |
| `GET` | `/api/v1/host/metrics` | `host:read` | Current or historical CPU, RAM, swap, disk and network metrics |

Detection marks the address used by the default route as the main host IP but
does not automatically treat every detected address as allocatable VM space.
An administrator must configure ranges explicitly.

### Virtual machines

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/vms` | `vms:read` | Complete VM inventory; not paginated |
| `POST` | `/api/v1/vms` | `vms:write` | Queue VM creation; returns a job |
| `GET` | `/api/v1/vms/{vm_id}` | `vms:read` | VM configuration, IPs and current state |
| `PATCH` | `/api/v1/vms/{vm_id}` | `vms:write` | Change editable metadata/resources; hostname changes include a live Guest Tools result and resource changes include an optional resize operation |
| `DELETE` | `/api/v1/vms/{vm_id}` | `vms:write` | Queue domain and storage deletion |
| `POST` | `/api/v1/vms/{vm_id}/actions/{action}` | `vms:power` | `start`, `shutdown`, `force-off`, `reboot`, `reset`, `suspend`, or `resume` |
| `PUT` | `/api/v1/vms/{vm_id}/maintenance` | `vms:write` | Enable/clear a customer-mutation maintenance window with an optional reason |
| `PUT` | `/api/v1/vms/{vm_id}/disk-protection` | `vms:write` | Set the deletion lock and pre-reinstall snapshot policy |
| `GET` | `/api/v1/vms/{vm_id}/metrics` | `vms:read` | CPU, RAM, disk I/O, network rates and traffic counters |
| `POST` | `/api/v1/vms/{vm_id}/traffic/reset` | `vms:write` | Reset accounted traffic to zero and restore a quota-blocked link |
| `POST` | `/api/v1/vms/{vm_id}/reinstall` | `vms:reinstall` | Queue reinstall with an enabled image |
| `GET` | `/api/v1/vms/{vm_id}/dns` | `vms:read` | Read the VM's ordered DNS provisioning records |
| `PUT` | `/api/v1/vms/{vm_id}/dns` | `vms:write` | Replace stored DNS and attempt a live Guest Tools update |
| `GET` | `/api/v1/vms/{vm_id}/password` | `vms:password:read` | Reveal the stored provisioning password; audited and never cached |
| `PUT` | `/api/v1/vms/{vm_id}/password` | `vms:password:write` | Replace the encrypted provisioning password and attempt a live Guest Tools update |
| `GET` | `/api/v1/vms/{vm_id}/ssh-keys` | `vms:read` | Read the VM's stored SSH public keys |
| `PUT` | `/api/v1/vms/{vm_id}/ssh-keys` | `vms:write` | Replace keys and attempt an authenticated live Guest Tools update |
| `GET` | `/api/v1/vms/{vm_id}/guest-tools` | `vms:read` | Read installation, version and connection status without exposing the channel secret |
| `POST` | `/api/v1/vms/{vm_id}/guest-tools/probe` | `vms:read` | Perform an authenticated health probe and refresh status |
| `GET` | `/api/v1/vms/{vm_id}/network-security` | `vms:read` | Read the opt-in firewall/DDoS profile and all VM rules |
| `PATCH` | `/api/v1/vms/{vm_id}/network-security` | `vms:write` | Change the firewall/DDoS profile and reconcile host enforcement |
| `GET` | `/api/v1/vms/{vm_id}/firewall/rules` | `vms:read` | List firewall rules |
| `POST` | `/api/v1/vms/{vm_id}/firewall/rules` | `vms:write` | Create a disabled-by-default rule and reconcile enforcement |
| `PATCH` | `/api/v1/vms/{vm_id}/firewall/rules/{rule_id}` | `vms:write` | Update a rule and reconcile enforcement |
| `DELETE` | `/api/v1/vms/{vm_id}/firewall/rules/{rule_id}` | `vms:write` | Delete a rule and reconcile enforcement |
| `GET` | `/api/v1/vms/{vm_id}/snapshots` | `vms:read` | List snapshots |
| `POST` | `/api/v1/vms/{vm_id}/snapshots` | `vms:write` | Queue snapshot creation |
| `POST` | `/api/v1/vms/{vm_id}/snapshots/{snapshot_id}/revert` | `vms:write` | Revert synchronously and return current hypervisor VM information |
| `DELETE` | `/api/v1/vms/{vm_id}/snapshots/{snapshot_id}` | `vms:write` | Delete synchronously; returns no body |
| `POST` | `/api/v1/vms/{vm_id}/status-tokens` | `vms:write` | Create a VM-scoped customer status link; secret returned once |
| `DELETE` | `/api/v1/vms/{vm_id}/status-tokens/{token_id}` | `vms:write` | Revoke a customer status link |
| `POST` | `/api/v1/vms/{vm_id}/vnc-tokens` | `vms:vnc` | Create a single-use VNC link valid for exactly 600 seconds |

Create example (for blank, cloud-init, and automatic images, the API generates
a guest password when `password` is omitted, `null`, or blank after trimming;
manual installer images do not):

```http
POST /api/v1/vms HTTP/1.1
Host: vm.example.com
Authorization: Bearer vxa_REDACTED
Idempotency-Key: create-example-vm-001
Content-Type: application/json

{
  "name": "example-vm-01",
  "hostname": "example-vm-01",
  "iso_id": "00000000-0000-4000-8000-000000000001",
  "vcpus": 2,
  "memory_mib": 2048,
  "disk_gib": 40,
  "network_limit_mbps": 10000,
  "traffic_limit_bytes": 1099511627776,
  "ip_addresses": ["00000000-0000-4000-8000-000000000002"],
  "dns_servers": ["1.1.1.1", "2606:4700:4700::1111"],
  "install_guest_tools": true,
  "autostart": true
}
```

`ip_address_ids` is accepted as an alias for the canonical `ip_addresses`
field. `PATCH /vms/{vm_id}` can increase disk size but cannot shrink it. A
resource change is represented by the optional `operation` job in the `200`
response. VM metrics report host-observed disk and network counters; there is
no guest-filesystem-usage field in this API.

`suspend` and its alias `pause` freeze a running guest and set its inventory
state to `paused`; `resume` continues it. Maintenance is different: it does not
pause or power off the VM. It leaves customer reads and console access
available while returning `409 conflict` for customer power, reinstall, DNS,
password, SSH-key, firewall, and VNC-token mutations until cleared.

Both disk-protection flags default to `false`. `deletion_lock` rejects VM
deletion. `snapshot_before_reinstall` requires a snapshot to succeed before a
reinstall may replace the disk. These policies are stored in VM metadata and
returned in the enriched administrator VM object.

### VM firewall and DDoS controls

All tenant-selectable VM network protections start disabled: `firewall_enabled`, `ddos_enabled`,
every rule's `enabled` flag, port-scan protection, and invalid-packet dropping
are `false`; default ingress and egress actions are `accept`. Merely creating a
rule therefore cannot cut off a VM. An administrator, or a customer status
session explicitly granted `firewall:write`, must choose and enable policy.
Rate thresholds and rules remain editable while their enforcement switches are
off, but they are inert until the corresponding firewall or DDoS switch is
explicitly enabled. The host's default-on managed-pool ownership guard is
separate and cannot be changed through a VM or customer route.

Profiles support `accept`, `drop`, or `reject` default actions and optional SYN,
UDP, ICMP, and new-connection packet-per-second limits. Enabling DDoS protection
requires at least one configured limiter, port-scan protection, or
invalid-packet dropping. `concurrent_connection_limit` is reserved in the
schema but non-null values are rejected in this release. Rules have priority,
ingress/egress direction, action, `any`/`tcp`/`udp`/`icmp`/`icmpv6` protocol,
optional IPv4/IPv6 source and destination CIDRs, optional TCP/UDP source and
destination port ranges, logging, enablement, and description. Ports are valid
only for TCP/UDP; a VM may have at most 256 rules and each side may contain at
most 64 port ranges.

Profile and rule mutations return an `enforcement` summary. Desired policy is
revisioned separately from applied policy; compare `revision` with
`applied_revision` and inspect `last_error`. A reconciliation error can be
returned after the desired revision was saved, so clients should re-read the
profile rather than assuming the old policy remains active.

Every returned firewall rule includes `owner_type` and nullable `owner_id`.
Administrator-created rules use administrator ownership; status-link rules use
`owner_type: "customer_token"` and identify the creating status token.

### IP ranges, addresses and DNS

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/ip-ranges` | `network:read` | List public/private IPv4 and IPv6 ranges |
| `POST` | `/api/v1/ip-ranges` | `network:write` | Add a CIDR, gateway, bridge/VLAN, MTU and scope |
| `GET` | `/api/v1/ip-ranges/{range_id}` | `network:read` | Get range details |
| `PATCH` | `/api/v1/ip-ranges/{range_id}` | `network:write` | Change range defaults or enabled state |
| `DELETE` | `/api/v1/ip-ranges/{range_id}` | `network:write` | Delete an unused range |
| `GET` | `/api/v1/ip-addresses` | `network:read` | Addresses filtered only by family, scope, or status |
| `POST` | `/api/v1/ip-addresses` | `network:write` | Import an explicit address as free, reserved, used, or main |
| `PATCH` | `/api/v1/ip-addresses/{address_id}` | `network:write` | Set status, assign to `vm_id`, and optionally mark primary |
| `POST` | `/api/v1/ip-addresses/{address_id}/assign` | `network:write` | Atomically assign an available address to a VM |
| `POST` | `/api/v1/ip-addresses/{address_id}/release` | `network:write` | Atomically release an address |
| `DELETE` | `/api/v1/ip-addresses/{address_id}` | `network:write` | Remove an unassigned, non-main explicit address |
| `GET` | `/api/v1/dns/defaults` | `network:read` | Ordered node DNS defaults |
| `PUT` | `/api/v1/dns/defaults` | `network:write` | Replace ordered IPv4/IPv6 DNS defaults |
| `GET` | `/api/v1/network/security` | `network:read` | Read managed-pool ownership and BCP38 policy plus applied revision |
| `PATCH` | `/api/v1/network/security` | `network:write` | Change either host-only switch and atomically reconcile enforcement |
| `GET` | `/api/v1/network/blacklist` | `network:read` | List blacklist entries, optionally active-only |
| `POST` | `/api/v1/network/blacklist` | `network:write` | Add an IPv4/IPv6 address or CIDR to the allocation blacklist |
| `PATCH` | `/api/v1/network/blacklist/{entry_id}` | `network:write` | Change reason, source, expiry, metadata, or enabled state |
| `DELETE` | `/api/v1/network/blacklist/{entry_id}` | `network:write` | Delete a blacklist entry |
| `GET` | `/api/v1/network/abuse-records` | `audit:read` | List provider abuse records by address, VM, unresolved state, and limit |
| `POST` | `/api/v1/network/abuse-records` | `network:write` | Record a timestamped IP abuse report with severity and provider reference |
| `POST` | `/api/v1/network/abuse-records/{record_id}/resolve` | `network:write` | Resolve an abuse record with an audit-visible resolution |

States are `free`, `reserved`, `used`, and `main`. `main` means an address owned
by the KVM host and can never be assigned. Allocation is performed in a SQLite
immediate transaction with a unique address constraint. IPv6 ranges are sparse:
the API returns explicit allocations and does not try to materialize every
address in a `/64`. Address path parameters accept either the record UUID or
the literal IPv4/IPv6 address.

The JSON field that associates an explicit address with an IP range/pool is
`pool_id` in both requests and responses. The resource paths retain the
`/ip-ranges` name for compatibility.

Address collection responses also include derived `blacklisted`,
`pool_enabled`, and `assignable` booleans. `assignable` is true only for a
`free` address that is not covered by an active blacklist entry and is either
unpooled or belongs to an enabled pool. Disabled pools remain visible as
inventory, including existing ownership, but cannot supply a new VM address.
Assignment transactions enforce the same rule even if a client ignores these
hints.

The allocation blacklist applies to new assignment attempts. An enabled,
unexpired entry matches a single address or CIDR and prevents a VM from
acquiring it; it does not disconnect an address already in use. Single
addresses are normalized to `/32` or `/128`. Abuse records are independent
evidence records for datacenter/provider workflows. Their severity is 1-10;
creating or resolving one does not automatically blacklist an address or
change a VM network.

`ip_ownership_guard_enabled` is an administrator-only allocation control and
defaults to `true`. It checks only Vexa-managed pool CIDRs: inbound destinations,
outbound sources, and ARP sender addresses must belong to the VM associated with
the host TAP. This prevents a guest from taking free, reserved, main-node, or
another tenant's managed address through in-guest network changes. The rule is
independent from tenant firewall/DDoS policy and is reconciled immediately after
address ownership changes.

Host BCP38 is a separate administrator-only, opt-in anti-spoofing control and defaults
to disabled so low-end nodes incur no filtering cost until an administrator
accepts and enables it. It validates VM IPv4/IPv6 and ARP sender sources against
assigned addresses while allowing bootstrap-unspecified and IPv6 link-local
traffic, and pins each TAP to the VM's configured Ethernet source MAC to prevent
shared-bridge FDB poisoning. There is no customer BCP38 route. Vexa-created domains use stable TAP
targets; imported domains with auto-generated `vnet*` targets must be given a
persistent target before their policy can be applied reliably. Disabling BCP38
does not disable the default managed-pool ownership guard.

### ISOs and images

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/isos` | `isos:read` | Catalog metadata including install mode and Guest Tools compatibility/artifact availability |
| `POST` | `/api/v1/isos` | `isos:write` | Create image metadata |
| `GET` | `/api/v1/isos/{iso_id}` | `isos:read` | Image catalog detail |
| `PATCH` | `/api/v1/isos/{iso_id}` | `isos:write` | Update catalog metadata |
| `DELETE` | `/api/v1/isos/{iso_id}` | `isos:write` | Delete unused catalog metadata; local files are never removed implicitly |
| `POST` | `/api/v1/isos/{iso_id}/verify` | `isos:write` | Verify a local file, or securely download and verify an HTTPS source |
| `POST` | `/api/v1/isos/upload` | `isos:write` | Stream a bounded multipart upload and verify SHA-256 |

`install_mode` is `cloud_init`, `automatic`, or `manual`. A remote `source_url`
requires a trusted 64-hex-character `checksum_sha256`. Calling `verify` downloads
the image to a unique partial file, follows at most five HTTPS redirects, rejects
credentials and non-public destinations, enforces the 16 GiB limit, and atomically
publishes the file only after its SHA-256 matches. URL and redirect targets use
HTTPS port 443. One remote transfer runs per node at a time, and admission keeps
at least 512 MiB free on the image-storage filesystem after the declared or
expected image size. Uploads and canonical paths inside the configured ISO storage
root remain supported. A `manual` image boots its installer and
cannot receive a Vexa-VM provisioning password: create/reinstall requests that
supply `password` are rejected, no password is generated on create, and a
successful reinstall clears any password previously stored for that VM.

For VM creation, the selected catalog image is authoritative for `os_family`.
If `root_username` is omitted, Vexa-VM uses `Administrator` for Windows images
and `root` for other images. Supplying a valid local account name explicitly
preserves that choice; the server does not replace it when the selected OS changes.

An image is exposed as `available: true` only after server-side hashing succeeds,
the catalog has a SHA-256, and the local file still exists. The metadata keys
`verified_at`, `downloaded_at`, `source`, and `download_error` are reserved for
the server and are cleared from catalog create/patch input. After upgrading from
an older release, re-run verification once for pre-existing local or uploaded
images before provisioning from them.

The `guest_tools` compatibility object is advisory for selection and is
revalidated at create/reinstall time. Linux is inferred for known Linux OS
families unless metadata explicitly selects cloud-init. Windows must explicitly
select `cloudbase-init-nocloud`; artifact availability must also be true before
`install_guest_tools: true` is accepted.

The multipart upload's required fields are `file`, `slug`, and `name`. Uploads
share the same one-transfer-per-node limit and 512 MiB storage reserve as remote
downloads; requests without a declared length reserve the full 16 GiB limit.
`provisioning_mode` is optional and accepts `cloud-init` (or `cloud_init`),
`automatic`, or `manual`; it defaults to `manual`. `sha256` is the optional
expected digest that is checked against the streamed file. `os_family` and
`architecture` are optional, with architecture defaulting to the host. The
presence of the optional `guest_agent` and `uefi` form fields enables those
catalog flags. These upload field names intentionally differ from the catalog
JSON names `install_mode` and `checksum_sha256`.

### Settings, administrators and API keys

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/settings` | `settings:read` | Read persisted settings, environment-owned runtime values and writable section names |
| `PATCH` | `/api/v1/settings` | `settings:write` | Validate and field-merge one or more supported setting sections |
| `PUT` | `/api/v1/admin/credentials` | Browser administrator session | Change the current administrator after verifying `current_password`; all sessions are revoked |
| `GET` | `/api/v1/admins` | `admins:read` | List administrators |
| `POST` | `/api/v1/admins` | `admins:write` | Create an administrator |
| `GET` | `/api/v1/admins/{admin_id}` | `admins:read` | Read one administrator |
| `PATCH` | `/api/v1/admins/{admin_id}` | `admins:write` | Change role or enabled state |
| `PUT` | `/api/v1/admins/{admin_id}/credentials` | `admins:write` | Change username and/or password and revoke all of that administrator's sessions |
| `DELETE` | `/api/v1/admins/{admin_id}` | `admins:write` | Delete an administrator except the last enabled super administrator |
| `GET` | `/api/v1/api-keys` | `api_keys:read` | List key metadata; never returns secrets |
| `POST` | `/api/v1/api-keys` | `api_keys:write` | Create a scoped key; secret returned once |
| `DELETE` | `/api/v1/api-keys/{key_id}` | `api_keys:write` | Revoke a key immediately |

Only these top-level sections are writable:

- `general`: `node_name`, `locale`, `timezone`, `ntp_servers`,
  `sample_interval_seconds`, `metrics_retention_days`, `cpu_overcommit_ratio`,
  and `memory_overcommit_ratio`;
- `network`: `default_bridge`, `default_port_limit_mbps`,
  `default_traffic_quota_bytes`, `allow_unlimited_traffic`, and `dns_servers`.
  Unlimited traffic is disabled by default and can only be enabled globally by
  a signed-in `super_admin`; API keys and delegated administrators cannot
  authorize it. When disabled, legacy zero/null VM quotas are replaced by the
  positive node default (1 TiB if no valid default was previously configured);
- `console`: `vnc_enabled`;
- `security`: `session_lifetime_minutes`, `login_rate_limit`, and
  `api_rate_limit`.

Each supplied section is field-merged with its previous object, then the merged
section is validated and stored. Unknown sections and unknown keys are rejected.
`network.dns_servers` also replaces the node DNS
records used as VM provisioning defaults. The response includes a `runtime`
object containing the environment-owned bind address, public URL, libvirt URI,
storage roots, and secure-cookie flag. Those values cannot be changed through
this endpoint. Administrator credentials use the dedicated credentials
endpoint, not an `account` settings section.

Sampling/retention, CPU and admission-accounted memory overcommit, new-VM network defaults, VNC enablement,
session lifetime, and rate limits are read dynamically by the service. `node_name`, `locale`,
`timezone`, and `ntp_servers` are stored control-plane preferences in this
release; changing them does not rename the Linux host or reconfigure its locale,
clock, or NTP daemon. Network defaults affect later VM provisioning and do not
rewrite existing guests or host interfaces.

### Signed updates

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/updates` | `updates:read` | Read updater availability, current verified release, staged components, and the last queued request ID |
| `POST` | `/api/v1/updates/check` | `updates:write` | Fetch release metadata and verify the latest signed manifest |
| `POST` | `/api/v1/updates/stage` | `updates:write` | Download and re-hash the selected signed Vexa-VM archive |
| `POST` | `/api/v1/updates/approve` | `updates:write` plus `super_admin` browser session | Approve exact manifest/components and queue a 15-minute activation request for the privileged helper |
| `POST` | `/api/v1/updates/rollback` | `updates:write` plus `super_admin` browser session | Explicitly approve the current server-published rollback point and queue a 15-minute rollback request |

The update source is fixed to `ItzGlace/vexa-vm`. A check retrieves bounded
GitHub release metadata, `vexa-vm-update-manifest.json`, and its detached
Ed25519 signature. The manifest is accepted only when its repository, release,
component definitions, asset URLs, signature, trusted key ID, and SHA-256
digest validate against the root-owned trust store. Checking downloads no
component archive and performs no host mutation.

The component names are `vexa-vm`, `qemu`, and `libvirt`. Only the signed
`vexa-vm` archive is accepted by `/updates/stage`; it is limited to 512 MiB and
is published to staging only after its declared size and SHA-256 match. QEMU
and libvirt remain distribution-owned `apt` packages and therefore have no
caller-selected archive to stage. Repeating a valid stage request reuses the
verified artifact. A new check whose manifest differs discards stale staged
artifacts.

Approval is deliberately separate. API keys can check and stage when granted
`updates:write`, but cannot approve activation or rollback. Both approval
routes accept only an authenticated browser session belonging to a
`super_admin`, require CSRF, and require
`maintenance_impact_accepted: true`. Activation approval binds the exact
expected release, manifest digest, and non-empty component set. Rollback
approval accepts only `expected_activation_id`, `expected_previous_release`,
and the maintenance acknowledgement. The server derives the snapshot path,
snapshot digest, manifest digest, component set, and active release from the
current validated root-helper status; callers cannot provide or override any
of those authority-bearing values.

The web process never runs installers, package managers, or service-control
commands. It writes a bounded, approval-bound request to a fixed spool; a
separately installed, root-owned helper revalidates it and performs activation
or rollback. Approval returns `409 conflict` when that helper is not securely
advertising readiness, the rollback point became stale, or the supplied
compare-and-approve fields no longer match it. Queued requests expire after 15
minutes.

The built-in `read_only` role can read updater status, the `admin` role can
check and stage, and only a `super_admin` session can approve. When the trusted
key configuration is unavailable, `GET /api/v1/updates` reports
`enabled: false` and the reason; check, stage, approve, and rollback return
`409 conflict` instead of bypassing verification.

`GET /api/v1/updates` also returns `executor_statuses`,
`latest_executor_status`, and the currently usable `rollback_point` (or
`null`). Executor statuses are bounded, non-secret, root-owned JSON records
sorted newest first. They include operation, phase, percentage, terminal
outcome, package changes, rollback progress, timestamps, and a sanitized
message. The panel rejects unsafe ownership, filenames, schema values, paths,
digests, or impossible completion states. A public rollback point contains
only its activation/release identities, digests, snapshot size, and component
names; the root-only snapshot path and activation receipt are never returned.

Typical flow:

1. Call `POST /api/v1/updates/check` and retain
   `check.release.manifest_sha256` and `check.release.tag`.
2. For `vexa-vm`, call `POST /api/v1/updates/stage` with that digest. Do not
   stage `qemu` or `libvirt`.
3. Present release contents and maintenance impact to a super administrator.
4. From that administrator's browser session, call
   `POST /api/v1/updates/approve` with the exact release, digest, selected
   components, and explicit maintenance acceptance.
5. Use `GET /api/v1/updates` to observe the queued request ID and durable
   executor outcome. Activation execution and receipts are owned by the
   privileged helper, not an API job.
6. If a successful application activation publishes a `rollback_point`, show
   its release transition and maintenance impact to a super administrator.
   Submit its `activation_id` and `previous_release` as the two expected values
   to `POST /api/v1/updates/rollback`; do not cache and reuse an older offer.

Queueing a rollback appends `update.rollback.approve` immediately. That event
records approval, not execution success. A background importer accepts only a
validated terminal helper status and appends `update.activate` or
`update.rollback` exactly once per helper request. A successfully consumed
rollback removes the root-only receipt and clears the original activation's
public rollback point; the helper also rejects a replay after the active
release changes.

### Audit and jobs

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/audit` | `audit:read` | Append-only events filtered by `before_id`, resource type/ID, and `limit` |
| `GET` | `/api/v1/jobs` | `jobs:read` | Jobs filtered by status, VM ID, and `limit` |
| `GET` | `/api/v1/jobs/{job_id}` | `jobs:read` | Job progress, result or sanitized failure |
| `POST` | `/api/v1/jobs/{job_id}/cancel` | `jobs:write` | Cancel a queued job; returns `204` |

Audit filters are limited to `before_id`, `resource_type`, `resource_id`, and
`limit`. Secrets, password values, API-key values, status tokens and VNC tokens
are redacted before event persistence.

## Customer endpoints

These routes operate only on the VM embedded in the status session. They do not
accept a VM ID from the client.

| Method | Path | Customer scope | Purpose |
|---|---|---|---|
| `POST` | `/api/public/session/exchange` | Status token | Exchange a link token for a VM-scoped cookie |
| `POST` | `/api/public/session/logout` | Public | Revoke any presented status/VNC session cookies and clear them; always returns `204` |
| `GET` | `/api/public/vm` | `vm:read` | Customer-safe VM state, resources, IPs, DNS and traffic usage |
| `GET` | `/api/public/vm/metrics` | `vm:read` | VM metrics and traffic usage/allowance |
| `POST` | `/api/public/vm/actions/{action}` | `vm:power` | Start, shutdown, force-off, reboot, or reset |
| `POST` | `/api/public/vm/reinstall` | `vm:reinstall` | Reinstall using an enabled customer-visible image |
| `GET` | `/api/public/vm/dns` | `vm:read` | Read stored DNS provisioning records |
| `PUT` | `/api/public/vm/dns` | `vm:dns` | Replace stored DNS and apply it live when Vexa Guest Tools is connected |
| `GET` | `/api/public/vm/password` | `vm:password:read` | Reveal the stored provisioning password; audited and never cached |
| `PUT` | `/api/public/vm/password` | `vm:password:write` | Replace the encrypted password and attempt a live Guest Tools update |
| `PUT` | `/api/public/vm/ssh-keys` | `ssh:write` | Replace stored SSH public keys and attempt a live Guest Tools update |
| `GET` | `/api/public/vm/firewall` | `firewall:read` | Read the VM firewall/DDoS profile and rules owned by this status link |
| `PUT` | `/api/public/vm/firewall` | `firewall:write` | Change only this VM's opt-in firewall/DDoS profile |
| `GET` | `/api/public/vm/firewall/rules` | `firewall:read` | Read the same profile and this status link's rule set |
| `POST` | `/api/public/vm/firewall/rules` | `firewall:write` | Add a disabled-by-default rule for this VM |
| `PATCH` | `/api/public/vm/firewall/rules/{rule_id}` | `firewall:write` | Update a rule owned by this status link |
| `DELETE` | `/api/public/vm/firewall/rules/{rule_id}` | `firewall:write` | Delete a rule owned by this status link |
| `GET` | `/api/public/isos` | `vm:reinstall` | Enabled images with `available`/`status` fields indicating local usability |
| `GET` | `/api/public/jobs/{job_id}` | Status session | Read a customer-safe job belonging to the session VM |
| `POST` | `/api/public/vm/vnc-token` | `vm:vnc` | Issue a single-use VNC link valid for exactly 600 seconds |

DNS, password, and SSH-key writes always update durable provisioning state.
When the VM opted into Vexa Guest Tools and its authenticated channel is
connected, they also apply inside the running guest. Responses include a
`guest_tools` result with `applied`, `pending`, `status`, `mechanism`, and a
human-readable message, so clients must not infer live success from HTTP 200
alone. Sending an empty `ssh_keys` array clears the stored and managed list.

Firewall write routes require the public CSRF header and are unavailable while
the administrator has placed the VM in maintenance. They cannot change host
BCP38 policy, IP assignments, traffic allowance, link speed, vCPU, RAM, or
disk. Neither firewall scope is present in default status links; the
administrator must grant it explicitly.

Customer firewall access is deliberately narrower than administrator access.
The status API returns only rules owned by the authenticated status-link token and
allows that session to create, edit, or delete only those token-owned rules.
Rules belonging to another link for the same VM remain hidden and immutable.
Such a rule can block up to 32 inbound TCP or UDP destination-port
ranges; it cannot add an allowlist, source/destination CIDR, egress policy,
source-port match, packet logging, or modify administrator/system rules.
Customers may toggle only the VM firewall and DDoS switches. Thresholds, packet checks, default
actions, and administrator/system rules remain administrator-owned. Separately, a customer with
`firewall:write` can create or manage only its own narrow inbound destination-port drop rules
described above.

The VNC token is consumed by `/vnc/{token}` and authorizes only the websocket
for its VM. The websocket stays on the normal HTTPS origin (`wss://...`) and is
proxied to a loopback-only libvirt VNC target. Tokens are hash-only in SQLite,
may be optionally IP-bound, and expire after ten minutes even if unused. The
API never publishes the underlying libvirt or random websockify port.

## Rate limits and caching

- Login is limited by source address and account; public token exchange is
  limited by source address.
- Every authenticated administrator API request shares the configured
  per-actor/source `api_rate_limit` window.
- `429` responses include `Retry-After`.
- Password reveals and responses containing newly issued secrets use
  `Cache-Control: no-store`. Clients must not assume health or metrics responses
  have an application-provided cache lifetime.
- CORS is disabled by default. If enabled, it must use explicit HTTPS origins;
  wildcard origins cannot be combined with credentialed sessions.

## Compatibility names

These guarded unversioned routes are compatibility aliases:

| Method | Compatibility path | Canonical replacement |
|---|---|---|
| `POST` | `/api/create` | `POST /api/v1/vms` |
| `POST` | `/api/set-ip` | `PATCH /api/v1/ip-addresses/{address_id}`; the compatibility body also carries `address` |
| `PATCH` | `/api/set-ip/{address}` | `PATCH /api/v1/ip-addresses/{address_id}` |
| `POST` | `/api/vms/reboot` | `POST /api/v1/vms/{vm_id}/actions/{action}`; the compatibility body carries the VM and optional action |
| `POST` | `/api/vms/{id}/reboot` | `POST /api/v1/vms/{vm_id}/actions/reboot` |

The service also exposes versioned `/api/v1/network/pools`,
`/api/v1/network/addresses`, and `/api/v1/operations` aliases. All aliases call
the same authenticated handlers and do not emit `Deprecation` or `Sunset`
headers. New integrations should use `/api/v1/vms`, `/api/v1/ip-ranges`,
`/api/v1/ip-addresses`, and `/api/v1/jobs`.
