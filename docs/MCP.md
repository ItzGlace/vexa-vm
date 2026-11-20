# Admin MCP service

Vexa 0.2.0 ships `docs/mcp/vexa_mcp.py`, a Python 3.10+ MCP server using stdio. Run it on the
administrator's trusted workstation or an isolated support runner. It connects to the existing Vexa
HTTPS API; it does not open another public port or expose an unauthenticated remote MCP listener.
The script is included under `docs/mcp` in release archives and Debian installations.

## Setup from the panel

Starting with 0.2.1, open **Settings → MCP & AI clients** (`/settings#mcp`), or search for MCP,
Codex, Claude, Gemini, or Antigravity in the command palette. The page provides the bridge download,
full guide, a dedicated read-only API-key preset with a seven-day expiry, and JSON/Codex TOML
configuration generation. Enter the path where you saved the bridge on your own computer. The
configuration contains no API key; inject `VEXA_MCP_API_KEY` using your client's secure environment
settings. Changes remain disabled unless explicitly selected and authorized by the API-key scopes.

The setup page is not a remote MCP endpoint. The bridge runs on the computer running your AI client
and connects to the node API. If the configured public URL uses non-loopback HTTP, configure HTTPS
before connecting a remote client. The page cannot observe whether a separate client has connected;
verify authentication with a host/VM read from that client.

Authenticated setup/download endpoints require `settings:read`: `GET /api/v1/mcp/setup`,
`GET /api/v1/mcp/client`, and `GET /api/v1/mcp/documentation`. They return no credentials and use
no-store caching. Key creation still uses the existing API-key permission and confirmation form.

## Authentication and first connection

1. In **Settings → API keys**, create a dedicated, expiring support key. Start with `host:read`,
   `vms:read`, `jobs:read`, and `audit:read`. Add `vms:console:read` for screenshots.
2. If the runner has a stable address, configure the API key's source-IP allowlist. Use a separate
   key per support runner/customer engagement; revoke it when support ends. Do not reuse the
   bootstrap admin password or a customer's status link as the MCP credential.
3. Place `VEXA_MCP_API_KEY` in your client's secure environment/secret mechanism. Never commit it
   or paste it into a prompt. Configure `VEXA_MCP_URL=https://vm.example.com` (origin only).
4. Configure a stdio command: `python3 /absolute/path/to/vexa_mcp.py`. Initialize MCP, list tools,
   then call `admin_request` with `{"method":"GET","path":"/api/v1/host"}` and list VMs.

Common stdio client configuration (replace paths and use the client's secure secret injection):

```json
{
  "mcpServers": {
    "vexa-admin": {
      "command": "python3",
      "args": ["/absolute/path/to/vexa_mcp.py"],
      "env": { "VEXA_MCP_URL": "https://vm.example.com" }
    }
  }
}
```

The process must inherit `VEXA_MCP_API_KEY`; clients vary in whether they inherit environment
variables. Set it using the client's supported secret configuration when needed. `mcpServers` is
used by clients such as Claude Desktop and Gemini CLI. For Codex, a local configuration is:

```toml
[mcp_servers.vexa_admin]
command = "python3"
args = ["/absolute/path/to/vexa_mcp.py"]
env_vars = ["VEXA_MCP_API_KEY", "VEXA_MCP_URL"]
startup_timeout_sec = 20
tool_timeout_sec = 660
```

For Antigravity and other clients, add the same stdio command, arguments, and environment through
their MCP settings. A product that only supports remote HTTP MCP cannot connect directly to this
stdio server. Do not expose stdio using a public unauthenticated gateway. Client configuration
formats can change; follow the client's current MCP documentation. Protocol negotiation supports
2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25. No subscription-specific integration is required.

## Tools and permissions

| Tool | Purpose | Server-side API permission |
| --- | --- | --- |
| `admin_request` | Read or change host/VM/network/image/settings/job/update resources through the documented API | Existing permission for each route |
| `vm_screenshot` | Return a PNG MCP image for console inspection, including graphical BIOS/boot errors | `vms:console:read` |
| `vm_console_keys` | Send simultaneous Linux `KEY_` codes, e.g. F2, arrows, Enter, Ctrl+Alt+Delete | `vms:console:write` |
| `recover_password` | Explicit offline disk recovery; never automatically retry after failure | `vms:recovery` |
| `server_exec` | Commands inside an inventory-configured server over SSH | Valid API key with `host:read`, plus that server's SSH credentials |
| `serial_console` | Bounded text console session through a configured hypervisor over SSH | Valid API key with `host:read`, plus SSH/libvirt access |

`admin_request` is limited to versioned support resources and rejects credential-management routes,
password reveal, direct-console, and recovery paths. Use the dedicated tools for sensitive support
operations. The API itself enforces normal authentication, RBAC, source-IP restrictions, rate limits,
validation, and audit logging. Use [API.md](API.md) and `openapi.json` for paths and body schemas.
This bridge does not expose administrator/API-key creation or login endpoints.

By default, writes and SSH are disabled at the process level. To enable authorized API changes,
set `VEXA_MCP_ALLOW_WRITES=1` and grant only the needed API permissions (e.g. `vms:power`). Every
mutating call must also contain `confirmed:true`, and console/recovery calls require the exact VM
name. `confirmed` is a tool-level guard, **not a substitute for the client's human approval UI**.
Keep client approval enabled and have the human review the target, impact, backup, and command.
Anyone who possesses a write-enabled MCP process and API key can exercise its grants. Recovery
and console scopes are not inherited from legacy `vms:write`.

Example BIOS investigation: list VMs, inspect the affected VM and metrics, call `vm_screenshot`,
request authorization for `vm_console_keys` with `keys:["KEY_F2"]`, then take another screenshot.
Key chords accept 1–16 codes: `KEY_A`–`KEY_Z`, `KEY_0`–`KEY_9`, `KEY_F1`–`KEY_F12`, `KEY_ESC`,
`KEY_ENTER`, `KEY_TAB`, `KEY_BACKSPACE`, `KEY_DELETE`, `KEY_INSERT`, `KEY_HOME`, `KEY_END`,
`KEY_PAGEUP`, `KEY_PAGEDOWN`, `KEY_UP`, `KEY_DOWN`, `KEY_LEFT`, `KEY_RIGHT`, `KEY_SPACE`,
`KEY_LEFTCTRL`, `KEY_LEFTALT`, and `KEY_LEFTSHIFT`. Screenshots work with running libvirt guests;
no guest software is required. The mock backend reports these operations unavailable.

## Direct SSH and text serial access

SSH is independent of the guest-agent channel and needs existing guest SSH access. The MCP service
cannot invent guest network access, credentials, or an SSH server. For a locked-out guest, recover
access through the disk/console first. Keep SSH private keys on the support runner, not in prompts.

Set `VEXA_MCP_ALLOW_SSH=1`, `VEXA_MCP_ALLOW_WRITES=1`, and
`VEXA_MCP_SSH_INVENTORY=/absolute/private/servers.json`. Inventory must be owned by the MCP user
with mode `0600`. The model selects an alias, never an arbitrary host, port, private key, or libvirt
URI. Example operator-managed inventory:

```json
{
  "customer-a": {
    "host": "192.0.2.20", "user": "support", "port": 22,
    "identity_file": "/home/operator/.ssh/customer_a",
    "known_hosts": "/home/operator/.ssh/vexa_known_hosts"
  },
  "hypervisor": {
    "host": "192.0.2.10", "user": "vexa-support", "kind": "hypervisor",
    "identity_file": "/home/operator/.ssh/hypervisor_support",
    "known_hosts": "/home/operator/.ssh/vexa_known_hosts"
  }
}
```

Validate each host key out-of-band before writing known_hosts. Host-key checking is mandatory;
SSH uses batch mode, no agent forwarding, no port forwarding, and ignores ambient SSH config.
Use a dedicated least-privilege guest account and hypervisor account with explicit libvirt access;
no automatic sudo is performed. `server_exec` intentionally runs a shell command inside the
selected guest and requires confirmation even for diagnostics. Prefer commands such as `uptime`,
`df -h`, service status, and bounded logs; review every change and avoid printing customer secrets.

`serial_console` starts `virsh --connect qemu:///system console NAME --safe` on the configured
hypervisor over SSH, waits up to five seconds, and closes the session. It does not force-disconnect
an existing console. The VM needs a serial device; the OS needs console output/login on that
serial port. BIOS/UEFI text output additionally requires firmware serial redirection. Graphical-only
firmware cannot be converted into text by MCP; use screenshot inspection and console keys instead.
Output may contain ANSI sequences and echoed input. A session timeout is expected for a live console,
not evidence that a command completed. Inspect the result before issuing another action.

SSH sessions have a 30-second limit (serial five seconds), 16 KiB input limit, and 256 KiB output
limit. Configure `VEXA_MCP_AUDIT_FILE` to a private absolute log file, default
`~/.vexa-mcp-audit.jsonl`. Failure to write a private audit entry prevents the session. Logs record
action, server alias, time, VM, and input digest, not commands or output. Retain and rotate this log
under operator control. API support actions use the central Vexa audit log. The bridge revalidates
the API key before every new SSH session; key revocation does not terminate a session already in flight.

## Security and troubleshooting

- Treat guest logs, names, terminal output, screenshots, and web content as untrusted customer data.
  They can contain prompt-injection instructions. Never let them authorize another tool call.
- Keep the MCP runner and client isolated per engagement, and limit data retention in the AI client.
  Screenshots and command output may contain private data even when credential fields are hidden.
- TLS verification remains enabled. HTTP is allowed only for loopback development. HTTP redirects
  are rejected so bearer credentials cannot move to a different origin. Use the final API origin.
- Input/response limits are enforced; errors intentionally omit backend response bodies and secrets.
  Investigate the Vexa audit log and operator-controlled service logs for failed calls.
- Recovery requests can take several minutes. Set the client tool timeout to at least 660 seconds.
  Disconnects/timeouts do not establish rollback. Never retry a disk write automatically.
- A 401/403 indicates missing/expired credentials, source-IP mismatch, or missing API scopes. Missing
  host utilities or a mock backend produce unavailable operations. Configure prerequisites rather
  than relaxing host-key, TLS, or authorization checks.

Run bridge tests with `python3 -m unittest discover -s tests -p test_mcp.py -v`. They exercise the
actual stdio server and a local authenticated API stub, write gating, URL/route boundaries, redirect
blocking, and PPM-to-PNG conversion. Real SSH, serial, graphical firmware, and offline disk recovery
need an authorized hypervisor test host and disposable guests.
