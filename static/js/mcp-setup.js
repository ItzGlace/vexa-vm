(function (root) {
  "use strict";
  function origin(raw) {
    const url = new URL(raw);
    const local = url.hostname === "localhost" || url.hostname === "[::1]" || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(url.hostname);
    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && local))) {
      throw new Error("Use the node's HTTPS origin without a path or credentials. HTTP is allowed only for loopback development.");
    }
    return url.origin;
  }
  function configuration({ apiOrigin, scriptPath, format, writes }) {
    const api = origin(apiOrigin);
    if (!scriptPath || scriptPath.length > 4096 || /[\r\n\0]/.test(scriptPath)) throw new Error("Enter the full local path where you saved vexa_mcp.py.");
    const environment = { VEXA_MCP_URL: api };
    if (writes === true) environment.VEXA_MCP_ALLOW_WRITES = "1";
    if (format === "codex") {
      return `[mcp_servers.vexa_admin]\ncommand = "python3"\nargs = [${JSON.stringify(scriptPath)}]\nenv_vars = ["VEXA_MCP_API_KEY"]\nstartup_timeout_sec = 20\ntool_timeout_sec = 660\n\n[mcp_servers.vexa_admin.env]\n${Object.entries(environment).map(([key,value]) => `${key} = ${JSON.stringify(value)}`).join("\n")}\n`;
    }
    return JSON.stringify({ mcpServers: { "vexa-admin": { command: "python3", args: [scriptPath], env: environment } } }, null, 2) + "\n";
  }
  root.VexaMcpSetup = { origin, configuration, async init({ api, copyText, prepareKey }) {
    const panel = document.querySelector('[data-settings-panel="mcp"]'); if (!panel) return;
    const field = (id) => document.getElementById(id);
    let content = "";
    const update = () => {
      try {
        content = configuration({ apiOrigin: field("mcp-origin").value, scriptPath: field("mcp-script-path").value, format: field("mcp-client-format").value, writes: field("mcp-writes").checked });
        field("mcp-config").textContent = content;
        field("mcp-config-error").textContent = "";
      } catch (error) { content = ""; field("mcp-config").textContent = "Complete the connection settings to generate your client configuration."; field("mcp-config-error").textContent = error.message; }
      field("mcp-copy").disabled = !content; field("mcp-download-config").disabled = !content;
    };
    panel.querySelectorAll("input, select").forEach((input) => input.addEventListener("input", update));
    field("mcp-copy").onclick = () => copyText(content, "MCP client configuration copied");
    field("mcp-download-config").onclick = () => {
      if (!content) return;
      const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
      const link = document.createElement("a"); link.href = url; link.download = field("mcp-client-format").value === "codex" ? "vexa-mcp.toml" : "vexa-mcp.json"; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    field("mcp-create-key").onclick = prepareKey;
    try {
      const setup = await api("/api/v1/mcp/setup");
      field("mcp-origin").value = setup.api_origin || location.origin;
      field("mcp-bridge-version").textContent = `Bridge version ${setup.version} · stdio`;
      field("mcp-create-key").disabled = !setup.can_create_key;
      field("mcp-setup-status").textContent = "Download the bridge below, save it on your trusted computer, and configure your AI client.";
    } catch (error) {
      field("mcp-setup-status").textContent = error.message;
      field("mcp-origin").value = location.origin;
      field("mcp-create-key").disabled = true;
    }
    update();
  } };
  if (typeof module !== "undefined") module.exports = { origin, configuration };
})(typeof globalThis !== "undefined" ? globalThis : window);
