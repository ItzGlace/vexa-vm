(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const page = document.body?.dataset.page || "";
  const GiB = 1024 ** 3;
  const MiB = 1024 ** 2;

  const state = {
    vms: [],
    vmCursor: null,
    ips: [],
    pools: [],
    images: [],
    currentVm: null,
    publicVm: null,
    auth: null,
    secretTimer: null,
    createCapacity: null,
    freshStatusLink: null,
    updates: null,
  };

  class ApiError extends Error {
    constructor(message, status = 0, code = "request_failed", requestId = "", details = null) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.code = code;
      this.requestId = requestId;
      this.details = details;
    }
  }

  function cookie(name) {
    const match = document.cookie.split("; ").find((item) => item.startsWith(`${name}=`));
    return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
  }

  function csrfToken() {
    const embedded = $("meta[name='csrf-token']")?.content || "";
    const publicRealm = page === "status" || page === "vnc" || location.pathname.startsWith("/status") || location.pathname.startsWith("/vnc");
    return embedded || (publicRealm ? cookie("vexa_status_csrf") : cookie("vexa_csrf")) || cookie("csrf_token") || "";
  }

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const token = csrfToken();
      if (token) headers.set("X-CSRF-Token", token);
    }
    let body = options.body;
    if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== "string") {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
    const response = await fetch(path, {
      ...options,
      method,
      headers,
      body,
      credentials: "same-origin",
      cache: options.cache || "no-store",
    });
    const requestId = response.headers.get("x-request-id") || "";
    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (response.status !== 204) {
      payload = contentType.includes("json") ? await response.json().catch(() => null) : await response.text().catch(() => "");
    }
    if (!response.ok) {
      const error = payload?.error || payload || {};
      const message = typeof error === "string" ? error : error.message || `Request failed with status ${response.status}`;
      throw new ApiError(message, response.status, error.code || "request_failed", error.request_id || requestId, error.details || null);
    }
    return payload;
  }

  async function apiFirst(paths, options = {}) {
    let lastError;
    for (const path of paths) {
      try {
        return await api(path, options);
      } catch (error) {
        lastError = error;
        if (!(error instanceof ApiError) || ![404, 405].includes(error.status)) throw error;
      }
    }
    throw lastError || new ApiError("No compatible endpoint is available.");
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
    })[character]);
  }

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (value === null || value === undefined || value === "") return [];
    return [value];
  }

  function listPayload(payload) {
    if (Array.isArray(payload)) return { items: payload, page: {} };
    return { items: payload?.items || payload?.data || payload?.results || [], page: payload?.page || {} };
  }

  function finite(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function operationTerminalError(operation) {
    if (!operation || !["failed", "cancelled"].includes(operation.status)) return null;
    const detail = operation.error;
    const message = typeof detail === "string"
      ? detail.trim()
      : detail?.message || operation.message || (operation.status === "cancelled" ? "Operation was cancelled" : "Operation failed");
    const code = typeof detail === "object" && detail?.code
      ? detail.code
      : operation.status === "cancelled" ? "operation_cancelled" : "operation_failed";
    const requestId = typeof detail === "object" && detail?.request_id ? detail.request_id : "";
    return new ApiError(
      message || (operation.status === "cancelled" ? "Operation was cancelled" : "Operation failed"),
      operation.status === "cancelled" ? 409 : 400,
      code,
      requestId,
    );
  }

  function clamp(value, minimum = 0, maximum = 100) {
    return Math.min(maximum, Math.max(minimum, finite(value)));
  }

  function bytes(value, digits = 1) {
    const count = finite(value);
    if (count === 0) return "0 B";
    const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    const index = Math.min(Math.floor(Math.log(Math.abs(count)) / Math.log(1024)), units.length - 1);
    const scaled = count / (1024 ** Math.max(0, index));
    return `${scaled.toFixed(index === 0 ? 0 : digits)} ${units[Math.max(0, index)]}`;
  }

  function bitsPerSecond(value) {
    const count = finite(value);
    const units = ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    if (count <= 0) return "0 bit/s";
    const index = Math.min(Math.floor(Math.log(count) / Math.log(1000)), units.length - 1);
    return `${(count / (1000 ** index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function byteRate(value) {
    return `${bytes(value)}/s`;
  }

  function dateTime(value) {
    if (!value) return "Never";
    const date = typeof value === "number" && value < 1e12 ? new Date(value * 1000) : new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function unixSeconds(value) {
    if (!value) return null;
    const timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) ? Math.floor(timestamp / 1000) : null;
  }

  function relativeTime(value) {
    if (!value) return "Unknown";
    const date = typeof value === "number" && value < 1e12 ? new Date(value * 1000) : new Date(value);
    const delta = date.getTime() - Date.now();
    const abs = Math.abs(delta);
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    if (abs < 60_000) return formatter.format(Math.round(delta / 1000), "second");
    if (abs < 3_600_000) return formatter.format(Math.round(delta / 60_000), "minute");
    if (abs < 86_400_000) return formatter.format(Math.round(delta / 3_600_000), "hour");
    return formatter.format(Math.round(delta / 86_400_000), "day");
  }

  function percent(value, digits = 0) {
    return `${finite(value).toFixed(digits)}%`;
  }

  function splitLines(value) {
    return String(value || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
  }

  let uuidFallbackCounter = 0;

  function randomUuid() {
    const cryptoApi = window.crypto || window.msCrypto;
    if (cryptoApi && typeof cryptoApi.randomUUID === "function") {
      try {
        return cryptoApi.randomUUID();
      } catch {
        // randomUUID can be unavailable in non-secure HTTP contexts even when
        // the rest of the Web Crypto API is present.
      }
    }

    const values = new Uint8Array(16);
    if (cryptoApi && typeof cryptoApi.getRandomValues === "function") {
      cryptoApi.getRandomValues(values);
    } else {
      // Idempotency keys are collision guards, not credentials. This final
      // fallback keeps older browsers usable when Web Crypto is absent.
      uuidFallbackCounter = (uuidFallbackCounter + 1) >>> 0;
      let seed = (Date.now() ^ uuidFallbackCounter) >>> 0;
      for (let index = 0; index < values.length; index += 1) {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        values[index] = (Math.floor(Math.random() * 256) ^ (seed >>> 24)) & 255;
      }
    }

    values[6] = (values[6] & 15) | 64;
    values[8] = (values[8] & 63) | 128;
    const hex = Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function setText(selector, value, root = document) {
    const element = typeof selector === "string" ? $(selector, root) : selector;
    if (element) element.textContent = value ?? "";
  }

  function setProgress(selector, value) {
    const element = typeof selector === "string" ? $(selector) : selector;
    if (!element) return;
    const normalized = clamp(value);
    element.style.width = `${normalized}%`;
    element.closest(".metric-track")?.setAttribute("role", "progressbar");
    element.closest(".metric-track")?.setAttribute("aria-valuenow", String(Math.round(normalized)));
    element.closest(".metric-track")?.setAttribute("aria-valuemin", "0");
    element.closest(".metric-track")?.setAttribute("aria-valuemax", "100");
  }

  function statusInfo(rawState) {
    const value = String(rawState || "unknown").toLowerCase().replaceAll("_", "-");
    if (["running", "on", "active", "up"].includes(value)) return { key: "running", label: "Running", dot: "bg-emerald-300", classes: "border-emerald-300/20 bg-emerald-300/[.07] text-emerald-200" };
    if (["stopped", "off", "offline", "shutoff", "shutdown"].includes(value)) return { key: "stopped", label: "Stopped", dot: "bg-slate-400", classes: "border-white/10 bg-white/[.035] text-slate-300" };
    if (["paused", "suspended"].includes(value)) return { key: "paused", label: "Paused", dot: "bg-amber-300", classes: "border-amber-300/20 bg-amber-300/[.07] text-amber-200" };
    if (["building", "creating", "provisioning", "reinstalling", "pending"].includes(value)) return { key: "building", label: "Building", dot: "bg-orbit-300", classes: "border-orbit-300/20 bg-orbit-300/[.07] text-orbit-300" };
    if (["error", "failed", "crashed"].includes(value)) return { key: "error", label: value === "crashed" ? "Crashed" : "Error", dot: "bg-rose-300", classes: "border-rose-300/20 bg-rose-300/[.07] text-rose-200" };
    if (["locked", "blocked"].includes(value)) return { key: "locked", label: "Locked", dot: "bg-nebula-300", classes: "border-nebula-300/20 bg-nebula-300/[.07] text-nebula-200" };
    return { key: value, label: value === "unknown" ? "Unknown" : value.replace(/(^|-)(\w)/g, (_, space, letter) => `${space ? " " : ""}${letter.toUpperCase()}`), dot: "bg-slate-500", classes: "border-white/10 bg-white/[.025] text-slate-400" };
  }

  function statusBadge(rawState) {
    const status = statusInfo(rawState);
    return `<span class="badge ${status.classes}"><span class="h-1.5 w-1.5 rounded-full ${status.dot}" aria-hidden="true"></span>${escapeHtml(status.label)}</span>`;
  }

  function normalizeVm(vm = {}) {
    const metrics = vm.metrics || vm.usage || vm.stats || {};
    const network = vm.network || {};
    const traffic = vm.traffic_quota || vm.traffic || {};
    const image = vm.image || {};
    const structuredIps = asArray(vm.ip_addresses || vm.addresses);
    const byIp = (scope, family) => structuredIps.filter((item) => typeof item === "object" && (!scope || item.scope === scope) && (item.family === family || item.family === (family === "ipv4" ? "v4" : "v6"))).map((item) => item.address);
    const structuredPublicV4 = byIp("public", "ipv4"); const structuredPublicV6 = byIp("public", "ipv6");
    const structuredPrivateV4 = byIp("private", "ipv4"); const structuredPrivateV6 = byIp("private", "ipv6");
    const publicV4 = vm.public_ipv4 || network.public_ipv4 || (structuredPublicV4.length ? structuredPublicV4 : (vm.public_ip && !String(vm.public_ip).includes(":") ? [vm.public_ip] : []));
    const publicV6 = vm.public_ipv6 || network.public_ipv6 || (structuredPublicV6.length ? structuredPublicV6 : (vm.public_ip && String(vm.public_ip).includes(":") ? [vm.public_ip] : []));
    const ramTotal = finite(vm.ram_bytes, finite(vm.ram_mb ?? vm.ramMB) * MiB);
    const ramUsed = finite(metrics.ram_used_bytes, finite(metrics.ram_mb) * MiB);
    const diskTotal = finite(vm.disk_bytes, finite(vm.disk_gb ?? vm.diskGB) * GiB);
    const trafficLimit = vm.traffic_limit_bytes ?? traffic.limit_bytes ?? (finite(vm.traffic_quota_mb) > 0 ? finite(vm.traffic_quota_mb) * MiB : null);
    const trafficUsed = finite(vm.traffic_used_bytes ?? traffic.used_bytes ?? metrics.traffic_used_bytes ?? metrics.used_bytes);
    return {
      ...vm,
      id: vm.id || vm.uuid || vm.name,
      name: vm.name || vm.hostname || "Unnamed VM",
      hostname: vm.hostname || vm.name || "—",
      state: vm.state || vm.power_state || "unknown",
      osName: image.name || image.display_name || vm.os_name || vm.os_family || vm.os || vm.iso || vm.image_slug || "Unknown OS",
      osVersion: image.version || vm.os_version || "",
      publicV4: asArray(publicV4),
      publicV6: asArray(publicV6),
      privateV4: asArray(vm.private_ipv4 || network.private_ipv4 || structuredPrivateV4),
      privateV6: asArray(vm.private_ipv6 || network.private_ipv6 || structuredPrivateV6),
      cpu: finite(vm.cpu ?? vm.vcpus, 1),
      cpuPct: finite(metrics.cpu_pct ?? metrics.cpu_percent ?? vm.cpu_pct),
      ramTotal,
      ramUsed: finite(metrics.memory_used_bytes, ramUsed),
      ramPct: finite(metrics.ram_pct, ramTotal > 0 ? finite(metrics.memory_used_bytes, ramUsed) * 100 / ramTotal : 0),
      diskTotal,
      diskPhysical: finite(vm.disk_physical_bytes ?? metrics.disk_used_bytes),
      diskReadBps: finite(metrics.disk_read_bps),
      diskWriteBps: finite(metrics.disk_write_bps),
      rxBps: finite(metrics.net_rx_bps ?? metrics.network_rx_bps ?? metrics.rx_bps ?? metrics.rx_rate_bps ?? metrics.instant_rx_Bps),
      txBps: finite(metrics.net_tx_bps ?? metrics.network_tx_bps ?? metrics.tx_bps ?? metrics.tx_rate_bps ?? metrics.instant_tx_Bps),
      trafficUsed,
      trafficLimit: trafficLimit === null || finite(trafficLimit) <= 0 ? null : finite(trafficLimit),
      trafficPct: trafficLimit && finite(trafficLimit) > 0 ? trafficUsed * 100 / finite(trafficLimit) : null,
      trafficBlocked: Boolean(traffic.network_blocked ?? vm.traffic_network_blocked),
      trafficExceeded: Boolean(traffic.exceeded ?? (trafficLimit && trafficUsed > finite(trafficLimit))),
      trafficEnforcementError: traffic.enforcement_error || null,
      portMbps: finite(vm.port_limit_mbps ?? vm.network_limit_mbps ?? network.port_limit_mbps, 0),
      dns: asArray(vm.dns_servers || network.dns_servers || vm.dns).map((item) => typeof item === "object" ? item.address : item).filter(Boolean),
      owner: vm.owner || vm.related_user_service_id || "—",
      tags: asArray(vm.tags),
      guestAgent: Boolean(vm.guest_agent ?? vm.guest_agent_available),
      allowedActions: asArray(vm.allowed_actions || vm.available_actions),
    };
  }

  function formObject(form) {
    const result = {};
    const data = new FormData(form);
    for (const [key, value] of data.entries()) {
      if (key in result) result[key] = asArray(result[key]).concat(value);
      else result[key] = value;
    }
    for (const checkbox of $$("input[type='checkbox'][name]", form)) {
      if (!data.has(checkbox.name)) result[checkbox.name] = false;
      else if (checkbox.value === "on" && !Array.isArray(result[checkbox.name])) result[checkbox.name] = true;
    }
    return result;
  }

  function fillForm(form, values = {}) {
    if (!form) return;
    for (const field of $$('[name]', form)) {
      if (!(field.name in values)) continue;
      const value = values[field.name];
      if (field.type === "checkbox") field.checked = Array.isArray(value) ? value.includes(field.value) : Boolean(value);
      else if (field.type === "radio") field.checked = String(field.value) === String(value);
      else if (field.multiple) {
        const selected = asArray(value).map(String);
        for (const option of field.options) option.selected = selected.includes(option.value);
      } else if (Array.isArray(value) && field.tagName === "TEXTAREA") field.value = value.join("\n");
      else field.value = value ?? "";
    }
  }

  function toast(message, kind = "info", requestId = "") {
    const region = $("#toast-region");
    if (!region) return;
    const styles = kind === "error" ? "border-rose-300/25 bg-rose-950/95 text-rose-100" : kind === "success" ? "border-emerald-300/25 bg-emerald-950/95 text-emerald-100" : "border-orbit-300/20 bg-slate-950/95 text-slate-100";
    const item = document.createElement("div");
    item.className = `pointer-events-auto rounded-2xl border p-4 shadow-2xl backdrop-blur-xl ${styles}`;
    item.setAttribute("role", kind === "error" ? "alert" : "status");
    item.innerHTML = `<div class="flex items-start gap-3"><div class="min-w-0 flex-1"><p class="text-sm font-normal">${escapeHtml(message)}</p>${requestId ? `<p class="mt-1 font-mono text-[10px] opacity-60">${escapeHtml(requestId)}</p>` : ""}</div><button type="button" class="-mr-1 -mt-1 grid h-8 w-8 place-items-center rounded-lg opacity-60 hover:bg-white/10 hover:opacity-100" aria-label="Dismiss notification">×</button></div>`;
    $("button", item).addEventListener("click", () => item.remove());
    region.append(item);
    window.setTimeout(() => item.remove(), kind === "error" ? 9000 : 5000);
  }

  async function copyText(value, success = "Copied") {
    try {
      await navigator.clipboard.writeText(String(value));
      toast(success, "success");
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = String(value);
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.append(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
      toast(success, "success");
    }
  }

  function randomPassword(length = 22) {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-";
    const values = new Uint32Array(length);
    const cryptoApi = window.crypto || window.msCrypto;
    if (!cryptoApi || typeof cryptoApi.getRandomValues !== "function") {
      throw new ApiError("Secure password generation is not available in this browser. Enter a password manually.");
    }
    cryptoApi.getRandomValues(values);
    return Array.from(values, (value) => alphabet[value % alphabet.length]).join("");
  }

  function confirmAction({ title = "Confirm action", message = "", phrase = "", confirmLabel = "Confirm", danger = true } = {}) {
    const dialog = $("#confirm-dialog");
    if (!dialog) return Promise.resolve(window.confirm(message));
    setText("#confirm-title", title, dialog);
    setText("#confirm-message", message, dialog);
    setText("#confirm-phrase-label", phrase, dialog);
    const phraseWrap = $("#confirm-phrase-wrap", dialog);
    const phraseInput = $("#confirm-phrase", dialog);
    const submit = $("#confirm-submit", dialog);
    phraseWrap?.classList.toggle("hidden", !phrase);
    if (phraseInput) phraseInput.value = "";
    if (submit) {
      submit.textContent = confirmLabel;
      submit.className = danger ? "btn-danger" : "btn-primary";
      submit.disabled = Boolean(phrase);
    }
    phraseInput?.addEventListener("input", () => { submit.disabled = phraseInput.value !== phrase; }, { once: false });
    if (!dialog.open) dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm" && (!phrase || phraseInput?.value === phrase)), { once: true });
    });
  }

  function renderChart(container, series, options = {}) {
    if (!container) return;
    const valid = series.map((item) => ({ ...item, values: asArray(item.values).map((value) => finite(value)) })).filter((item) => item.values.length);
    if (!valid.length) {
      container.innerHTML = '<p class="text-sm text-slate-500">No samples are available for this range.</p>';
      return;
    }
    const width = 900;
    const height = 260;
    const padding = { left: 42, right: 18, top: 18, bottom: 28 };
    const maxPoints = Math.max(...valid.map((item) => item.values.length));
    const maximum = Math.max(1, finite(options.max), ...valid.flatMap((item) => item.values));
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const colors = ["#21a8ff", "#aa55f7", "#9aa6ff", "#72e3b2"];
    const lines = valid.map((item, seriesIndex) => {
      const points = item.values.map((value, index) => {
        const x = padding.left + (maxPoints <= 1 ? plotWidth / 2 : index * plotWidth / (maxPoints - 1));
        const y = padding.top + plotHeight - clamp(value / maximum, 0, 1) * plotHeight;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");
      return `<polyline points="${points}" fill="none" stroke="${item.color || colors[seriesIndex % colors.length]}" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round" ${seriesIndex ? `stroke-dasharray="${4 + seriesIndex * 2} ${3 + seriesIndex}"` : ""}/>`;
    }).join("");
    const grids = [0, .25, .5, .75, 1].map((ratio) => {
      const y = padding.top + plotHeight * ratio;
      const label = options.formatY ? options.formatY(maximum * (1 - ratio)) : Math.round(maximum * (1 - ratio));
      return `<line x1="${padding.left}" x2="${width - padding.right}" y1="${y}" y2="${y}" stroke="rgba(255,255,255,.07)"/><text x="${padding.left - 8}" y="${y + 4}" text-anchor="end" fill="#64748b" font-size="10">${escapeHtml(label)}</text>`;
    }).join("");
    const legend = valid.map((item, index) => `<span class="inline-flex items-center gap-1.5"><span class="h-0.5 w-4" style="background:${item.color || colors[index % colors.length]}"></span>${escapeHtml(item.label)}</span>`).join("");
    container.innerHTML = `<div class="h-full w-full"><svg viewBox="0 0 ${width} ${height}" class="h-[calc(100%-2rem)] w-full" role="img" aria-label="${escapeHtml(options.label || "Performance chart")}">${grids}${lines}</svg><div class="flex flex-wrap justify-center gap-4 px-3 text-[10px] text-slate-500">${legend}</div></div>`;
  }

  async function followOperation(payload, onUpdate = () => {}) {
    const directOperation = payload?.id && (payload?.status || payload?.kind) ? payload : null;
    const operation = payload?.data?.operation || payload?.operation || directOperation;
    if (!operation?.id) return operation || payload;
    if (["succeeded", "failed", "cancelled"].includes(operation.status)) {
      onUpdate(operation);
      const terminalError = operationTerminalError(operation);
      if (terminalError) throw terminalError;
      return operation;
    }
    let current = operation;
    for (let attempt = 0; attempt < 180; attempt += 1) {
      onUpdate(current);
      await new Promise((resolve) => window.setTimeout(resolve, Math.min(1000 + attempt * 50, 3000)));
      const response = await apiFirst([`/api/v1/jobs/${encodeURIComponent(operation.id)}`, `/api/v1/operations/${encodeURIComponent(operation.id)}`]);
      current = response?.operation || response;
      if (["succeeded", "failed", "cancelled"].includes(current?.status)) {
        onUpdate(current);
        const terminalError = operationTerminalError(current);
        if (terminalError) throw terminalError;
        return current;
      }
    }
    throw new ApiError("The operation is still running. Check the VM page for progress.", 408, "operation_timeout");
  }

  function setLiveState(kind, label) {
    const dot = $("#live-indicator");
    const text = $("#live-label");
    if (dot) dot.className = `h-1.5 w-1.5 rounded-full ${kind === "live" ? "bg-emerald-300" : kind === "error" ? "bg-rose-300" : "bg-amber-300"}`;
    if (text) text.textContent = label;
  }

  function initGlobalUi() {
    if (!["login", "public-status", "public-vnc", "error"].includes(page)) {
      api("/api/v1/auth/me").then((payload) => {
        const auth = payload?.data || payload || {};
        state.auth = auth;
        const username = auth.admin?.username || "Admin";
        setText("#account-username", username);
        setText("#account-initial", username.slice(0, 1).toUpperCase());
      }).catch(() => {});
    }
    const sidebar = $("#sidebar");
    const backdrop = $("#mobile-backdrop");
    const sidebarTrigger = $("[data-open-sidebar]");
    const toggleSidebar = (open) => {
      sidebar?.classList.toggle("-translate-x-full", !open);
      backdrop?.classList.toggle("hidden", !open);
      sidebarTrigger?.setAttribute("aria-expanded", String(open));
    };
    sidebarTrigger?.addEventListener("click", () => toggleSidebar(true));
    $$('[data-close-sidebar]').forEach((element) => element.addEventListener("click", () => toggleSidebar(false)));

    const navKey = page.startsWith("vm-") ? "vms" : page;
    $(`[data-nav='${CSS.escape(navKey)}']`)?.classList.add("nav-link-active");

    const accountTrigger = $("[data-account-trigger]");
    const accountMenu = $("[data-account-menu]");
    accountTrigger?.addEventListener("click", () => {
      const open = accountMenu?.classList.toggle("hidden") === false;
      accountTrigger.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("click", (event) => {
      if (accountMenu && !accountMenu.classList.contains("hidden") && !accountMenu.contains(event.target) && !accountTrigger?.contains(event.target)) {
        accountMenu.classList.add("hidden");
        accountTrigger?.setAttribute("aria-expanded", "false");
      }
    });
    $("[data-logout]")?.addEventListener("click", async () => {
      try { await api("/api/v1/auth/logout", { method: "POST", body: {} }); } catch { /* session is cleared locally by navigation too */ }
      location.assign("/login");
    });

    $$('[data-toggle-input]').forEach((button) => button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.toggleInput);
      if (!input) return;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.setAttribute("aria-pressed", String(show));
      if (button.textContent.trim() === "Show" || button.textContent.trim() === "Hide") button.textContent = show ? "Hide" : "Show";
    }));
    $$('[data-generate-password]').forEach((button) => button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.generatePassword);
      if (!input) return;
      input.value = randomPassword();
      input.type = "text";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      copyText(input.value, "Generated password copied");
    }));
    $$('[data-refresh-page]').forEach((button) => button.addEventListener("click", () => location.reload()));

    const commandDialog = $("#command-dialog");
    const commandInput = $("#command-input");
    const commands = [
      ["Overall", "/overall", "Host health and capacity"], ["Virtual machines", "/vms", "Guest inventory"], ["Create VM", "/vms/create", "Provision a new guest"], ["Activity logs", "/logs", "Audit and abuse records"],
      ["Network", "/network", "IP pools and defaults"], ["Images & ISOs", "/isos", "Installation library"], ["Settings", "/settings", "Node configuration"], ["API documentation", "/docs", "REST API reference"],
    ];
    const renderCommands = () => {
      const query = commandInput?.value.trim().toLowerCase() || "";
      const results = commands.filter((item) => item.join(" ").toLowerCase().includes(query));
      const target = $("#command-results");
      if (target) target.innerHTML = results.map(([name, href, description], index) => `<a href="${href}" class="flex items-center justify-between rounded-xl px-3 py-2.5 ${index === 0 ? "bg-white/[.05]" : ""}"><span><span class="block text-sm font-normal text-slate-200">${name}</span><span class="block text-xs text-slate-500">${description}</span></span><span class="text-xs text-slate-600">↵</span></a>`).join("") || '<p class="px-3 py-5 text-center text-sm text-slate-500">No matching pages</p>';
    };
    $("[data-command-trigger]")?.addEventListener("click", () => { renderCommands(); commandDialog?.showModal(); requestAnimationFrame(() => commandInput?.focus()); });
    commandInput?.addEventListener("input", renderCommands);
    commandInput?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        const first = $("a", $("#command-results"));
        if (first) location.assign(first.href);
      }
    });
    document.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        $("[data-command-trigger]")?.click();
      }
    });
  }

  async function initLogin() {
    const form = $("#login-form");
    if (!form) return;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const errorBox = $("#login-error");
      errorBox?.classList.add("hidden");
      if (!form.reportValidity()) return;
      const submit = $("button[type='submit']", form);
      const original = submit?.innerHTML;
      if (submit) { submit.disabled = true; submit.textContent = "Signing in…"; }
      try {
        const body = formObject(form);
        const response = await api("/api/v1/auth/login", { method: "POST", body });
        if (response?.requires_totp || response?.mfa_required) {
          $("#totp-field")?.classList.remove("hidden");
          $("#login-totp")?.setAttribute("required", "");
          $("#login-totp")?.focus();
          if (response?.challenge_id) form.dataset.challengeId = response.challenge_id;
          return;
        }
        location.assign(response?.redirect || "/overall");
      } catch (error) {
        if (errorBox) {
          errorBox.textContent = error.message || "Sign in failed.";
          errorBox.classList.remove("hidden");
          errorBox.focus();
        }
      } finally {
        if (submit) { submit.disabled = false; submit.innerHTML = original; }
      }
    });
  }

  function extractHost(payload) {
    return payload?.host || payload?.data || payload || {};
  }

  function extractMetrics(payload) {
    return payload?.metrics || payload?.data || payload || {};
  }

  async function loadOverall(range = state.overallRange || "24h") {
    state.overallRange = ["1h", "24h", "7d"].includes(range) ? range : "24h";
    range = state.overallRange;
    setLiveState("connecting", "Updating");
    const [hostResult, metricsResult, vmResult, operationsResult, auditResult] = await Promise.allSettled([
      api("/api/v1/host"),
      api(`/api/v1/host/metrics?range=${encodeURIComponent(range)}`),
      api("/api/v1/vms?limit=200"),
      apiFirst(["/api/v1/jobs?limit=6", "/api/v1/operations?limit=6"]),
      api("/api/v1/audit?limit=6"),
    ]);
    if (hostResult.status === "rejected" && metricsResult.status === "rejected") throw hostResult.reason;
    const host = hostResult.status === "fulfilled" ? extractHost(hostResult.value) : {};
    const metrics = metricsResult.status === "fulfilled" ? extractMetrics(metricsResult.value) : {};
    const vms = vmResult.status === "fulfilled" ? listPayload(vmResult.value).items.map(normalizeVm) : [];
    const operations = operationsResult.status === "fulfilled" ? listPayload(operationsResult.value).items : [];
    const audit = auditResult.status === "fulfilled" ? listPayload(auditResult.value).items : [];

    const hostname = host.hostname || host.node_name || host.name || "Local node";
    const detectedAt = host.detected_at || host.updated_at || metrics.sampled_at;
    setText("#overview-subtitle", `${hostname} · ${host.primary_ip || host.listen_address || "address pending"}${detectedAt ? ` · updated ${relativeTime(detectedAt)}` : ""}`);
    setText("#sidebar-node-name", hostname);

    const cpu = metrics.cpu || {};
    const memory = metrics.memory || metrics.ram || {};
    const storage = metrics.storage || metrics.disk || {};
    const network = metrics.network || metrics.net || {};
    const cpuPct = finite(cpu.usage_pct ?? metrics.cpu_pct);
    const memTotal = finite(memory.total_bytes, finite(host.ram_total_bytes ?? host.memory_bytes));
    const memUsed = finite(memory.used_bytes);
    const memPct = finite(memory.usage_pct, memTotal ? memUsed * 100 / memTotal : 0);
    const diskTotal = finite(storage.total_bytes ?? storage.capacity_bytes);
    const diskUsed = finite(storage.used_bytes ?? storage.physical_used_bytes);
    const diskPct = finite(storage.usage_pct, diskTotal ? diskUsed * 100 / diskTotal : 0);
    const rxBps = finite(network.rx_bps ?? network.receive_bps ?? network.rx_bytes_per_second);
    const txBps = finite(network.tx_bps ?? network.transmit_bps ?? network.tx_bytes_per_second);
    const cpuThreads = finite(host.cpu_threads ?? host.cpu_logical_cores ?? host.cpu_cores ?? cpu.total);
    const allocatedCpu = finite(host.allocated_vcpus, vms.reduce((sum, vm) => sum + vm.cpu, 0));
    const allocatedRam = finite(host.allocated_ram_bytes, vms.reduce((sum, vm) => sum + vm.ramTotal, 0));

    setText("#metric-cpu", percent(cpuPct, 1)); setProgress("#metric-cpu-bar", cpuPct);
    setText("#metric-cpu-detail", `${finite(cpu.cores ?? host.cpu_cores)} cores · ${cpuThreads} threads · measured load`);
    setText("#metric-memory", percent(memPct, 1)); setProgress("#metric-memory-bar", memPct);
    setText("#metric-memory-detail", `${bytes(memUsed)} of ${bytes(memTotal)} used`);
    setText("#metric-storage", percent(diskPct, 1)); setProgress("#metric-storage-bar", diskPct);
    setText("#metric-storage-detail", `${bytes(diskUsed)} of ${bytes(diskTotal)} physically used`);
    setText("#metric-network", bitsPerSecond((rxBps + txBps) * 8));
    setText("#metric-rx", byteRate(rxBps)); setText("#metric-tx", byteRate(txBps));
    setText("#metric-network-detail", network.interface ? `Interface ${network.interface}` : "Across detected interfaces");

    setText("#capacity-cpu", `${allocatedCpu} / ${cpuThreads || "—"}`); setProgress("#capacity-cpu-bar", cpuThreads ? allocatedCpu * 100 / cpuThreads : 0);
    setText("#capacity-memory", `${bytes(allocatedRam)} / ${bytes(memTotal)}`); setProgress("#capacity-memory-bar", memTotal ? allocatedRam * 100 / memTotal : 0);
    const ipCapacity = host.ip_capacity || metrics.ip_capacity || {};
    const ipTotal = finite(ipCapacity.total); const ipUsed = finite(ipCapacity.used);
    setText("#capacity-ips", ipTotal ? `${ipUsed} / ${ipTotal}` : "Not configured"); setProgress("#capacity-ips-bar", ipTotal ? ipUsed * 100 / ipTotal : 0);
    const states = vms.reduce((result, vm) => { const key = statusInfo(vm.state).key; result[key] = (result[key] || 0) + 1; return result; }, {});
    setText("#vm-running", states.running || 0); setText("#vm-stopped", states.stopped || 0); setText("#vm-issues", (states.error || 0) + (states.locked || 0));

    const samples = asArray(metrics.samples || metrics.history);
    const series = samples.length ? [
      { label: "CPU %", values: samples.map((item) => item.cpu_pct ?? item.cpu_percent) },
      { label: "RAM %", values: samples.map((item) => item.memory_pct ?? item.ram_pct ?? (finite(item.memory_total_bytes) ? finite(item.memory_used_bytes) * 100 / finite(item.memory_total_bytes) : 0)), color: "#aa55f7" },
    ] : [
      { label: "CPU %", values: asArray(cpu.history || metrics.cpu_history) },
      { label: "RAM %", values: asArray(memory.history || metrics.memory_history), color: "#aa55f7" },
    ];
    renderChart($("#performance-chart"), series, { label: "Host CPU and memory usage", max: 100, formatY: (value) => `${Math.round(value)}%` });
    const rangeLabel = range === "7d" ? "Last 7 days" : range === "24h" ? "Last 24 hours" : "Last hour";
    setText("#performance-range-label", rangeLabel);
    setText("#performance-summary", samples.length ? `${rangeLabel} · ${samples.length} samples. Current CPU ${percent(cpuPct, 1)}, memory ${percent(memPct, 1)}.` : `No samples are available for ${rangeLabel.toLowerCase()}.`);
    $$('[data-range]').forEach((button) => {
      const active = button.dataset.range === range;
      button.classList.toggle("bg-white/10", active);
      button.classList.toggle("text-white", active);
      button.classList.toggle("text-slate-500", !active);
      button.setAttribute("aria-pressed", String(active));
    });

    const services = asArray(host.services || metrics.services);
    const serviceList = $("#service-list");
    if (serviceList) {
      serviceList.innerHTML = services.length ? services.map((service) => {
        const healthy = [true, "healthy", "running", "active", "ok"].includes(service.healthy ?? service.status);
        return `<div class="flex items-center gap-3 py-3"><span class="h-2.5 w-2.5 shrink-0 rounded-full ${healthy ? "bg-emerald-300" : "bg-rose-300"}" aria-hidden="true"></span><div class="min-w-0 flex-1"><p class="truncate text-sm font-normal text-slate-300">${escapeHtml(service.name || service.service)}</p><p class="truncate text-xs text-slate-600">${escapeHtml(service.message || service.status || (healthy ? "Healthy" : "Unavailable"))}</p></div><span class="text-xs ${healthy ? "text-emerald-300" : "text-rose-300"}">${healthy ? "Healthy" : "Issue"}</span></div>`;
      }).join("") : '<p class="py-5 text-sm text-slate-500">No service checks were reported.</p>';
    }
    const unhealthy = services.filter((service) => ![true, "healthy", "running", "active", "ok"].includes(service.healthy ?? service.status)).length;
    const summary = $("#service-health-summary");
    if (summary) { summary.textContent = unhealthy ? `${unhealthy} issue${unhealthy === 1 ? "" : "s"}` : "All healthy"; summary.className = `badge ${unhealthy ? "border-rose-300/20 text-rose-200" : "border-emerald-300/20 text-emerald-200"}`; }

    const activity = [...operations.map((item) => ({ ...item, _source: "operation" })), ...audit.map((item) => ({ ...item, _source: "audit" }))].sort((a, b) => finite(b.created_at ?? b.occurred_at ?? b.timestamp) - finite(a.created_at ?? a.occurred_at ?? a.timestamp)).slice(0, 7);
    const activityList = $("#activity-list");
    if (activityList) activityList.innerHTML = activity.length ? activity.map((item) => `<li class="flex gap-3 py-3"><span class="mt-1 h-2 w-2 shrink-0 rounded-full ${item.status === "failed" || item.result === "failed" || item.success === false ? "bg-rose-300" : item.status === "running" ? "bg-orbit-300" : "bg-nebula-300"}"></span><div class="min-w-0 flex-1"><p class="truncate text-sm font-normal text-slate-300">${escapeHtml(item.title || item.kind || item.action || "Node activity")}</p><p class="truncate text-xs text-slate-600">${escapeHtml(item.resource_name || item.resource_id || item.actor || [item.actor_type, item.actor_id].filter(Boolean).join(":") || "System")}</p></div><time class="shrink-0 text-xs text-slate-600">${escapeHtml(relativeTime(item.created_at || item.occurred_at || item.timestamp))}</time></li>`).join("") : '<li class="py-5 text-sm text-slate-500">No recent activity.</li>';

    const addresses = asArray(host.ip_addresses || host.addresses);
    const facts = [
      ["Hostname", hostname],
      ["Listen address", host.listen_address ? `${host.listen_address}:${host.listen_port || ""}`.replace(/:$/, "") : (host.primary_ip || "—")],
      ["CPU", `${host.cpu_model || "Detected CPU"} · ${finite(host.cpu_cores)} cores`],
      ["Memory", bytes(memTotal)],
      ["Public IPs", addresses.filter((item) => (item.scope || "").toLowerCase() === "public").map((item) => item.address || item).join(", ") || host.primary_ip || "—"],
      ["Network interface", host.public_interface || network.interface || "—"],
      ["Virtualization", host.virtualization || (host.kvm_available ? "KVM available" : "Unknown")],
      ["Kernel", host.kernel || host.os || "—"],
    ];
    const hostFacts = $("#host-facts");
    if (hostFacts) hostFacts.innerHTML = facts.map(([label, value]) => `<div class="min-w-0"><dt class="text-xs text-slate-500">${escapeHtml(label)}</dt><dd class="mt-1 truncate text-sm font-normal text-slate-200" title="${escapeHtml(value)}">${escapeHtml(value)}</dd></div>`).join("");
    setText("#host-detected-at", detectedAt ? `Detected ${dateTime(detectedAt)}` : "");

    const alerts = asArray(host.alerts || metrics.alerts);
    const alertRegion = $("#overview-alerts");
    if (alertRegion) alertRegion.innerHTML = alerts.map((alert) => `<div class="rounded-xl border ${alert.severity === "critical" ? "border-rose-300/20 bg-rose-300/[.07] text-rose-100" : "border-amber-300/20 bg-amber-300/[.07] text-amber-100"} p-4 text-sm"><p class="font-normal">${escapeHtml(alert.title || "Node alert")}</p><p class="mt-1 text-xs opacity-70">${escapeHtml(alert.message || "")}</p></div>`).join("");
    $("#sidebar-health-dot")?.classList.replace("bg-amber-300", unhealthy ? "bg-rose-300" : "bg-emerald-300");
    setText("#sidebar-node-meta", unhealthy ? `${unhealthy} service issue${unhealthy === 1 ? "" : "s"}` : "All services healthy");
    setLiveState("live", "Live");
  }

  async function initOverall() {
    try { await loadOverall(); } catch (error) {
      setLiveState("error", "Unavailable");
      $("#overview-alerts")?.insertAdjacentHTML("beforeend", `<div class="rounded-xl border border-rose-300/20 bg-rose-300/[.07] p-4 text-sm text-rose-100" role="alert"><p class="font-normal">Node metrics could not be loaded</p><p class="mt-1 text-xs text-rose-200/70">${escapeHtml(error.message)}</p>${error.requestId ? `<p class="mt-2 font-mono text-[10px] text-rose-200/50">${escapeHtml(error.requestId)}</p>` : ""}</div>`);
    }
    $("[data-refresh-activity]")?.addEventListener("click", () => loadOverall());
    $$('[data-range]').forEach((button) => button.addEventListener("click", () => {
      const range = button.dataset.range;
      if (range) loadOverall(range).catch((error) => toast(error.message || "Could not load metrics", "error", error.requestId));
    }));
  }

  async function loadLogs(append = false) {
    const type = $("#log-resource-type")?.value.trim() || "";
    const resource = $("#log-resource-id")?.value.trim() || "";
    const result = $("#log-result")?.value || "";
    const params = new URLSearchParams({ limit: "100" });
    if (type) params.set("resource_type", type);
    if (resource) params.set("resource_id", resource);
    if (append && state.auditBefore) params.set("before_id", state.auditBefore);
    const [auditResult, abuseResult] = await Promise.allSettled([
      api(`/api/v1/audit?${params}`),
      apiFirst(["/api/v1/network/abuse-records?limit=100", "/api/v1/abuse-records?limit=100"]),
    ]);
    if (auditResult.status === "rejected") throw auditResult.reason;
    let audit = listPayload(auditResult.value).items;
    if (result) audit = audit.filter((item) => result === "success" ? item.success !== false : item.success === false);
    state.auditBefore = audit.length ? String(audit[audit.length - 1].id) : state.auditBefore;
    const body = $("#audit-log-body");
    const rows = audit.map((item) => `<tr><td>${escapeHtml(dateTime(item.occurred_at))}</td><td>${escapeHtml(item.action)}</td><td>${escapeHtml([item.actor_type, item.actor_id].filter(Boolean).join(":") || "system")}</td><td class="font-mono text-xs">${escapeHtml([item.resource_type, item.resource_id].filter(Boolean).join(":"))}</td><td class="font-mono text-xs">${escapeHtml(item.source_ip || "—")}</td><td>${item.success === false ? '<span class="text-rose-300">Failed</span>' : '<span class="text-emerald-300">Success</span>'}</td><td class="font-mono text-xs">${escapeHtml(item.request_id || "—")}</td></tr>`).join("");
    if (body) body.innerHTML = append ? body.innerHTML + rows : (rows || '<tr><td colspan="7" class="py-10 text-center text-slate-500">No matching activity.</td></tr>');
    const abuse = abuseResult.status === "fulfilled" ? listPayload(abuseResult.value).items : [];
    const abuseBody = $("#abuse-log-body");
    if (abuseBody) abuseBody.innerHTML = abuse.length ? abuse.map((item) => {
      const resolved = item.resolved_at != null;
      const category = `${item.category || "other"} · severity ${finite(item.severity) || 1}/10`;
      const reporter = [item.reporter, item.provider_reference].filter(Boolean).join(" · ") || "—";
      const disposition = resolved ? `Resolved${item.resolution ? ` · ${item.resolution}` : ""}` : "Open";
      return `<tr><td>${escapeHtml(dateTime(item.observed_at || item.reported_at))}</td><td class="font-mono text-xs">${escapeHtml(item.address || item.ip_address || "—")}</td><td class="font-mono text-xs">${escapeHtml(item.vm_id || "—")}</td><td>${escapeHtml(category)}</td><td>${escapeHtml(reporter)}</td><td class="max-w-sm whitespace-normal">${escapeHtml(item.summary || "—")}</td><td><span class="${resolved ? "text-emerald-300" : "text-amber-200"}">${escapeHtml(disposition)}</span></td><td>${resolved ? "" : `<button type="button" class="btn-secondary px-3 py-2" data-resolve-abuse="${escapeHtml(item.id)}">Resolve</button>`}</td></tr>`;
    }).join("") : '<tr><td colspan="8" class="py-10 text-center text-slate-500">No abuse records.</td></tr>';
  }

  async function initLogs() {
    await loadLogs();
    $("[data-refresh-logs]")?.addEventListener("click", () => { state.auditBefore = null; loadLogs().catch((error) => toast(error.message, "error", error.requestId)); });
    $("[data-load-more-audit]")?.addEventListener("click", () => loadLogs(true).catch((error) => toast(error.message, "error", error.requestId)));
    ["#log-resource-type", "#log-resource-id", "#log-result"].forEach((selector) => $(selector)?.addEventListener("change", () => { state.auditBefore = null; loadLogs().catch((error) => toast(error.message, "error", error.requestId)); }));
    $("#abuse-record-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const values = formObject(form);
      try {
        await api("/api/v1/network/abuse-records", {
          method: "POST",
          body: {
            address: String(values.address || "").trim(),
            vm_id: String(values.vm_id || "").trim() || null,
            category: values.category,
            severity: finite(values.severity),
            summary: String(values.summary || "").trim(),
            reporter: String(values.reporter || "").trim() || null,
            provider_reference: String(values.provider_reference || "").trim() || null,
            observed_at: null,
            metadata: {},
          },
        });
        form.reset();
        if (form.elements.severity) form.elements.severity.value = "5";
        toast("Abuse report recorded", "success");
        await loadLogs();
      } catch (error) { toast(error.message, "error", error.requestId); }
    });
    document.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-resolve-abuse]");
      if (!button) return;
      const approved = await confirmAction({ title: "Resolve abuse report?", message: "This closes the datacenter abuse record. It does not release a blacklist or change VM networking.", confirmLabel: "Resolve report" });
      if (!approved) return;
      try {
        await api(`/api/v1/network/abuse-records/${encodeURIComponent(button.dataset.resolveAbuse)}/resolve`, { method: "POST", body: { resolution: "Resolved from the Vexa-VM panel" } });
        toast("Abuse report resolved", "success");
        await loadLogs();
      } catch (error) { toast(error.message, "error", error.requestId); }
    });
  }

  function vmAddresses(vm) {
    const publicAddresses = [...vm.publicV4, ...vm.publicV6];
    const privateAddresses = [...vm.privateV4, ...vm.privateV6];
    const render = (items, label, color) => items.length ? `<div><span class="mr-1 text-[10px] uppercase tracking-wider text-slate-600">${label}</span>${items.map((address) => `<button type="button" class="block max-w-64 truncate font-mono text-xs ${color} hover:underline" data-copy="${escapeHtml(address)}" title="Copy ${escapeHtml(address)}">${escapeHtml(address)}</button>`).join("")}</div>` : "";
    return render(publicAddresses, "Public", "text-orbit-300") + render(privateAddresses, "Private", "text-nebula-200") || '<span class="text-slate-600">No address</span>';
  }

  function vmTraffic(vm) {
    if (!vm.trafficLimit) return `<span class="text-xs text-slate-500">${bytes(vm.trafficUsed)} / Unlimited</span>`;
    const value = clamp(vm.trafficPct);
    return `<div class="w-44"><div class="flex justify-between text-xs"><span class="text-slate-400">${bytes(vm.trafficUsed)}</span><span class="text-slate-600">${bytes(vm.trafficLimit)}</span></div><div class="metric-track mt-1.5"><div class="metric-fill" style="width:${value}%"></div></div>${vm.trafficBlocked ? '<p class="mt-1 text-[10px] font-normal uppercase tracking-wider text-rose-300">Network blocked</p>' : ""}</div>`;
  }

  function vmActionButtons(vm, compact = false) {
    if (!vm.libvirt_uuid && ["creating", "building", "error"].includes(statusInfo(vm.state).key)) {
      return `<div class="flex justify-end"><a href="/vms/${encodeURIComponent(vm.id)}" class="btn-secondary ${compact ? "px-3 py-2" : "h-9 w-9 p-0"}" title="Open failed VM record">${compact ? "Review" : "↗"}</a></div>`;
    }
    return `<div class="flex items-center justify-end gap-1"><a href="/vms/${encodeURIComponent(vm.id)}" class="btn-secondary ${compact ? "px-3 py-2" : "h-9 w-9 p-0"}" ${compact ? "" : `aria-label="Open ${escapeHtml(vm.name)}" title="Open"`}>${compact ? "Open" : "↗"}</a><button type="button" class="btn-secondary ${compact ? "px-3 py-2" : "h-9 w-9 p-0"}" data-vm-row-action="${statusInfo(vm.state).key === "running" ? "shutdown" : "start"}" data-vm-id="${escapeHtml(vm.id)}" ${compact ? "" : `aria-label="${statusInfo(vm.state).key === "running" ? "Shut down" : "Start"} ${escapeHtml(vm.name)}"`}>${statusInfo(vm.state).key === "running" ? "■" : "▶"}</button><button type="button" class="btn-secondary ${compact ? "px-3 py-2" : "h-9 w-9 p-0"}" data-vm-row-action="console" data-vm-id="${escapeHtml(vm.id)}" ${compact ? "" : `aria-label="Open ${escapeHtml(vm.name)} console"`}>${compact ? "Console" : "⌘"}</button></div>`;
  }

  function renderVms() {
    const query = $("#vm-search")?.value.trim().toLowerCase() || "";
    const stateFilter = $("#vm-state-filter")?.value || "";
    const familyFilter = $("#vm-family-filter")?.value || "";
    const filtered = state.vms.filter((vm) => {
      const text = [vm.name, vm.hostname, vm.osName, vm.owner, ...vm.publicV4, ...vm.publicV6, ...vm.privateV4, ...vm.privateV6, ...vm.tags].join(" ").toLowerCase();
      const statusMatch = !stateFilter || statusInfo(vm.state).key === stateFilter;
      const dual = vm.publicV4.length > 0 && vm.publicV6.length > 0;
      const familyMatch = !familyFilter || (familyFilter === "ipv4" && vm.publicV4.length) || (familyFilter === "ipv6" && vm.publicV6.length) || (familyFilter === "dual" && dual);
      return (!query || text.includes(query)) && statusMatch && familyMatch;
    });
    $("#vms-empty")?.classList.toggle("hidden", state.vms.length !== 0);
    $("#vms-no-results")?.classList.toggle("hidden", state.vms.length === 0 || filtered.length !== 0);
    const tableWrap = $("#vms-table-wrap");
    const cardList = $("#vms-card-list");
    const show = filtered.length > 0;
    if (tableWrap) tableWrap.classList.toggle("hidden", !show || window.innerWidth < 1024);
    if (cardList) cardList.classList.toggle("hidden", !show || window.innerWidth >= 1024);
    setText("#vm-count-summary", `${state.vms.length} virtual machine${state.vms.length === 1 ? "" : "s"} · ${state.vms.filter((vm) => statusInfo(vm.state).key === "running").length} running`);

    const tbody = $("#vms-table-body");
    if (tbody) tbody.innerHTML = filtered.map((vm) => {
      const status = statusInfo(vm.state);
      return `<tr data-vm-row="${escapeHtml(vm.id)}"><td><input type="checkbox" class="h-4 w-4 rounded border-white/20 bg-white/5 text-plasma-500" data-select-vm="${escapeHtml(vm.id)}" aria-label="Select ${escapeHtml(vm.name)}"></td><td><div class="flex items-center gap-3"><span class="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-orbit-400/10 to-nebula-400/10 text-xs font-normal text-orbit-300">${escapeHtml(vm.osName.slice(0, 2).toUpperCase())}</span><div class="min-w-0"><a href="/vms/${encodeURIComponent(vm.id)}" class="block max-w-44 truncate font-normal text-white hover:text-white">${escapeHtml(vm.name)}</a><p class="max-w-44 truncate text-xs text-slate-500">${escapeHtml(vm.hostname)} · ${escapeHtml(vm.osName)}${vm.osVersion ? ` ${escapeHtml(vm.osVersion)}` : ""}</p><div class="mt-1">${statusBadge(vm.state)}</div></div></div></td><td>${vmAddresses(vm)}</td><td><p class="text-sm text-slate-300">${vm.cpu} vCPU <span class="text-slate-600">·</span> ${percent(vm.cpuPct, 1)}</p><p class="mt-1 text-xs text-slate-500">${bytes(vm.ramUsed)} / ${bytes(vm.ramTotal)} · ${percent(vm.ramPct)}</p></td><td><p class="text-sm text-slate-300">${bytes(vm.diskTotal, 0)} provisioned</p><p class="mt-1 text-xs text-slate-500">R ${byteRate(vm.diskReadBps)} · W ${byteRate(vm.diskWriteBps)}</p></td><td><p class="text-sm text-slate-300">${vm.portMbps ? `${vm.portMbps} Mbit/s` : "Uncapped"}</p><p class="mt-1 text-xs text-slate-500">↓ ${byteRate(vm.rxBps)} · ↑ ${byteRate(vm.txBps)}</p><div class="mt-2">${vmTraffic(vm)}</div></td><td><div class="max-w-56"><p class="truncate font-mono text-xs text-slate-400" title="${escapeHtml(vm.dns.join(", "))}">${escapeHtml(vm.dns.join(", ") || "Inherited DNS")}</p><div class="mt-2 flex items-center gap-2"><span class="font-mono text-xs tracking-widest text-slate-600">••••••••</span><button type="button" class="text-xs font-normal text-orbit-300 hover:text-white" data-vm-row-action="secret" data-vm-id="${escapeHtml(vm.id)}">Reveal</button></div></div></td><td>${vmActionButtons(vm)}</td></tr>`;
    }).join("");
    if (cardList) cardList.innerHTML = filtered.map((vm) => `<article class="panel p-4"><div class="flex items-start justify-between gap-3"><div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><a href="/vms/${encodeURIComponent(vm.id)}" class="truncate text-base font-normal text-white">${escapeHtml(vm.name)}</a>${statusBadge(vm.state)}</div><p class="mt-1 truncate text-xs text-slate-500">${escapeHtml(vm.hostname)} · ${escapeHtml(vm.osName)}</p></div><input type="checkbox" data-select-vm="${escapeHtml(vm.id)}" aria-label="Select ${escapeHtml(vm.name)}"></div><div class="mt-4 rounded-xl bg-white/[.025] p-3">${vmAddresses(vm)}</div><dl class="mt-4 grid grid-cols-2 gap-3 text-sm"><div><dt class="text-xs text-slate-600">Compute</dt><dd class="mt-1 text-slate-300">${vm.cpu} vCPU · ${bytes(vm.ramTotal)}</dd></div><div><dt class="text-xs text-slate-600">Live usage</dt><dd class="mt-1 text-slate-300">CPU ${percent(vm.cpuPct)} · RAM ${percent(vm.ramPct)}</dd></div><div><dt class="text-xs text-slate-600">Storage</dt><dd class="mt-1 text-slate-300">${bytes(vm.diskTotal, 0)}</dd></div><div><dt class="text-xs text-slate-600">Network</dt><dd class="mt-1 text-slate-300">↓ ${byteRate(vm.rxBps)}</dd></div></dl><div class="mt-4 border-t border-white/[.07] pt-3">${vmActionButtons(vm, true)}</div></article>`).join("");
    $$('[data-copy]').forEach((button) => button.addEventListener("click", () => copyText(button.dataset.copy, "Address copied")));
    bindVmSelection();
  }

  function bindVmSelection() {
    $$('[data-select-vm]').forEach((checkbox) => checkbox.addEventListener("change", updateVmBulkToolbar));
    updateVmBulkToolbar();
  }

  function selectedVmIds() {
    return $$('[data-select-vm]:checked').map((input) => input.dataset.selectVm);
  }

  function updateVmBulkToolbar() {
    const count = selectedVmIds().length;
    const toolbar = $("#bulk-toolbar");
    if (toolbar) { toolbar.classList.toggle("hidden", count === 0); toolbar.classList.toggle("flex", count > 0); }
    setText("#bulk-count", count);
  }

  async function loadVms({ append = false } = {}) {
    $("#vms-error")?.classList.add("hidden");
    if (!append) $("#vms-loading")?.classList.remove("hidden");
    try {
      const cursor = append && state.vmCursor ? `&cursor=${encodeURIComponent(state.vmCursor)}` : "";
      const payload = await api(`/api/v1/vms?limit=100${cursor}`);
      const result = listPayload(payload);
      const items = result.items.map(normalizeVm);
      state.vms = append ? [...state.vms, ...items] : items;
      state.vmCursor = result.page.next_cursor || null;
      $("#vms-pagination")?.classList.toggle("hidden", !state.vmCursor);
      $("#vms-pagination")?.classList.toggle("flex", Boolean(state.vmCursor));
      setText("#vms-page-label", `${state.vms.length} loaded`);
      renderVms();
      setLiveState("live", "Live");
    } catch (error) {
      $("#vms-error")?.classList.remove("hidden");
      setText("#vms-error-message", `${error.message}${error.requestId ? ` · Request ${error.requestId}` : ""}`);
      setLiveState("error", "Unavailable");
    } finally {
      $("#vms-loading")?.classList.add("hidden");
    }
  }

  async function vmRowAction(id, action) {
    const vm = state.vms.find((item) => String(item.id) === String(id));
    if (action === "console") {
      try {
        const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/vnc-tokens`, { method: "POST", body: {} });
        const link = response?.data?.url || response?.url || response?.link;
        if (!link) throw new ApiError("The console link was not returned.");
        window.open(link, "_blank", "noopener,noreferrer");
      } catch (error) { toast(error.message, "error", error.requestId); }
      return;
    }
    if (action === "secret") {
      try {
        const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/password`);
        const secret = response?.data?.password || response?.password;
        if (!secret) throw new ApiError("No stored password is available.");
        const value = window.prompt(`Password for ${vm?.name || "VM"} (visible only in this prompt):`, secret);
        if (value === secret) await copyText(secret, "Password copied");
      } catch (error) { toast(error.message, "error", error.requestId); }
      return;
    }
    const destructive = ["shutdown", "stop", "reset"].includes(action);
    if (destructive) {
      const approved = await confirmAction({ title: `${action === "shutdown" ? "Shut down" : action === "reset" ? "Hard reboot" : "Force stop"} ${vm?.name || "VM"}?`, message: action === "shutdown" ? "The guest will receive a graceful shutdown request." : "Unsaved guest data may be lost.", confirmLabel: action === "shutdown" ? "Shut down" : "Continue", danger: action !== "shutdown" });
      if (!approved) return;
    }
    try {
      const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/actions/${encodeURIComponent(action)}`, { method: "POST", body: {} });
      toast(`${vm?.name || "VM"}: ${action} requested`, "success");
      await followOperation(response);
      await loadVms();
    } catch (error) { toast(error.message, "error", error.requestId); }
  }

  async function initVms() {
    $("#vm-search")?.addEventListener("input", renderVms);
    $("#vm-state-filter")?.addEventListener("change", renderVms);
    $("#vm-family-filter")?.addEventListener("change", renderVms);
    $$('[data-refresh-vms]').forEach((button) => button.addEventListener("click", () => loadVms()));
    $("[data-clear-vm-filters]")?.addEventListener("click", () => { $("#vm-search").value = ""; $("#vm-state-filter").value = ""; $("#vm-family-filter").value = ""; renderVms(); });
    $("[data-load-more-vms]")?.addEventListener("click", () => loadVms({ append: true }));
    $("#select-all-vms")?.addEventListener("change", (event) => { $$('[data-select-vm]').forEach((input) => { input.checked = event.target.checked; }); updateVmBulkToolbar(); });
    document.addEventListener("click", (event) => {
      const action = event.target.closest("[data-vm-row-action]");
      if (action) vmRowAction(action.dataset.vmId, action.dataset.vmRowAction);
    });
    $$('[data-bulk-action]').forEach((button) => button.addEventListener("click", async () => {
      const ids = selectedVmIds(); const action = button.dataset.bulkAction;
      if (!ids.length) return;
      if (action === "delete") {
        const approved = await confirmAction({ title: `Delete ${ids.length} virtual machines?`, message: "Managed disks and guest data will be permanently removed.", phrase: `delete ${ids.length}`, confirmLabel: "Delete virtual machines" });
        if (!approved) return;
        const results = await Promise.allSettled(ids.map((id) => api(`/api/v1/vms/${encodeURIComponent(id)}`, { method: "DELETE" })));
        const failed = results.filter((result) => result.status === "rejected").length;
        toast(failed ? `${failed} deletion request${failed === 1 ? "" : "s"} failed` : "Deletion requests accepted", failed ? "error" : "success");
      } else {
        await Promise.allSettled(ids.map((id) => api(`/api/v1/vms/${encodeURIComponent(id)}/actions/${action}`, { method: "POST", body: {} })));
        toast(`${action} requested for ${ids.length} VMs`, "success");
      }
      await loadVms();
    }));
    window.addEventListener("resize", renderVms);
    await loadVms();
  }

  function imageLabel(image) {
    return image.name || image.display_name || image.slug || image.filename || "Unnamed image";
  }

  function imageMode(image) {
    return String(image.provisioning_mode || image.install_mode || (image.supports_cloud_init ? "cloud-init" : "manual")).replaceAll("_", "-");
  }

  function isManualInstallImage(image) {
    return imageMode(image || {}).startsWith("manual");
  }

  function isApplianceImage(image = {}) {
    const family = String(image.os_family || "").toLowerCase();
    return family.includes("routeros") || image.metadata?.preconfigured_appliance === true;
  }

  function isReadyImage(image) {
    if (!(image.enabled ?? true)) return false;
    if (typeof image.available === "boolean") return image.available;
    return ["ready", "available"].includes(image.status || image.state)
      || Boolean(image.local_path || image.path);
  }

  function guestAdministratorDefault(image = {}) {
    const family = String(image.os_family || "").toLowerCase();
    if (family.includes("windows")) return "Administrator";
    if (family.includes("routeros") || family.includes("mikrotik")) return "vexa-admin";
    return "root";
  }

  function updateCreateAdministratorDefault(form, image) {
    const username = form?.elements?.username;
    if (!username || username.dataset.userEdited === "true") return;
    username.value = guestAdministratorDefault(image);
    username.dataset.imageDefault = "true";
  }

  function updateCreateAccessMode(form) {
    const image = state.images.find((item) => String(item.id || item.slug) === String(form.elements.image_id?.value));
    const manual = Boolean(image && isManualInstallImage(image));
    const appliance = Boolean(image && isApplianceImage(image));
    const builtinRouterTools = appliance;
    const interactiveAccess = manual;
    updateCreateAdministratorDefault(form, image);
    const access = $("#create-automated-access");
    access?.classList.toggle("hidden", interactiveAccess);
    const accessNotice = $("#create-manual-access-notice");
    accessNotice?.classList.toggle("hidden", !interactiveAccess);
    if (accessNotice) accessNotice.textContent = "This is a manual installer image. Set the administrator account inside the installer through VNC; Vexa-VM will not invent or store a password it cannot inject.";
    $$('input, textarea, button', access).forEach((control) => control.toggleAttribute("disabled", interactiveAccess));
    const password = $("#create-password");
    if (password) {
      password.required = !interactiveAccess;
      if (interactiveAccess) password.value = "";
    }
    const tools = image?.guestTools || image?.guest_tools || {};
    const guestTools = $("#create-guest-tools");
    const guestToolsReady = !interactiveAccess && !builtinRouterTools && tools.supported === true && tools.artifact_available === true;
    if (guestTools) {
      guestTools.disabled = builtinRouterTools || !guestToolsReady;
      if (builtinRouterTools) guestTools.checked = true;
      else if (!guestToolsReady) guestTools.checked = false;
    }
    const toolsMessage = manual
      ? "Guest Tools cannot be injected into a manual installer."
      : builtinRouterTools
        ? "Vexa RouterOS integration is enabled automatically. It uses QGA for networking and a host-only REST link to create the secure administrator account."
      : guestToolsReady
        ? `Available for ${tools.platform || "this image"}; installation is opt-in.`
        : tools.reason || "No verified Guest Tools artifact is available for this image.";
    setText("#create-guest-tools-status", toolsMessage);
  }

  function renderCreateImages(images) {
    const grid = $("#create-image-grid");
    if (!grid) return;
    const query = $("#image-search")?.value.trim().toLowerCase() || "";
    const filtered = images.filter((image) => [imageLabel(image), image.slug, image.os_family, image.version, image.architecture].join(" ").toLowerCase().includes(query));
    const selectedId = $('input[name="image_id"]:checked', grid)?.value;
    const hasVisibleSelection = filtered.some((image) => String(image.id || image.slug) === String(selectedId) && isReadyImage(image));
    let assignedDefault = false;
    grid.innerHTML = filtered.map((image, index) => {
      const id = image.id || image.slug;
      const ready = isReadyImage(image);
      const checked = ready && (hasVisibleSelection ? String(id) === String(selectedId) : !assignedDefault);
      if (checked) assignedDefault = true;
      const mode = imageMode(image);
      const modeClass = isManualInstallImage(image) ? "border-amber-300/20 text-amber-200" : "border-emerald-300/20 text-emerald-200";
      const tools = image.guestTools || image.guest_tools || {};
      const toolsBadge = tools.supported && tools.artifact_available ? '<span class="badge border-orbit-300/20 text-orbit-300">Vexa Tools ready</span>' : "";
      return `<label class="group relative cursor-pointer rounded-2xl border ${checked || index === 0 ? "border-plasma-400/40 bg-plasma-500/10" : "border-white/[.08] bg-white/[.025]"} p-4 transition hover:border-orbit-300/30"><input type="radio" class="peer sr-only" name="image_id" value="${escapeHtml(id)}" ${checked ? "checked" : ""} ${ready ? "" : "disabled"}><span class="absolute inset-0 rounded-2xl ring-2 ring-transparent peer-checked:ring-plasma-400/60"></span><span class="relative flex items-start gap-3"><span class="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-orbit-400/10 to-nebula-400/15 text-sm font-normal text-orbit-300">${escapeHtml((image.os_family || imageLabel(image)).slice(0, 2).toUpperCase())}</span><span class="min-w-0 flex-1"><span class="block truncate text-sm font-normal text-white">${escapeHtml(imageLabel(image))}</span><span class="mt-1 block text-xs text-slate-500">${escapeHtml(image.version || "")}${image.architecture ? ` · ${escapeHtml(image.architecture)}` : ""}</span><span class="mt-2 flex flex-wrap gap-1.5"><span class="badge ${modeClass}">${escapeHtml(mode)}</span>${image.guest_agent || image.supports_guest_agent ? '<span class="badge border-orbit-300/20 text-orbit-300">Guest agent</span>' : ""}${toolsBadge}${!ready ? '<span class="badge border-rose-300/20 text-rose-200">Not ready</span>' : ""}</span></span></span></label>`;
    }).join("");
    $("#create-images-empty")?.classList.toggle("hidden", filtered.length > 0);
    const form = $("#vm-create-form");
    if (form) updateCreateAccessMode(form);
  }

  function selectedReinstallIsManual(select) {
    return String(select?.selectedOptions?.[0]?.dataset.installMode || "").startsWith("manual");
  }

  function selectedReinstallIsAppliance(select) {
    return String(select?.selectedOptions?.[0]?.dataset.osFamily || "").toLowerCase().includes("routeros");
  }

  function updateReinstallPasswordMode(select, root, requiredForAutomatic) {
    const manual = selectedReinstallIsManual(select);
    const interactiveAccess = manual;
    const field = $('[data-reinstall-password]', root);
    const input = $('input[name="password"]', field);
    field?.classList.toggle("hidden", interactiveAccess);
    const notice = $('[data-manual-password-notice]', root);
    notice?.classList.toggle("hidden", !interactiveAccess);
    if (notice) notice.textContent = "Manual installers set credentials interactively through VNC. The old stored password is removed only after the reinstall succeeds.";
    if (input) {
      input.disabled = interactiveAccess;
      input.required = !interactiveAccess && requiredForAutomatic;
      if (interactiveAccess) input.value = "";
    }
  }

  function updateReinstallGuestToolsMode(select, root, vm = {}) {
    const checkbox = $('input[name="install_guest_tools"]', root);
    if (!checkbox) return;
    const image = state.images.find((item) => String(item.id || item.slug) === String(select?.value));
    const tools = image?.guestTools || image?.guest_tools || {};
    const builtinRouterTools = Boolean(isApplianceImage(image));
    const ready = Boolean(image && !builtinRouterTools && tools.supported && tools.artifact_available && !isManualInstallImage(image));
    checkbox.disabled = builtinRouterTools || !ready;
    if (builtinRouterTools) checkbox.checked = true;
    else if (!ready) checkbox.checked = false;
    const removing = Boolean(vm.guest_tools?.enabled && !ready);
    setText("[data-reinstall-tools-status]", builtinRouterTools
      ? "Vexa RouterOS integration uses QGA plus a host-only credential link and is enabled automatically."
      : ready
      ? `Available for ${tools.platform || "this image"}; keep this checked to reinstall Guest Tools.`
      : removing
        ? "This image does not support Vexa Guest Tools. The old tools channel and pending key will be removed only after the reinstall succeeds."
        : tools.reason || "Select a compatible automated image to enable Guest Tools.", root);
  }

  function createStepName(step) {
    return ["", "Identity", "Image", "Resources", "Network", "Access", "Review"][step] || "";
  }

  function setCreateCapacityError(message) {
    setText("#create-inline-error", message);
    $("#create-inline-error")?.classList.remove("hidden");
  }

  function configureCreateCapacity(host) {
    const legacyCpuCapacity = finite(host.cpu_threads ?? host.cpu_cores) - finite(host.allocated_vcpus);
    const cpuCapacity = Math.min(512, Math.max(0, Math.floor(finite(host.available_vcpus, legacyCpuCapacity))));
    const legacyMemoryAvailable = Math.max(0, finite(host.memory?.available_bytes ?? host.ram_available_bytes ?? host.ram_total_bytes) - (256 * MiB));
    const memoryAvailable = finite(host.available_memory_bytes, legacyMemoryAvailable);
    const ramCapacity = Math.min(16 * 1024 * 1024, Math.max(0, Math.floor(memoryAvailable / (256 * MiB)) * 256));
    const diskCapacity = Math.max(0, Math.floor(Math.max(0, finite(host.storage_free_bytes) - (2 * GiB)) / GiB));
    const policy = host.capacity_policy || {};
    state.createCapacity = { cpu: cpuCapacity, ramMiB: ramCapacity, diskGiB: diskCapacity, cpuRatio: finite(policy.cpu_overcommit_ratio, 1), memoryRatio: finite(policy.memory_overcommit_ratio, 1) };

    const cpu = $("#create-cpu"); const ram = $("#create-ram"); const disk = $("#create-disk");
    if (cpu) { cpu.max = String(Math.max(1, cpuCapacity)); if (cpuCapacity >= 1) cpu.value = String(Math.min(Math.max(1, finite(cpu.value, 1)), cpuCapacity)); }
    if (ram) { ram.max = String(Math.max(256, ramCapacity)); if (ramCapacity >= 256) ram.value = String(Math.min(Math.max(256, finite(ram.value, 512)), ramCapacity)); }
    if (disk) { disk.max = String(Math.max(5, diskCapacity)); if (diskCapacity >= 5) disk.value = String(Math.min(Math.max(5, finite(disk.value, 10)), diskCapacity)); }
  }

  function validateCreateCapacity(form) {
    const capacity = state.createCapacity;
    if (!capacity) return true;
    const requestedCpu = finite($("#create-cpu", form)?.value);
    const requestedRam = finite($("#create-ram", form)?.value);
    const requestedDisk = finite($("#create-disk", form)?.value);
    if (capacity.cpu < 1 || capacity.ramMiB < 256 || capacity.diskGiB < 5) {
      setCreateCapacityError(`This node does not currently have enough schedulable capacity to create a VM (available: ${capacity.cpu} vCPU, ${capacity.ramMiB} MiB RAM, ${capacity.diskGiB} GiB disk).`);
      return false;
    }
    if (requestedCpu > capacity.cpu || requestedRam > capacity.ramMiB || requestedDisk > capacity.diskGiB) {
      setCreateCapacityError(`Requested resources exceed the schedulable node capacity: ${capacity.cpu} vCPU, ${capacity.ramMiB} MiB RAM, ${capacity.diskGiB} GiB disk. Reduce the request or adjust the overcommit policy in Settings.`);
      return false;
    }
    return true;
  }

  function reviewCreateForm(form) {
    const values = formObject(form);
    const image = state.images.find((item) => String(item.id || item.slug) === String(values.image_id));
    const manual = Boolean(image && isManualInstallImage(image));
    const appliance = Boolean(image && isApplianceImage(image));
    const dns = values.dns_mode === "custom" ? splitLines(values.dns_servers) : ["Node defaults"];
    const automaticAddress = preferredPublicIp()?.address;
    const addresses = values.ip_mode === "manual" ? asArray(values.ip_addresses) : [automaticAddress || "No public address available"];
    const rows = [
      ["Virtual machine", `${values.name || "—"} · ${values.hostname || "—"}`],
      ["Image", image ? `${imageLabel(image)} · ${imageMode(image)}` : "Not selected"],
      ["Compute", `${values.cpu || 0} vCPU · ${values.ram_mb || 0} MiB`],
      ["Storage", `${values.disk_gb || 0} GiB · managed qcow2`],
      ["Public addresses", addresses.join(", ")],
      ["Private network", values.private_network || "None"],
      ["DNS", dns.join(", ")],
      ["Network policy", `${values.port_limit_mbps || "—"} Mbit/s · ${finite(values.traffic_quota_gb) ? `${values.traffic_quota_gb} GiB accounting allowance` : "Unlimited traffic allowance"}`],
      ["Guest access", manual ? "Set interactively in the manual installer through VNC" : `${values.username || guestAdministratorDefault(image)}${splitLines(values.ssh_keys).length ? ` · ${splitLines(values.ssh_keys).length} SSH key(s)` : ""}`],
      ["Vexa Guest Tools", appliance ? "Built-in RouterOS QEMU integration" : values.install_guest_tools ? "Install on first boot" : "Not installed"],
      ["Start policy", values.start_after_create ? "Start after provisioning" : "Create stopped"],
    ];
    const review = $("#create-review");
    if (review) review.innerHTML = rows.map(([label, value]) => `<div class="rounded-xl border border-white/[.07] bg-white/[.02] p-4"><dt class="text-xs uppercase tracking-wider text-slate-600">${escapeHtml(label)}</dt><dd class="mt-2 break-words text-sm font-normal text-slate-200">${escapeHtml(value)}</dd></div>`).join("");
  }

  function validateCreateStep(form, step) {
    const panel = $(`[data-create-step='${step}']`, form);
    if (!panel) return true;
    if (step === 3 && !validateCreateCapacity(form)) return false;
    const fields = $$('input:not([disabled]), select:not([disabled]), textarea:not([disabled])', panel);
    for (const field of fields) {
      if (!field.checkValidity()) { field.reportValidity(); field.focus(); return false; }
    }
    if (step === 2 && !$('input[name="image_id"]:checked', panel)) {
      setText("#create-inline-error", "Choose a ready installation image.");
      $("#create-inline-error")?.classList.remove("hidden");
      return false;
    }
    return true;
  }

  function showCreateStep(form, step) {
    const normalized = clamp(step, 1, 6);
    form.dataset.step = String(normalized);
    $$('[data-create-step]', form).forEach((panel) => panel.classList.toggle("hidden", Number(panel.dataset.createStep) !== normalized));
    $$('[data-go-step]', form).forEach((button) => {
      const active = Number(button.dataset.goStep) === normalized;
      button.className = active ? "w-full rounded-xl bg-plasma-500/15 px-3 py-2.5 text-left text-sm font-normal text-white ring-1 ring-plasma-400/20" : "w-full rounded-xl px-3 py-2.5 text-left text-sm text-slate-500 hover:bg-white/[.035] hover:text-white";
    });
    setText("#create-step-label", `Step ${normalized} of 6 · ${createStepName(normalized)}`);
    $("#create-back")?.classList.toggle("invisible", normalized === 1);
    $("#create-next")?.classList.toggle("hidden", normalized === 6);
    $("#create-submit")?.classList.toggle("hidden", normalized !== 6);
    $("#create-inline-error")?.classList.add("hidden");
    if (normalized === 6) reviewCreateForm(form);
    $("#create-step-scroll")?.scrollTo({ top: 0, behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
  }

  async function loadCreateDependencies() {
    const [imagesResult, addressesResult, networksResult, hostResult, settingsResult] = await Promise.allSettled([
      apiFirst(["/api/v1/isos", "/api/v1/images"]),
      apiFirst(["/api/v1/network/addresses?status=free&limit=1000", "/api/v1/ip-addresses?status=free&limit=1000"]),
      apiFirst(["/api/v1/network/pools?scope=private", "/api/v1/networks?scope=private"]),
      api("/api/v1/host"),
      api("/api/v1/settings"),
    ]);
    state.images = imagesResult.status === "fulfilled" ? listPayload(imagesResult.value).items.map(normalizeImage) : [];
    state.ips = (addressesResult.status === "fulfilled" ? listPayload(addressesResult.value).items : [])
      .map(normalizeIp)
      .filter(isPublicFreeIp)
      .sort((left, right) => Number(left.family === "ipv6") - Number(right.family === "ipv6") || left.address.localeCompare(right.address, undefined, { numeric: true }));
    const networks = (networksResult.status === "fulfilled" ? listPayload(networksResult.value).items : [])
      .filter((network) => String(network.scope || "").toLowerCase() === "private" && network.enabled !== false);
    const host = hostResult.status === "fulfilled" ? extractHost(hostResult.value) : {};
    const settingsPayload = settingsResult.status === "fulfilled" ? settingsResult.value : {};
    const defaults = settingsPayload?.settings?.network || settingsPayload?.data?.network || {};
    const speedInput = $("input[name='port_limit_mbps']"); if (speedInput && defaults.default_port_limit_mbps) speedInput.value = defaults.default_port_limit_mbps;
    const quotaInput = $("input[name='traffic_quota_gb']"); if (quotaInput && defaults.default_traffic_quota_bytes) quotaInput.value = finite(defaults.default_traffic_quota_bytes) / GiB;
    $("#create-images-loading")?.classList.add("hidden");
    renderCreateImages(state.images);
    const createForm = $("#vm-create-form");
    if (createForm) updateCreateAccessMode(createForm);
    const addressSelect = $("#create-addresses");
    if (addressSelect) {
      addressSelect.innerHTML = state.ips.length
        ? state.ips.map((item, index) => `<option value="${escapeHtml(item.address)}" ${index === 0 ? "selected" : ""}>${escapeHtml(item.address)} · ${escapeHtml(item.pool_name || item.pool || (item.family === "ipv6" ? "IPv6" : "IPv4"))}</option>`).join("")
        : '<option value="" disabled>No free public addresses</option>';
    }
    const privateSelect = $("#create-private-network");
    if (privateSelect) {
      privateSelect.innerHTML = '<option value="">None</option>' + networks.map((network) => {
        const bridge = network.bridge || defaults.default_bridge || "";
        const unavailable = !bridge;
        return `<option value="${escapeHtml(bridge)}" ${unavailable ? "disabled" : ""}>${escapeHtml(network.name || network.cidr)} · ${escapeHtml(network.cidr || "")}${bridge ? ` · ${escapeHtml(bridge)}` : " · bridge not configured"}</option>`;
      }).join("");
    }
    configureCreateCapacity(host);
    const freeCpu = state.createCapacity?.cpu ?? 0;
    const freeRam = (state.createCapacity?.ramMiB ?? 0) * MiB;
    const freeDisk = (state.createCapacity?.diskGiB ?? 0) * GiB;
    const capacity = $("#create-capacity");
    if (capacity) capacity.innerHTML = `<p class="font-normal text-slate-300">Schedulable now</p><dl class="mt-2 space-y-1"><div class="flex justify-between"><dt>vCPU</dt><dd>${Math.max(0, freeCpu) || "—"}</dd></div><div class="flex justify-between"><dt>Memory</dt><dd>${freeRam > 0 ? bytes(freeRam) : "—"}</dd></div><div class="flex justify-between"><dt>Storage</dt><dd>${freeDisk > 0 ? bytes(freeDisk) : "—"}</dd></div><div class="flex justify-between"><dt>Free IPs</dt><dd>${state.ips.length}</dd></div></dl><p class="mt-2 border-t border-white/[.06] pt-2 text-[11px] text-slate-600">CPU ${state.createCapacity.cpuRatio.toFixed(2)}× · RAM ${state.createCapacity.memoryRatio.toFixed(2)}× with VirtIO ballooning</p>`;
  }

  function createPayload(form) {
    const values = formObject(form);
    const image = state.images.find((item) => String(item.id || item.slug) === String(values.image_id));
    const manual = Boolean(image && isManualInstallImage(image));
    const appliance = Boolean(image && isApplianceImage(image));
    const manualAddresses = asArray(values.ip_addresses);
    const automaticAddress = preferredPublicIp()?.address;
    return {
      name: String(values.name || "").trim(), hostname: String(values.hostname || "").trim(),
      description: String(values.description || "").trim(), os_family: image?.os_family || "unknown", iso_id: values.image_id || null,
      vcpus: finite(values.cpu), memory_mib: finite(values.ram_mb), disk_gib: finite(values.disk_gb), disk_format: "qcow2",
      firmware: values.firmware || "auto", machine_type: values.machine_type || null,
      bridge: values.private_network || null, tap_name: null, mac_address: values.mac_address || null,
      network_limit_mbps: finite(values.port_limit_mbps), traffic_limit_bytes: finite(values.traffic_quota_gb) > 0 ? finite(values.traffic_quota_gb) * GiB : 0,
      root_username: values.username || guestAdministratorDefault(image), guest_agent: Boolean(image?.supports_guest_agent || image?.guest_agent), autostart: Boolean(values.autostart), timezone: null,
      ...(manual ? {} : { password: values.password }), ip_addresses: values.ip_mode === "manual" ? manualAddresses : (automaticAddress ? [automaticAddress] : []), start: Boolean(values.start_after_create),
      dns_servers: values.dns_mode === "custom" ? splitLines(values.dns_servers) : [],
      install_guest_tools: Boolean(values.install_guest_tools),
      metadata: { owner: String(values.owner || "").trim() || null, tags: splitLines(values.tags), ssh_keys: splitLines(values.ssh_keys), private_bridge: values.private_network || null, create_status_link: Boolean(values.create_status_link) },
    };
  }

  async function initVmCreate() {
    const form = $("#vm-create-form");
    const dialog = $("#vm-create-dialog");
    if (!form || !dialog) return;
    if (dialog.hasAttribute("open")) { dialog.removeAttribute("open"); dialog.showModal(); }
    form.dataset.step = "1";
    $("#create-name")?.addEventListener("input", (event) => { const hostname = $("#create-hostname"); if (hostname && (!hostname.value || hostname.dataset.derived === "true")) { hostname.value = event.target.value.toLowerCase().replace(/[^a-z0-9.-]/g, "-"); hostname.dataset.derived = "true"; } });
    $("#create-hostname")?.addEventListener("input", () => { $("#create-hostname").dataset.derived = "false"; });
    $("#create-user")?.addEventListener("input", (event) => { event.currentTarget.dataset.userEdited = "true"; });
    $("[data-copy-created-status-link]")?.addEventListener("click", () => copyText($("#create-status-link")?.textContent || "", "Customer link copied"));
    $("#image-search")?.addEventListener("input", () => renderCreateImages(state.images));
    form.addEventListener("change", (event) => {
      if (event.target.matches('input[name="image_id"]')) updateCreateAccessMode(form);
    });
    $$('input[name="ip_mode"]', form).forEach((radio) => radio.addEventListener("change", () => $("#manual-addresses")?.classList.toggle("hidden", radio.form.elements.ip_mode.value !== "manual")));
    $("#create-dns-mode")?.addEventListener("change", (event) => $("#custom-dns")?.classList.toggle("hidden", event.target.value !== "custom"));
    $("#create-next")?.addEventListener("click", () => { const step = Number(form.dataset.step); if (validateCreateStep(form, step)) showCreateStep(form, step + 1); });
    $("#create-back")?.addEventListener("click", () => showCreateStep(form, Number(form.dataset.step) - 1));
    $$('[data-go-step]', form).forEach((button) => button.addEventListener("click", () => { const target = Number(button.dataset.goStep); const current = Number(form.dataset.step); if (target < current || validateCreateStep(form, current)) showCreateStep(form, target); }));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!form.reportValidity() || !validateCreateStep(form, 6)) return;
      const submit = $("#create-submit");
      submit.disabled = true;
      try {
        const payload = createPayload(form);
        $("#create-progress")?.classList.remove("hidden");
        $$('[data-create-step]', form).forEach((panel) => panel.classList.add("hidden"));
        $("#create-footer")?.classList.add("hidden");
        const response = await api("/api/v1/vms", { method: "POST", headers: { "Idempotency-Key": randomUuid() }, body: payload });
        form.elements.password.value = "";
        const operation = response?.operation || response?.data?.operation;
        setText("#create-operation-id", operation?.id ? `Operation ${operation.id}` : "");
        const result = await followOperation(response?.data || response, (current) => { setText("#create-progress-message", current.message || current.status || "Provisioning…"); setProgress("#create-progress-bar", current.progress ?? current.progress_percent ?? 10); });
        const vmId = response?.data?.vm?.id || response?.vm?.id || result?.resource_id || result?.result?.vm_id || payload.name;
        setProgress("#create-progress-bar", 100);
        toast("Virtual machine created", "success");
        if (payload.metadata.create_status_link) {
          try {
            const created = await api(`/api/v1/vms/${encodeURIComponent(vmId)}/status-tokens`, { method: "POST", body: { scopes: [], expires_at: null } });
            const url = created?.url || created?.data?.url;
            if (url) {
              setText("#create-progress-message", "Virtual machine created. Copy the one-time customer link before continuing.");
              setText("#create-status-link", url);
              $("#create-status-link-result")?.classList.remove("hidden");
              const open = $("#create-open-vm"); if (open) open.href = `/vms/${encodeURIComponent(vmId)}`;
              return;
            }
          } catch (linkError) {
            toast(`VM created, but its customer link could not be created: ${linkError.message}`, "error", linkError.requestId);
          }
        }
        setText("#create-progress-message", "Virtual machine created. Opening its detail page…");
        window.setTimeout(() => location.assign(`/vms/${encodeURIComponent(vmId)}`), 500);
      } catch (error) {
        $("#create-progress")?.classList.add("hidden");
        showCreateStep(form, 6);
        $("#create-footer")?.classList.remove("hidden");
        const summary = $("#create-validation-summary");
        if (summary) { summary.textContent = `${error.message}${error.requestId ? ` · Request ${error.requestId}` : ""}`; summary.classList.remove("hidden"); summary.focus(); }
        submit.disabled = false;
      }
    });
    try { await loadCreateDependencies(); } catch (error) { toast(error.message, "error", error.requestId); }
  }

  function currentVmId() {
    const parts = location.pathname.split("/").filter(Boolean);
    return parts[0] === "vms" && parts[1] && parts[1] !== "create" ? decodeURIComponent(parts[1]) : "";
  }

  function guestApplyMessage(response, fallback) {
    const result = response?.data?.guest_tools || response?.guest_tools;
    return result?.message || fallback;
  }

  function guestApplyKind(response) {
    const result = response?.data?.guest_tools || response?.guest_tools;
    if (result?.status === "rejected") return "error";
    if (result?.pending) return "info";
    return "success";
  }

  function renderVmDetail(vm, metricsPayload = {}) {
    const metricItems = asArray(metricsPayload?.items || metricsPayload?.samples || metricsPayload?.history);
    const latestMetric = metricItems.at(-1) || metricsPayload?.metrics || metricsPayload?.data || (metricsPayload?.items ? null : metricsPayload) || vm.metrics;
    const detail = normalizeVm({ ...vm, metrics: latestMetric });
    state.currentVm = detail;
    document.title = `${detail.name} · Vexa VM`;
    setText("#vm-title", detail.name);
    const badge = $("#vm-state-badge");
    if (badge) badge.outerHTML = statusBadge(detail.state).replace("<span ", '<span id="vm-state-badge" ');
    const addresses = [...detail.publicV4, ...detail.publicV6];
    const summary = $("#vm-summary");
    if (summary) summary.innerHTML = `<span>${escapeHtml(detail.osName)}${detail.osVersion ? ` ${escapeHtml(detail.osVersion)}` : ""}</span><span class="font-mono text-orbit-300">${escapeHtml(addresses[0] || "No public IP")}</span><span>${detail.cpu} vCPU · ${bytes(detail.ramTotal)} RAM · ${bytes(detail.diskTotal, 0)} disk</span>`;
    const stateKey = statusInfo(detail.state).key;
    const isRunning = stateKey === "running";
    const isPaused = stateKey === "paused";
    const hasDomain = Boolean(vm.libvirt_uuid);
    $$('[data-vm-power="start"]').forEach((button) => button.classList.toggle("hidden", isRunning || isPaused || !hasDomain));
    $$('[data-vm-power="shutdown"]').forEach((button) => button.classList.toggle("hidden", !isRunning || !hasDomain));
    $$('[data-vm-power="suspend"]').forEach((button) => button.classList.toggle("hidden", !isRunning || !hasDomain));
    $$('[data-vm-power="resume"]').forEach((button) => button.classList.toggle("hidden", !isPaused || !hasDomain));
    $$('[data-vm-console]').forEach((button) => button.classList.toggle("hidden", !hasDomain));
    const maintenance = vm.metadata?.maintenance || {};
    const maintenanceEnabled = maintenance.enabled === true;
    $("#vm-maintenance-banner")?.classList.toggle("hidden", !maintenanceEnabled);
    setText("#vm-maintenance-reason", maintenance.reason || "Customer mutations are temporarily unavailable.");
    $$('[data-vm-maintenance-enable]').forEach((button) => button.classList.toggle("hidden", maintenanceEnabled));
    $$('[data-vm-maintenance-disable]').forEach((button) => button.classList.toggle("hidden", !maintenanceEnabled));
    const diskProtection = vm.metadata?.disk_protection || {};
    fillForm($("#vm-disk-protection-form"), { deletion_lock: diskProtection.deletion_lock === true, snapshot_before_reinstall: diskProtection.snapshot_before_reinstall === true });
    const guestTools = vm.guest_tools || {};
    const guestToolsLabel = !guestTools.enabled
      ? "Not installed"
      : guestTools.connected
        ? `Connected${guestTools.installed_version ? ` · ${guestTools.installed_version}` : ""}`
        : guestTools.status === "pending"
          ? "Installation pending first boot"
          : `Unavailable${guestTools.last_error ? ` · ${guestTools.last_error}` : ""}`;
    setText("#vm-guest-tools-status", guestToolsLabel);
    $("[data-probe-guest-tools]")?.toggleAttribute("disabled", !guestTools.enabled);

    setText("#vm-metric-cpu", percent(detail.cpuPct, 1)); setProgress("#vm-metric-cpu-bar", detail.cpuPct); setText("#vm-metric-cpu-detail", `${detail.cpu} allocated vCPU`);
    setText("#vm-metric-ram", percent(detail.ramPct, 1)); setProgress("#vm-metric-ram-bar", detail.ramPct); setText("#vm-metric-ram-detail", `${bytes(detail.ramUsed)} of ${bytes(detail.ramTotal)}`);
    setText("#vm-metric-net", bitsPerSecond((detail.rxBps + detail.txBps) * 8)); setText("#vm-metric-net-detail", `↓ ${byteRate(detail.rxBps)} · ↑ ${byteRate(detail.txBps)} · ${detail.portMbps || "—"} Mbit/s cap`);
    setText("#vm-metric-traffic", detail.trafficBlocked ? "Blocked" : (detail.trafficLimit ? percent(detail.trafficPct, 1) : "Unlimited")); setProgress("#vm-metric-traffic-bar", detail.trafficPct || 0); setText("#vm-metric-traffic-detail", detail.trafficBlocked ? `${bytes(detail.trafficUsed)} used · network disabled` : (detail.trafficLimit ? `${bytes(detail.trafficUsed)} of ${bytes(detail.trafficLimit)}` : `${bytes(detail.trafficUsed)} used`));
    setText("#vm-metrics-updated", (metricsPayload?.sampled_at || vm.updated_at) ? `Updated ${relativeTime(metricsPayload.sampled_at || vm.updated_at)}` : "");
    const samples = metricItems.length ? metricItems : asArray(vm.metrics?.samples);
    renderChart($("#vm-performance-chart"), [
      { label: "CPU %", values: samples.map((item) => item.cpu_pct ?? item.cpu_percent) },
      { label: "RAM %", values: samples.map((item) => item.ram_pct ?? item.memory_pct ?? (finite(item.memory_total_bytes) ? finite(item.memory_used_bytes) * 100 / finite(item.memory_total_bytes) : 0)), color: "#aa55f7" },
    ], { label: `${detail.name} CPU and memory usage`, max: 100, formatY: (value) => `${Math.round(value)}%` });
    const configFacts = [
      ["Operating system", `${detail.osName}${detail.osVersion ? ` ${detail.osVersion}` : ""}`], ["vCPU", detail.cpu], ["Memory", bytes(detail.ramTotal)], ["Disk", bytes(detail.diskTotal, 0)],
      ["Guest-agent profile", detail.guestAgent ? "Declared by image" : "Not declared"], ["Autostart", vm.autostart ? "Enabled" : "Disabled"], ["Port speed", detail.portMbps ? `${detail.portMbps} Mbit/s` : "Uncapped"], ["Owner", detail.owner],
    ];
    const facts = $("#vm-config-facts");
    if (facts) facts.innerHTML = configFacts.map(([label, value]) => `<div class="flex justify-between gap-4 py-3"><dt class="text-sm text-slate-500">${escapeHtml(label)}</dt><dd class="text-right text-sm font-normal text-slate-200">${escapeHtml(value)}</dd></div>`).join("");
    fillForm($("#vm-resource-form"), { hostname: detail.hostname, cpu: detail.cpu, ram_mb: Math.round(detail.ramTotal / MiB), disk_gb: Math.round(detail.diskTotal / GiB), port_limit_mbps: detail.portMbps, traffic_quota_gb: detail.trafficLimit ? Math.round(detail.trafficLimit / GiB) : 0 });
    const revealButton = $("[data-reveal-vm-secret]");
    revealButton?.toggleAttribute("disabled", !vm.password_present);
    if (!vm.password_present) setText("#vm-secret-display", "No stored password");
    fillForm($("#vm-dns-form"), { dns_servers: detail.dns });
    const disks = asArray(vm.disks);
    const diskList = $("#vm-disk-list");
    if (diskList) diskList.innerHTML = disks.length ? disks.map((disk) => `<div class="flex items-center justify-between gap-4 py-3"><div><p class="text-sm font-normal text-slate-300">${escapeHtml(disk.name || disk.target || "Primary disk")}</p><p class="mt-1 text-xs text-slate-600">${escapeHtml(disk.format || "qcow2")} · ${escapeHtml(disk.bus || "virtio")}</p></div><div class="text-right"><p class="text-sm text-slate-300">${bytes(disk.size_bytes || detail.diskTotal, 0)}</p><p class="mt-1 text-xs text-slate-600">${bytes(disk.physical_bytes || 0)} physical</p></div></div>`).join("") : `<div class="flex items-center justify-between py-3"><div><p class="text-sm font-normal text-slate-300">Primary disk</p><p class="mt-1 text-xs text-slate-600">Managed guest volume</p></div><p class="text-sm text-slate-300">${bytes(detail.diskTotal, 0)}</p></div>`;
    const interfaces = asArray(vm.interfaces || vm.network?.interfaces);
    const interfaceList = $("#vm-interface-list");
    if (interfaceList) interfaceList.innerHTML = `<table class="data-table min-w-[680px]"><thead><tr><th>Device</th><th>MAC</th><th>Bridge</th><th>Addresses</th><th>Live rate</th></tr></thead><tbody>${(interfaces.length ? interfaces : [{ name: vm.tap || "eth0", mac: vm.mac || vm.mac_address, bridge: vm.bridge || vm.bridge_name, addresses }]).map((item) => `<tr><td>${escapeHtml(item.name || item.target || "eth0")}</td><td class="font-mono text-xs">${escapeHtml(item.mac || item.mac_address || "—")}</td><td class="font-mono text-xs">${escapeHtml(item.bridge || "—")}</td><td class="font-mono text-xs">${escapeHtml(asArray(item.addresses || addresses).join(", ") || "—")}</td><td>↓ ${byteRate(item.rx_bps || detail.rxBps)} · ↑ ${byteRate(item.tx_bps || detail.txBps)}</td></tr>`).join("")}</tbody></table>`;
    renderVmLinks(vm);
  }

  function renderVmLinks(vm) {
    const links = asArray(vm.status_tokens || vm.status_links);
    const target = $("#vm-status-links");
    if (!target) return;
    target.innerHTML = links.length ? links.map((link) => {
      const fresh = state.freshStatusLink && String(state.freshStatusLink.tokenId) === String(link.id);
      const reveal = fresh ? `<div class="mt-3 rounded-lg border border-emerald-300/20 bg-emerald-300/[.06] p-3"><p class="text-[11px] font-normal uppercase tracking-wider text-emerald-200">New link · shown only in this browser until refresh</p><code class="mt-2 block break-all font-mono text-xs text-emerald-100">${escapeHtml(state.freshStatusLink.url)}</code><button type="button" class="mt-3 text-xs font-normal text-emerald-200 hover:text-emerald-100" data-copy-status-link>Copy link</button></div>` : `<p class="mt-1 text-xs text-slate-600">The URL is shown only when created. Generate a replacement if it was not saved.</p>`;
      return `<div class="flex items-start justify-between gap-4 py-3"><div class="min-w-0"><p class="truncate text-sm font-normal text-slate-300">${escapeHtml(link.name || "Customer status")}</p><p class="mt-1 text-xs text-slate-600">${link.expires_at ? `Expires ${dateTime(link.expires_at)}` : "No fixed expiry"} · ${escapeHtml(asArray(link.scopes).join(", ") || "default scopes")}</p>${reveal}</div><button type="button" class="shrink-0 text-xs font-normal text-rose-300 hover:text-rose-200" data-revoke-status-link="${escapeHtml(link.id)}">Revoke</button></div>`;
    }).join("") : '<p class="py-4 text-sm text-slate-500">No active customer links.</p>';
  }

  function renderVmNetworkSecurity(payload = {}) {
    const profile = payload.profile || payload.data?.profile || {};
    const rules = asArray(payload.rules || payload.data?.rules);
    fillForm($("#vm-network-security-form"), {
      firewall_enabled: profile.firewall_enabled === true,
      ddos_enabled: profile.ddos_enabled === true,
      default_ingress_action: profile.default_ingress_action || "accept",
      default_egress_action: profile.default_egress_action || "accept",
      port_scan_protection: profile.port_scan_protection === true,
      drop_invalid_packets: profile.drop_invalid_packets === true,
      syn_rate_limit_pps: profile.syn_rate_limit_pps || "",
      udp_rate_limit_pps: profile.udp_rate_limit_pps || "",
      icmp_rate_limit_pps: profile.icmp_rate_limit_pps || "",
      new_connection_limit_pps: profile.new_connection_limit_pps || "",
    });
    const applied = profile.applied_revision != null && Number(profile.applied_revision) === Number(profile.revision) && !profile.last_error;
    setText("#vm-network-security-state", profile.last_error ? `Not applied: ${profile.last_error}` : applied ? `Revision ${profile.revision} is applied` : "Protection is disabled and consumes no packet-filtering resources");
    const target = $("#vm-firewall-rules");
    if (!target) return;
    target.innerHTML = rules.length ? rules.map((rule) => {
      const ports = asArray(rule.destination_ports).map((range) => Number(range.start) === Number(range.end) ? range.start : `${range.start}-${range.end}`).join(", ") || "All ports";
      return `<div class="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between"><div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><span class="badge ${rule.enabled ? "border-emerald-300/20 text-emerald-200" : "border-slate-300/20 text-slate-400"}">${rule.enabled ? "Enabled" : "Off"}</span><span class="text-sm font-normal text-slate-200">${escapeHtml(rule.direction)} · ${escapeHtml(rule.action)} ${escapeHtml(rule.protocol)} ${escapeHtml(ports)}</span></div><p class="mt-1 truncate text-xs text-slate-500">${escapeHtml(rule.source_cidr || "Any source")} · ${escapeHtml(rule.description || "No description")}</p></div><div class="flex shrink-0 gap-2"><button type="button" class="btn-secondary px-3 py-2" data-firewall-toggle="${escapeHtml(rule.id)}" data-enabled="${rule.enabled ? "true" : "false"}">${rule.enabled ? "Disable" : "Enable"}</button><button type="button" class="btn-danger px-3 py-2" data-firewall-delete="${escapeHtml(rule.id)}">Delete</button></div></div>`;
    }).join("") : '<p class="py-3 text-sm text-slate-500">No rules configured.</p>';
  }

  function parsePortRanges(value) {
    const text = String(value || "").trim();
    if (!text) return [];
    return text.split(",").map((part) => {
      const match = part.trim().match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
      if (!match) throw new ApiError("Ports must be numbers or ranges such as 22 or 8000-8100.");
      const start = Number(match[1]); const end = Number(match[2] || match[1]);
      if (start < 1 || end > 65535 || start > end) throw new ApiError("Port ranges must be between 1 and 65535.");
      return { start, end };
    });
  }

  function renderVmSnapshots(items = []) {
    const target = $("#vm-snapshot-list");
    if (!target) return;
    target.innerHTML = items.length ? items.map((snapshot) => `<div class="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between"><div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><p class="font-normal text-slate-200">${escapeHtml(snapshot.name)}</p>${statusBadge(snapshot.state === "ready" ? "running" : snapshot.state).replace("Running", "Ready")}</div><p class="mt-1 text-xs text-slate-500">${escapeHtml(snapshot.description || "No description")} · ${escapeHtml(dateTime(snapshot.created_at))}</p></div><div class="flex shrink-0 gap-2"><button type="button" class="btn-secondary px-3 py-2" data-snapshot-revert="${escapeHtml(snapshot.id)}" ${snapshot.state === "ready" ? "" : "disabled"}>Restore</button><button type="button" class="btn-danger px-3 py-2" data-snapshot-delete="${escapeHtml(snapshot.id)}" ${snapshot.state === "ready" ? "" : "disabled"}>Delete</button></div></div>`).join("") : '<p class="py-4 text-sm text-slate-500">No snapshots have been created.</p>';
  }

  async function loadVmDetail() {
    const id = currentVmId();
    if (!id) return;
    try {
      const [vmResult, metricsResult, ipsResult, auditResult, securityResult, snapshotsResult] = await Promise.allSettled([
        api(`/api/v1/vms/${encodeURIComponent(id)}`),
        api(`/api/v1/vms/${encodeURIComponent(id)}/metrics?range=24h`),
        apiFirst(["/api/v1/network/addresses?status=free&limit=1000", "/api/v1/ip-addresses?status=free&limit=1000"]),
        api(`/api/v1/audit?resource_id=${encodeURIComponent(id)}&limit=50`),
        api(`/api/v1/vms/${encodeURIComponent(id)}/network-security`),
        api(`/api/v1/vms/${encodeURIComponent(id)}/snapshots`),
      ]);
      if (vmResult.status === "rejected") throw vmResult.reason;
      const vm = vmResult.value?.data || vmResult.value?.vm || vmResult.value;
      const metrics = metricsResult.status === "fulfilled" ? (metricsResult.value?.data || metricsResult.value) : {};
      state.ips = ipsResult.status === "fulfilled" ? listPayload(ipsResult.value).items.filter((item) => item.assignable !== false && item.blacklisted !== true) : [];
      renderVmDetail(vm, metrics);
      renderVmNetworkSecurity(securityResult.status === "fulfilled" ? (securityResult.value?.data || securityResult.value) : {});
      renderVmSnapshots(snapshotsResult.status === "fulfilled" ? listPayload(snapshotsResult.value).items : []);
      const assigned = new Set([...state.currentVm.publicV4, ...state.currentVm.publicV6, ...state.currentVm.privateV4, ...state.currentVm.privateV6]);
      const select = $("#vm-ip-addresses");
      if (select) select.innerHTML = [...state.ips, ...[...assigned].map((address) => ({ id: address, address }))].filter((item, index, array) => array.findIndex((other) => String(other.address) === String(item.address)) === index).map((item) => `<option value="${escapeHtml(item.address)}" ${assigned.has(item.address) ? "selected" : ""}>${escapeHtml(item.address)} · ${escapeHtml(item.status || (assigned.has(item.address) ? "assigned" : "free"))}</option>`).join("");
      const audit = auditResult.status === "fulfilled" ? listPayload(auditResult.value).items : [];
      const auditList = $("#vm-audit-list");
      if (auditList) auditList.innerHTML = audit.length ? audit.map((item) => `<li class="flex gap-3 py-4"><span class="mt-1 h-2 w-2 shrink-0 rounded-full ${item.success === false || item.result === "failed" ? "bg-rose-300" : "bg-nebula-300"}"></span><div class="min-w-0 flex-1"><p class="text-sm font-normal text-slate-300">${escapeHtml(item.action || item.title)}</p><p class="mt-1 text-xs text-slate-600">${escapeHtml(item.actor || [item.actor_type, item.actor_id].filter(Boolean).join(":") || "System")} · ${escapeHtml(item.source_ip || item.ip_address || "")}</p></div><time class="text-xs text-slate-600">${escapeHtml(dateTime(item.occurred_at || item.created_at || item.timestamp))}</time></li>`).join("") : '<li class="py-4 text-sm text-slate-500">No audit events recorded.</li>';
      $("#vm-detail-error")?.classList.add("hidden");
      setLiveState("live", "Live");
    } catch (error) {
      const box = $("#vm-detail-error");
      if (box) { box.textContent = `${error.message}${error.requestId ? ` · Request ${error.requestId}` : ""}`; box.classList.remove("hidden"); }
      setLiveState("error", "Unavailable");
    }
  }

  async function vmDetailPower(action) {
    const vm = state.currentVm; if (!vm) return;
    if (["shutdown", "hard-stop", "reset", "suspend"].includes(action)) {
      const label = action === "shutdown" ? "Shut down" : action === "hard-stop" ? "Force stop" : action === "reset" ? "Hard reboot" : "Pause";
      const message = action === "shutdown" ? "The guest receives a graceful shutdown request." : action === "suspend" ? "CPU execution will stop while memory remains allocated." : "Unsaved guest data may be lost.";
      const approved = await confirmAction({ title: `${label} ${vm.name}?`, message, confirmLabel: "Continue", danger: ["hard-stop", "reset"].includes(action) });
      if (!approved) return;
    }
    try { const response = await api(`/api/v1/vms/${encodeURIComponent(vm.id)}/actions/${action}`, { method: "POST", body: {} }); toast(`${action} requested`, "success"); await followOperation(response?.data || response); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); }
  }

  function openVmAction(mode) {
    const dialog = $("#vm-action-dialog"); const form = $("#vm-action-form"); const fields = $("#vm-action-fields");
    if (!dialog || !form || !fields || !state.currentVm) return;
    form.dataset.action = mode;
    const vm = state.currentVm;
    if (mode === "password") {
      setText("#vm-action-title", "Set a new guest password");
      fields.innerHTML = `<label><span class="label">New password</span><div class="flex gap-2"><input id="vm-new-password" name="password" type="password" minlength="12" class="field" autocomplete="new-password" required><button type="button" class="btn-secondary" data-modal-generate>Generate</button></div></label>`;
    } else if (mode === "status-link") {
      setText("#vm-action-title", "Create customer status link");
      fields.innerHTML = `<div class="space-y-4"><label><span class="label">Expires</span><input name="expires_at" type="datetime-local" class="field"><span class="mt-1.5 block text-xs text-slate-600">Defaults to seven days; each browser session lasts ten minutes.</span></label><fieldset><legend class="label">Allowed actions</legend><div class="grid gap-2 sm:grid-cols-2"><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="vm:power" checked>Power controls</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="vm:reinstall" checked>Reinstall OS</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="vm:dns" checked>Edit stored DNS</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="vm:password:read">Reveal password</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="vm:password:write">Change password record</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="ssh:write">Manage SSH keys</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="firewall:write">Manage VM firewall</label><label class="flex gap-2 rounded-xl border border-white/[.07] p-3 text-sm"><input type="checkbox" name="scopes" value="vm:vnc" checked>Open console</label></div></fieldset></div>`;
    } else if (mode === "reinstall") {
      setText("#vm-action-title", `Reinstall ${vm.name}`);
      fields.innerHTML = `<div class="rounded-xl border border-rose-300/20 bg-rose-300/[.07] p-4 text-sm text-rose-100">The system disk and all data on it will be permanently replaced.</div><label class="mt-4 block"><span class="label">Installation image</span><select name="image_id" class="field" required><option value="">Select an image…</option>${state.images.filter(isReadyImage).map((image) => `<option value="${escapeHtml(image.id || image.slug)}" data-install-mode="${escapeHtml(imageMode(image))}" data-os-family="${escapeHtml(image.os_family || "")}">${escapeHtml(imageLabel(image))} · ${escapeHtml(imageMode(image))}</option>`).join("")}</select></label><label class="mt-4 block" data-reinstall-password><span class="label">New administrator password <span class="normal-case tracking-normal text-slate-600">(optional when one is already stored)</span></span><input name="password" type="password" minlength="12" class="field" autocomplete="new-password"></label><div class="mt-4 hidden rounded-xl border border-amber-300/20 bg-amber-300/[.07] p-4 text-sm leading-6 text-amber-100" data-manual-password-notice>Manual installers set credentials interactively through VNC. The old stored password is removed only after the reinstall succeeds.</div><label class="mt-4 flex items-start gap-3 rounded-xl border border-white/[.07] p-4"><input name="install_guest_tools" type="checkbox" ${vm.guest_tools?.enabled ? "checked" : ""}><span><span class="block text-sm text-slate-200">${vm.guest_tools?.enabled ? "Keep Vexa Guest Tools installed" : "Install Vexa Guest Tools"}</span><span data-reinstall-tools-status class="mt-1 block text-xs text-slate-500">Choose an image to verify compatibility.</span></span></label><label class="mt-4 block"><span class="label">Type ${escapeHtml(vm.name)} to continue</span><input name="confirmation" class="field" required autocomplete="off"></label>`;
      const select = $('select[name="image_id"]', fields);
      select?.addEventListener("change", () => { updateReinstallPasswordMode(select, fields, !vm.password_present); updateReinstallGuestToolsMode(select, fields, vm); });
      updateReinstallPasswordMode(select, fields, !vm.password_present);
      updateReinstallGuestToolsMode(select, fields, vm);
    } else if (mode === "maintenance") {
      setText("#vm-action-title", `Enter maintenance for ${vm.name}`);
      fields.innerHTML = `<div class="rounded-xl border border-amber-300/20 bg-amber-300/[.07] p-4 text-sm leading-6 text-amber-100">Customer-token changes will be blocked. Administrators can still manage the guest and the status page remains readable.</div><label class="mt-4 block"><span class="label">Reason shown to administrators</span><textarea name="reason" class="field min-h-24 resize-y" maxlength="500" placeholder="Scheduled operating-system maintenance"></textarea></label>`;
    }
    $("[data-modal-generate]", fields)?.addEventListener("click", () => { const input = $("#vm-new-password"); input.value = randomPassword(); input.type = "text"; });
    $("#vm-action-error")?.classList.add("hidden");
    dialog.showModal();
  }

  async function initVmDetail() {
    const id = currentVmId();
    $$('[data-vm-tab]').forEach((button) => button.addEventListener("click", () => {
      $$('[data-vm-tab]').forEach((item) => { const active = item === button; item.classList.toggle("border-orbit-300", active); item.classList.toggle("border-transparent", !active); item.classList.toggle("text-white", active); item.classList.toggle("text-slate-500", !active); });
      $$('[data-vm-panel]').forEach((panel) => panel.classList.toggle("hidden", panel.dataset.vmPanel !== button.dataset.vmTab));
      history.replaceState(null, "", `${location.pathname}#${button.dataset.vmTab}`);
    }));
    $$('[data-vm-power]').forEach((button) => button.addEventListener("click", () => vmDetailPower(button.dataset.vmPower)));
    $("[data-vm-more]")?.addEventListener("click", () => $("#vm-more-menu")?.classList.toggle("hidden"));
    $("[data-close-vm-action]")?.addEventListener("click", () => $("#vm-action-dialog")?.close());
    $("#vm-resource-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); const hostname = String(values.hostname || "").trim(); const hostnameChanged = hostname !== String(state.currentVm?.hostname || ""); const body = { vcpus: finite(values.cpu), memory_mib: finite(values.ram_mb), disk_gib: finite(values.disk_gb), network_limit_mbps: finite(values.port_limit_mbps), traffic_limit_bytes: finite(values.traffic_quota_gb) > 0 ? finite(values.traffic_quota_gb) * GiB : 0, ...(hostnameChanged ? { hostname } : {}) }; try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "Idempotency-Key": randomUuid() }, body }); toast(hostnameChanged ? guestApplyMessage(response, "Resources and hostname updated") : "Resources updated", hostnameChanged ? guestApplyKind(response) : "success"); await followOperation(response?.data || response); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#vm-disk-protection-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); try { await api(`/api/v1/vms/${encodeURIComponent(id)}/disk-protection`, { method: "PUT", body: { deletion_lock: Boolean(values.deletion_lock), snapshot_before_reinstall: Boolean(values.snapshot_before_reinstall) } }); toast("Disk protection updated", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#vm-snapshot-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const values = formObject(form); try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/snapshots`, { method: "POST", headers: { "Idempotency-Key": randomUuid() }, body: { name: String(values.name || "").trim(), description: "Created from the Vexa-VM panel" } }); form.reset(); toast("Snapshot requested", "success"); await followOperation(response?.data || response); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("[data-reset-vm-traffic]")?.addEventListener("click", async () => { const approved = await confirmAction({ title: "Reset traffic usage?", message: "Usage will return to zero and a Vexa-VM quota block will be removed. This starts a new accounting period.", confirmLabel: "Reset traffic" }); if (!approved) return; try { await api(`/api/v1/vms/${encodeURIComponent(id)}/traffic/reset`, { method: "POST", body: {} }); toast("Traffic usage reset", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#vm-network-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); const desired = asArray(values.ip_addresses); const current = [...state.currentVm.publicV4, ...state.currentVm.publicV6, ...state.currentVm.privateV4, ...state.currentVm.privateV6]; try { const requests = []; desired.forEach((address, index) => { if (!current.includes(address)) requests.push(api(`/api/v1/network/addresses/${encodeURIComponent(address)}`, { method: "PATCH", body: { vm_id: id, primary: index === 0 } })); }); current.filter((address) => !desired.includes(address)).forEach((address) => requests.push(api(`/api/v1/network/addresses/${encodeURIComponent(address)}`, { method: "PATCH", body: { status: "free" } }))); const results = await Promise.allSettled(requests); const failure = results.find((result) => result.status === "rejected"); if (failure) throw failure.reason; const guestResult = results.filter((result) => result.status === "fulfilled").map((result) => result.value?.guest_tools).filter(Boolean).at(-1); toast(guestResult?.message || (requests.length ? "Network assignment updated" : "Network assignment is already current"), guestResult?.status === "rejected" ? "warning" : "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#vm-dns-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/dns`, { method: "PUT", body: { dns_servers: splitLines(values.dns_servers) } }); toast(guestApplyMessage(response, "DNS configuration saved"), guestApplyKind(response)); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#vm-network-security-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); const optionalNumber = (value) => String(value || "").trim() ? finite(value) : null; try { await api(`/api/v1/vms/${encodeURIComponent(id)}/network-security`, { method: "PATCH", body: { firewall_enabled: Boolean(values.firewall_enabled), ddos_enabled: Boolean(values.ddos_enabled), default_ingress_action: values.default_ingress_action, default_egress_action: values.default_egress_action, port_scan_protection: Boolean(values.port_scan_protection), drop_invalid_packets: Boolean(values.drop_invalid_packets), syn_rate_limit_pps: optionalNumber(values.syn_rate_limit_pps), udp_rate_limit_pps: optionalNumber(values.udp_rate_limit_pps), icmp_rate_limit_pps: optionalNumber(values.icmp_rate_limit_pps), new_connection_limit_pps: optionalNumber(values.new_connection_limit_pps) } }); toast("Network protection policy applied", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#vm-firewall-rule-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const values = formObject(form); try { const destinationPorts = parsePortRanges(values.destination_ports); if (destinationPorts.length && !["tcp", "udp"].includes(values.protocol)) throw new ApiError("Ports can only be used with TCP or UDP rules."); await api(`/api/v1/vms/${encodeURIComponent(id)}/firewall/rules`, { method: "POST", body: { priority: 1000, direction: values.direction, action: values.action, protocol: values.protocol, source_cidr: String(values.source_cidr || "").trim() || null, destination_cidr: null, source_ports: [], destination_ports: destinationPorts, log: false, enabled: Boolean(values.enabled), description: String(values.description || "").trim() } }); form.reset(); toast("Firewall rule created", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("[data-reveal-vm-secret]")?.addEventListener("click", async () => { try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/password`); const secret = response?.data?.password || response?.password; if (!secret) throw new ApiError("No stored password is available."); revealSecret($("#vm-secret-display"), $("#vm-secret-timer"), secret); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("[data-reset-vm-password]")?.addEventListener("click", () => openVmAction("password"));
    $("[data-probe-guest-tools]")?.addEventListener("click", async () => { try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/guest-tools/probe`, { method: "POST", body: {} }); const result = response?.data?.result || response?.result; toast(result?.message || "Guest Tools connection checked", result?.status === "healthy" ? "success" : "error"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("[data-create-status-link]")?.addEventListener("click", () => openVmAction("status-link"));
    $("[data-vm-reinstall]")?.addEventListener("click", async () => { if (!state.images.length) { try { state.images = listPayload(await apiFirst(["/api/v1/isos", "/api/v1/images"])).items.map(normalizeImage); } catch {} } openVmAction("reinstall"); });
    $$('[data-vm-maintenance-enable]').forEach((button) => button.addEventListener("click", () => openVmAction("maintenance")));
    $$('[data-vm-maintenance-disable]').forEach((button) => button.addEventListener("click", async () => { const approved = await confirmAction({ title: `End maintenance for ${state.currentVm?.name || id}?`, message: "Customer-token actions will be available again according to the link scopes.", confirmLabel: "End maintenance" }); if (!approved) return; try { await api(`/api/v1/vms/${encodeURIComponent(id)}/maintenance`, { method: "PUT", body: { enabled: false, reason: "" } }); toast("Maintenance ended", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } }));
    $$('[data-vm-console]').forEach((button) => button.addEventListener("click", async () => { try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}/vnc-tokens`, { method: "POST", body: {} }); const url = response?.data?.url || response?.url; if (!url) throw new ApiError("Console link was not returned."); window.open(url, "_blank", "noopener,noreferrer"); } catch (error) { toast(error.message, "error", error.requestId); } }));
    $("[data-vm-delete]")?.addEventListener("click", async (event) => { const name = state.currentVm?.name || id; const approved = await confirmAction({ title: `Delete ${name}?`, message: "The domain and its managed disks will be permanently removed.", phrase: name, confirmLabel: "Delete virtual machine" }); if (!approved) return; const button = event.currentTarget; button.disabled = true; try { const response = await api(`/api/v1/vms/${encodeURIComponent(id)}`, { method: "DELETE", headers: { "Idempotency-Key": randomUuid() } }); await followOperation(response?.data || response); toast("Virtual machine deleted", "success"); location.assign("/vms"); } catch (error) { button.disabled = false; toast(error.message, "error", error.requestId); } });
    $("#vm-action-form")?.addEventListener("submit", async (event) => {
      event.preventDefault(); const form = event.currentTarget; const values = formObject(form); const action = form.dataset.action; const errorBox = $("#vm-action-error"); errorBox?.classList.add("hidden");
      try {
        let response;
        if (action === "password") response = await api(`/api/v1/vms/${encodeURIComponent(id)}/password`, { method: "PUT", body: { password: values.password } });
        else if (action === "status-link") { const requestedScopes = asArray(values.scopes); if (requestedScopes.includes("firewall:write")) requestedScopes.push("firewall:read"); response = await api(`/api/v1/vms/${encodeURIComponent(id)}/status-tokens`, { method: "POST", body: { scopes: [...new Set(["vm:read", ...requestedScopes])], expires_at: unixSeconds(values.expires_at), bound_ip: null } }); }
        else if (action === "reinstall") { if (values.confirmation !== state.currentVm.name) throw new ApiError("The VM name does not match."); const password = String(values.password || "").trim(); response = await api(`/api/v1/vms/${encodeURIComponent(id)}/reinstall`, { method: "POST", headers: { "Idempotency-Key": randomUuid() }, body: { image_id: values.image_id, install_guest_tools: Boolean(values.install_guest_tools), ...(password ? { password } : {}) } }); }
        else if (action === "maintenance") response = await api(`/api/v1/vms/${encodeURIComponent(id)}/maintenance`, { method: "PUT", body: { enabled: true, reason: String(values.reason || "").trim() } });
        form.reset(); $("#vm-action-dialog")?.close();
        if (action === "status-link") {
          const url = response?.data?.url || response?.url;
          const record = response?.data?.record || response?.record;
          if (!url || !record?.id) throw new ApiError("The status link was created but its one-time URL was not returned.");
          state.freshStatusLink = { tokenId: record.id, url };
          const knownLinks = asArray(state.currentVm?.status_tokens || state.currentVm?.status_links)
            .filter((link) => String(link.id) !== String(record.id));
          state.currentVm = { ...(state.currentVm || {}), status_tokens: [record, ...knownLinks] };
          renderVmLinks(state.currentVm);
          $(`[data-vm-tab='access']`)?.click();
          toast("Customer status link created and displayed below", "success");
        }
        else toast(action === "password" ? guestApplyMessage(response, "Guest password updated") : action === "maintenance" ? "Maintenance enabled" : "Reinstall started", action === "password" ? guestApplyKind(response) : "success");
        if (response?.operation || response?.data?.operation) await followOperation(response?.data || response);
        await loadVmDetail();
      } catch (error) { if (errorBox) { errorBox.textContent = `${error.message}${error.requestId ? ` · ${error.requestId}` : ""}`; errorBox.classList.remove("hidden"); } }
    });
    document.addEventListener("click", async (event) => { const copy = event.target.closest("[data-copy-status-link]"); if (copy) { if (state.freshStatusLink?.url) await copyText(state.freshStatusLink.url, "Status link copied"); return; } const revoke = event.target.closest("[data-revoke-status-link]"); if (!revoke) return; const approved = await confirmAction({ title: "Revoke customer link?", message: "Anyone currently using this status link will lose access.", confirmLabel: "Revoke link" }); if (!approved) return; try { await api(`/api/v1/vms/${encodeURIComponent(id)}/status-tokens/${encodeURIComponent(revoke.dataset.revokeStatusLink)}`, { method: "DELETE" }); if (state.freshStatusLink && String(state.freshStatusLink.tokenId) === String(revoke.dataset.revokeStatusLink)) state.freshStatusLink = null; toast("Status link revoked", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    document.addEventListener("click", async (event) => { const toggle = event.target.closest("[data-firewall-toggle]"); const remove = event.target.closest("[data-firewall-delete]"); if (!toggle && !remove) return; const ruleId = toggle?.dataset.firewallToggle || remove?.dataset.firewallDelete; if (remove) { const approved = await confirmAction({ title: "Delete firewall rule?", message: "The rule will be removed from the next atomic policy revision.", confirmLabel: "Delete rule" }); if (!approved) return; } try { if (toggle) await api(`/api/v1/vms/${encodeURIComponent(id)}/firewall/rules/${encodeURIComponent(ruleId)}`, { method: "PATCH", body: { enabled: toggle.dataset.enabled !== "true" } }); else await api(`/api/v1/vms/${encodeURIComponent(id)}/firewall/rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" }); toast(toggle ? "Firewall rule updated" : "Firewall rule deleted", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    document.addEventListener("click", async (event) => { const revert = event.target.closest("[data-snapshot-revert]"); const remove = event.target.closest("[data-snapshot-delete]"); if (!revert && !remove) return; const snapshotId = revert?.dataset.snapshotRevert || remove?.dataset.snapshotDelete; const approved = await confirmAction({ title: revert ? "Restore this snapshot?" : "Delete this snapshot?", message: revert ? "The current disk state will be replaced by the selected snapshot." : "This recovery point will be permanently removed.", confirmLabel: revert ? "Restore snapshot" : "Delete snapshot", danger: true }); if (!approved) return; try { if (revert) await api(`/api/v1/vms/${encodeURIComponent(id)}/snapshots/${encodeURIComponent(snapshotId)}/revert`, { method: "POST", body: {} }); else await api(`/api/v1/vms/${encodeURIComponent(id)}/snapshots/${encodeURIComponent(snapshotId)}`, { method: "DELETE" }); toast(revert ? "Snapshot restored" : "Snapshot deleted", "success"); await loadVmDetail(); } catch (error) { toast(error.message, "error", error.requestId); } });
    await loadVmDetail();
    const initialTab = location.hash.slice(1); if (initialTab) $(`[data-vm-tab='${CSS.escape(initialTab)}']`)?.click();
  }

  function revealSecret(display, timer, value) {
    if (!display) return;
    window.clearInterval(state.secretTimer);
    let remaining = 30;
    display.textContent = value;
    display.classList.remove("tracking-[.2em]", "text-slate-500");
    display.classList.add("break-all", "tracking-normal", "text-orbit-300");
    timer?.classList.remove("hidden");
    const tick = () => {
      if (timer) timer.textContent = `Hides automatically in ${remaining} seconds`;
      if (remaining <= 0) {
        window.clearInterval(state.secretTimer);
        display.textContent = "••••••••••••";
        display.classList.add("tracking-[.2em]", "text-slate-500");
        display.classList.remove("break-all", "tracking-normal", "text-orbit-300");
        timer?.classList.add("hidden");
      }
      remaining -= 1;
    };
    tick(); state.secretTimer = window.setInterval(tick, 1000);
  }

  function normalizeIp(item = {}) {
    const address = item.address || item.ip || item.ip_address || "";
    const rawStatus = item.main || item.is_main ? "main" : item.status || (item.reserved ? "reserved" : item.assigned_to || item.vm_id ? "used" : "free");
    const status = String(rawStatus).toLowerCase().replaceAll("_", "-").replace("main-ip", "main");
    const rawFamily = item.family || (String(address).includes(":") ? "ipv6" : "ipv4");
    const familyToken = String(rawFamily).toLowerCase();
    const family = familyToken === "v6" || familyToken === "ipv6" || familyToken === "6" || String(address).includes(":") ? "ipv6" : "ipv4";
    const scope = String(item.scope || (item.public === false ? "private" : "public")).toLowerCase();
    return { ...item, recordId: item.id || address, id: address, address, family, status, pool: item.pool_name || item.pool || item.network_name || item.pool_id || "—", association: item.vm_name || item.assigned_to || item.assigned_vm_id || item.node_name || "", gateway: item.gateway || item.gateway_ip || "", scope };
  }

  function isPublicFreeIp(item) {
    return Boolean(item?.address) && item.scope === "public" && item.status === "free" && item.assignable !== false && item.blacklisted !== true;
  }

  function compareIpAddresses(left, right) {
    const familyOrder = Number(left.family === "ipv6") - Number(right.family === "ipv6");
    return familyOrder || String(left.address || "").localeCompare(String(right.address || ""), undefined, { numeric: true, sensitivity: "base" });
  }

  function preferredPublicIp() {
    return state.ips.find(isPublicFreeIp);
  }

  function normalizePool(item = {}) {
    const cidr = item.cidr || item.range || item.network || "";
    const familyToken = String(item.family || (String(cidr).includes(":") ? "ipv6" : "ipv4")).toLowerCase();
    const family = familyToken === "v6" || familyToken === "ipv6" || familyToken === "6" || String(cidr).includes(":") ? "ipv6" : "ipv4";
    return {
      ...item,
      id: item.id || item.uuid || cidr || item.name,
      name: item.name || item.label || cidr || "Unnamed pool",
      cidr,
      family,
      scope: String(item.scope || (item.public === false ? "private" : "public")).toLowerCase(),
      gateway: item.gateway || item.gateway_ip || "",
      bridge: item.bridge || item.bridge_name || "",
      mtu: finite(item.mtu),
      enabled: item.enabled !== false,
    };
  }

  function poolAddressCounts(pool) {
    const addresses = state.ips.filter((item) => {
      const poolId = item.pool_id || item.poolId;
      return poolId ? String(poolId) === String(pool.id) : item.pool === pool.name || item.pool === pool.cidr;
    });
    return {
      total: addresses.length,
      free: addresses.filter((item) => item.status === "free" && item.assignable !== false && item.blacklisted !== true).length,
      reserved: addresses.filter((item) => item.status === "reserved" || item.status === "main").length,
      used: addresses.filter((item) => item.status === "used").length,
    };
  }

  function renderNetworkPools() {
    const grid = $("#network-pool-grid");
    const empty = $("#network-pools-empty");
    const hasPools = state.pools.length > 0;
    grid?.classList.toggle("hidden", !hasPools);
    empty?.classList.toggle("hidden", hasPools);
    setText("#network-pool-count", `${state.pools.length} configured range${state.pools.length === 1 ? "" : "s"}`);
    if (!grid) return;
    grid.innerHTML = state.pools.map((pool) => {
      const counts = poolAddressCounts(pool);
      const scopeClass = pool.scope === "private" ? "border-nebula-300/20 text-nebula-200" : "border-orbit-300/20 text-orbit-300";
      const familyLabel = pool.family === "ipv6" ? "IPv6" : "IPv4";
      return `<article class="panel overflow-hidden"><div class="h-1 bg-gradient-to-r ${pool.scope === "private" ? "from-nebula-500/70 to-plasma-500/60" : "from-orbit-400/70 to-plasma-500/60"}"></div><div class="p-5"><div class="flex items-start justify-between gap-3"><div class="min-w-0"><h3 class="truncate text-base font-normal text-white" title="${escapeHtml(pool.name)}">${escapeHtml(pool.name)}</h3><p class="mt-1 font-mono text-xs text-slate-500">${escapeHtml(pool.cidr || "CIDR not set")}</p></div><div class="flex shrink-0 flex-wrap justify-end gap-1.5"><span class="badge ${scopeClass}">${escapeHtml(pool.scope)}</span><span class="badge border-white/10 text-slate-300">${familyLabel}</span>${pool.enabled ? "" : '<span class="badge border-rose-300/20 text-rose-200">Disabled</span>'}</div></div><dl class="mt-4 grid grid-cols-2 gap-3 rounded-xl bg-white/[.025] p-3 text-xs"><div><dt class="text-slate-600">Gateway</dt><dd class="mt-1 truncate font-mono text-slate-300" title="${escapeHtml(pool.gateway || "Node default")}">${escapeHtml(pool.gateway || "Node default")}</dd></div><div><dt class="text-slate-600">Bridge</dt><dd class="mt-1 truncate font-mono text-slate-300" title="${escapeHtml(pool.bridge || "Node default")}">${escapeHtml(pool.bridge || "Node default")}</dd></div><div><dt class="text-slate-600">MTU</dt><dd class="mt-1 text-slate-300">${pool.mtu || "—"}</dd></div><div><dt class="text-slate-600">Tracked</dt><dd class="mt-1 text-slate-300">${counts.total} address${counts.total === 1 ? "" : "es"}</dd></div></dl><div class="mt-4 grid grid-cols-3 gap-2 text-center"><div class="rounded-xl border border-emerald-300/10 bg-emerald-300/[.04] p-2"><p class="text-[10px] uppercase tracking-wider text-slate-600">Free</p><p class="mt-1 text-lg font-extralight text-emerald-200">${counts.free}</p></div><div class="rounded-xl border border-nebula-300/10 bg-nebula-300/[.04] p-2"><p class="text-[10px] uppercase tracking-wider text-slate-600">Reserved</p><p class="mt-1 text-lg font-extralight text-nebula-200">${counts.reserved}</p></div><div class="rounded-xl border border-orbit-300/10 bg-orbit-300/[.04] p-2"><p class="text-[10px] uppercase tracking-wider text-slate-600">Used</p><p class="mt-1 text-lg font-extralight text-orbit-300">${counts.used}</p></div></div></div></article>`;
    }).join("");
  }

  function renderNetworkIps() {
    const query = $("#ip-search")?.value.trim().toLowerCase() || "";
    const statusFilter = $("#ip-status-filter")?.value || "";
    const familyFilter = $("#ip-family-filter")?.value || "";
    const filtered = state.ips.filter((item) => (!query || [item.address, item.pool, item.association, item.gateway, item.status, item.blacklisted ? "blacklisted" : ""].join(" ").toLowerCase().includes(query)) && (!statusFilter || item.status === statusFilter) && (!familyFilter || item.family === familyFilter));
    const body = $("#ip-table-body");
    const wrap = $("#ip-table-wrap");
    if (wrap) wrap.classList.toggle("hidden", filtered.length === 0);
    if (body) body.innerHTML = filtered.map((item) => {
      const statusStyles = { free: "border-emerald-300/20 text-emerald-200", used: "border-orbit-300/20 text-orbit-300", reserved: "border-nebula-300/20 text-nebula-200", main: "border-amber-300/20 text-amber-200" };
      const blacklistBadge = item.blacklisted ? '<span class="badge ml-1 border-rose-300/20 text-rose-200">Blacklisted</span>' : "";
      const association = item.association || (item.status === "free" ? (item.blacklisted ? "Blocked from allocation" : "Available") : "—");
      return `<tr><td><input type="checkbox" data-select-ip="${escapeHtml(item.id)}" ${item.status === "main" ? "disabled" : ""} aria-label="Select ${escapeHtml(item.address)}"></td><td><button type="button" class="font-mono text-xs font-normal text-orbit-300 hover:underline" data-copy="${escapeHtml(item.address)}">${escapeHtml(item.address)}</button><p class="mt-1 text-[10px] uppercase tracking-wider text-slate-600">${escapeHtml(item.family)} · ${escapeHtml(item.scope)}</p></td><td><p class="text-sm text-slate-300">${escapeHtml(item.pool)}</p><p class="mt-1 font-mono text-xs text-slate-600">${escapeHtml(item.cidr || "")}</p></td><td><span class="badge ${statusStyles[item.status] || "border-white/10 text-slate-300"}">${escapeHtml(item.status === "main" ? "Main IP" : item.status)}</span>${blacklistBadge}</td><td><p class="text-sm text-slate-300">${escapeHtml(association)}</p><p class="mt-1 text-xs text-slate-600">${escapeHtml(item.mac_address || item.note || "")}</p></td><td><p class="font-mono text-xs text-slate-400">${escapeHtml(item.gateway || "—")}</p><p class="mt-1 font-mono text-xs text-slate-600">${escapeHtml(item.route || "")}</p></td><td><div class="flex justify-end gap-1">${item.status === "free" ? `<button class="btn-secondary px-3 py-1.5" data-ip-status="reserved" data-ip-id="${escapeHtml(item.id)}">Reserve</button>` : item.status === "reserved" ? `<button class="btn-secondary px-3 py-1.5" data-ip-status="free" data-ip-id="${escapeHtml(item.id)}">Release</button>` : ""}${item.status === "main" ? '<span class="text-xs text-slate-600" title="The node main IP cannot be changed here">Protected</span>' : ""}</div></td></tr>`;
    }).join("");
    $$('[data-copy]').forEach((button) => button.addEventListener("click", () => copyText(button.dataset.copy, "IP address copied")));
    $$('[data-select-ip]').forEach((input) => input.addEventListener("change", updateIpBulk));
    updateIpBulk();
  }

  function updateIpBulk() {
    const count = $$('[data-select-ip]:checked').length;
    const toolbar = $("#ip-bulk-toolbar");
    if (toolbar) { toolbar.classList.toggle("hidden", !count); toolbar.classList.toggle("flex", Boolean(count)); }
    setText("#ip-selected-count", count);
  }

  function renderIpBlacklist(items = []) {
    state.ipBlacklist = items;
    const target = $("#ip-blacklist-list");
    if (!target) return;
    target.innerHTML = items.length ? items.map((entry) => `<div class="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between"><div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><code class="font-mono text-sm text-orbit-300">${escapeHtml(entry.cidr)}</code><span class="badge ${entry.enabled ? "border-rose-300/20 text-rose-200" : "border-slate-300/20 text-slate-400"}">${entry.enabled ? "Active" : "Disabled"}</span></div><p class="mt-1 text-xs text-slate-500">${escapeHtml(entry.reason)}${entry.expires_at ? ` · expires ${escapeHtml(dateTime(entry.expires_at))}` : ""}</p></div><div class="flex shrink-0 gap-2"><button type="button" class="btn-secondary px-3 py-2" data-blacklist-toggle="${escapeHtml(entry.id)}" data-enabled="${entry.enabled ? "true" : "false"}">${entry.enabled ? "Disable" : "Enable"}</button><button type="button" class="btn-danger px-3 py-2" data-blacklist-delete="${escapeHtml(entry.id)}">Delete</button></div></div>`).join("") : '<p class="py-4 text-sm text-slate-500">No addresses are blacklisted.</p>';
  }

  async function loadNetwork() {
    $("#network-loading")?.classList.remove("hidden");
    $("#network-pools-loading")?.classList.remove("hidden");
    try {
      const [poolsResult, addressesResult, settingsResult, hostResult, blacklistResult] = await Promise.allSettled([
        apiFirst(["/api/v1/network/pools?limit=500", "/api/v1/networks?limit=500"]),
        apiFirst(["/api/v1/network/addresses?limit=2000", "/api/v1/ip-addresses?limit=2000"]),
        api("/api/v1/settings"), api("/api/v1/host"),
        api("/api/v1/network/blacklist"),
      ]);
      state.pools = (poolsResult.status === "fulfilled" ? listPayload(poolsResult.value).items : []).map(normalizePool);
      const poolsById = new Map(state.pools.map((pool) => [String(pool.id), pool]));
      state.ips = (addressesResult.status === "fulfilled" ? listPayload(addressesResult.value).items : []).map((item) => {
        const address = normalizeIp(item);
        const pool = poolsById.get(String(address.pool_id || address.poolId || ""));
        return pool ? { ...address, pool: pool.name, cidr: pool.cidr, gateway: address.gateway || pool.gateway } : address;
      }).sort(compareIpAddresses);
      const settings = settingsResult.status === "fulfilled" ? (settingsResult.value?.data || settingsResult.value?.settings || settingsResult.value) : {};
      const host = hostResult.status === "fulfilled" ? extractHost(hostResult.value) : {};
      const free = state.ips.filter((item) => item.status === "free" && item.assignable !== false && item.blacklisted !== true).length; const used = state.ips.filter((item) => item.status === "used").length; const reserved = state.ips.filter((item) => ["reserved", "main"].includes(item.status)).length; const blacklistedFree = state.ips.filter((item) => item.status === "free" && item.blacklisted === true).length;
      setText("#ip-total", state.ips.length); setText("#ip-free", free); setText("#ip-used", used); setText("#ip-reserved", reserved);
      setText("#ip-total-detail", `${state.ips.filter((item) => item.family === "ipv4").length} IPv4 · ${state.ips.filter((item) => item.family === "ipv6").length} IPv6`);
      setText("#network-summary", `${state.pools.length} pool${state.pools.length === 1 ? "" : "s"} · ${free} assignable address${free === 1 ? "" : "es"}${blacklistedFree ? ` · ${blacklistedFree} blacklisted` : ""}`);
      $("#network-empty")?.classList.toggle("hidden", state.ips.length > 0 || state.pools.length > 0);
      renderNetworkPools();
      renderNetworkIps();
      renderIpBlacklist(blacklistResult.status === "fulfilled" ? listPayload(blacklistResult.value).items : []);
      setText("#uplink-name", host.public_interface || settings.public_interface || "Unknown interface");
      const uplink = host.network || {};
      const status = $("#uplink-status");
      if (status) { const online = host.network_online ?? uplink.online ?? Boolean(host.primary_ip); status.textContent = online ? "Online" : "Unknown"; status.className = `badge ${online ? "border-emerald-300/20 text-emerald-200" : "border-white/10 text-slate-400"}`; }
      const mainIp = state.ips.find((item) => item.status === "main")?.address || host.primary_ip || "—";
      const facts = [["Main IP", mainIp], ["Gateway", host.public_gateway || settings.public_gateway || "—"], ["MTU", host.mtu || settings.mtu || "—"], ["Bridge", settings.default_bridge || host.bridge || "—"]];
      const factTarget = $("#uplink-facts"); if (factTarget) factTarget.innerHTML = facts.map(([label, value]) => `<div class="flex justify-between gap-4 py-3"><dt class="text-sm text-slate-500">${escapeHtml(label)}</dt><dd class="text-right font-mono text-sm text-slate-300">${escapeHtml(value)}</dd></div>`).join("");
      setText("#uplink-rx", byteRate(uplink.rx_bps)); setText("#uplink-tx", byteRate(uplink.tx_bps));
      fillForm($("#network-defaults-form"), { dns_servers: settings.dns_servers || settings.network?.dns_servers || [], default_port_limit_mbps: settings.default_port_limit_mbps || settings.network?.default_port_limit_mbps, default_traffic_quota_gb: finite(settings.default_traffic_quota_bytes || settings.network?.default_traffic_quota_bytes) / GiB, allow_unlimited_traffic: Boolean(settings.allow_unlimited_traffic ?? settings.network?.allow_unlimited_traffic), default_bridge: settings.default_bridge || settings.network?.default_bridge });
      setLiveState("live", "Live");
    } catch (error) { toast(error.message, "error", error.requestId); setLiveState("error", "Unavailable"); }
    finally { $("#network-loading")?.classList.add("hidden"); $("#network-pools-loading")?.classList.add("hidden"); }
  }

  async function setIpStatus(id, status) {
    try { await apiFirst([`/api/v1/network/addresses/${encodeURIComponent(id)}`, `/api/v1/ip-addresses/${encodeURIComponent(id)}`], { method: "PATCH", body: { status } }); toast(`Address marked ${status}`, "success"); await loadNetwork(); } catch (error) { toast(error.message, "error", error.requestId); }
  }

  async function initNetwork() {
    $("#ip-search")?.addEventListener("input", renderNetworkIps); $("#ip-status-filter")?.addEventListener("change", renderNetworkIps); $("#ip-family-filter")?.addEventListener("change", renderNetworkIps);
    $$('[data-refresh-network]').forEach((button) => button.addEventListener("click", loadNetwork));
    $$('[data-open-network-dialog]').forEach((button) => button.addEventListener("click", () => $("#network-dialog")?.showModal()));
    $$('[data-close-network-dialog]').forEach((button) => button.addEventListener("click", () => $("#network-dialog")?.close()));
    document.addEventListener("click", (event) => { const button = event.target.closest("[data-ip-status]"); if (button) setIpStatus(button.dataset.ipId, button.dataset.ipStatus); });
    $("#select-all-ips")?.addEventListener("change", (event) => { $$('[data-select-ip]:not(:disabled)').forEach((input) => { input.checked = event.target.checked; }); updateIpBulk(); });
    $$('[data-ip-bulk]').forEach((button) => button.addEventListener("click", async () => { const ids = $$('[data-select-ip]:checked').map((input) => input.dataset.selectIp); const status = button.dataset.ipBulk === "reserve" ? "reserved" : "free"; await Promise.allSettled(ids.map((id) => apiFirst([`/api/v1/network/addresses/${encodeURIComponent(id)}`, `/api/v1/ip-addresses/${encodeURIComponent(id)}`], { method: "PATCH", body: { status } }))); toast(`${ids.length} address${ids.length === 1 ? "" : "es"} updated`, "success"); await loadNetwork(); }));
    $("#network-range-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return; const values = formObject(form); const errorBox = $("#network-dialog-error"); errorBox?.classList.add("hidden"); try { await apiFirst(["/api/v1/network/pools", "/api/v1/networks"], { method: "POST", body: { name: values.name, cidr: values.cidr, gateway: values.gateway || null, scope: values.scope, bridge: values.bridge || null, vlan_id: null, mtu: finite(values.mtu) || 1500, enabled: true, reserved: splitLines(values.reserved) } }); form.reset(); form.elements.mtu.value = "1500"; $("#network-dialog")?.close(); toast("IP range added", "success"); await loadNetwork(); } catch (error) { if (errorBox) { errorBox.textContent = error.message; errorBox.classList.remove("hidden"); } } });
    $("#network-defaults-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); try { await api("/api/v1/settings", { method: "PATCH", body: { network: { dns_servers: splitLines(values.dns_servers), default_port_limit_mbps: finite(values.default_port_limit_mbps), default_traffic_quota_bytes: finite(values.default_traffic_quota_gb) > 0 ? finite(values.default_traffic_quota_gb) * GiB : null, allow_unlimited_traffic: Boolean(values.allow_unlimited_traffic), default_bridge: values.default_bridge } } }); toast("Network defaults saved", "success"); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#ip-blacklist-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const values = formObject(form); try { await api("/api/v1/network/blacklist", { method: "POST", body: { cidr: values.cidr, reason: values.reason, source: "manual", enabled: true, expires_at: null, metadata: {} } }); form.reset(); toast("Address blacklisted", "success"); await loadNetwork(); } catch (error) { toast(error.message, "error", error.requestId); } });
    document.addEventListener("click", async (event) => { const toggle = event.target.closest("[data-blacklist-toggle]"); const remove = event.target.closest("[data-blacklist-delete]"); if (!toggle && !remove) return; const recordId = toggle?.dataset.blacklistToggle || remove?.dataset.blacklistDelete; if (remove) { const approved = await confirmAction({ title: "Delete blacklist entry?", message: "The address may be assigned to a VM again.", confirmLabel: "Delete entry" }); if (!approved) return; } try { if (toggle) await api(`/api/v1/network/blacklist/${encodeURIComponent(recordId)}`, { method: "PATCH", body: { enabled: toggle.dataset.enabled !== "true" } }); else await api(`/api/v1/network/blacklist/${encodeURIComponent(recordId)}`, { method: "DELETE" }); toast(toggle ? "Blacklist updated" : "Blacklist entry deleted", "success"); await loadNetwork(); } catch (error) { toast(error.message, "error", error.requestId); } });
    await loadNetwork();
  }

  function normalizeImage(item = {}) {
    const available = item.available ?? Boolean(item.local_path || item.path);
    const status = item.status || item.state || (available ? "ready" : "missing");
    return { ...item, id: item.id || item.slug || item.filename, name: imageLabel(item), status, mode: imageMode(item), architecture: item.architecture || item.arch || "x86_64", sizeBytes: finite(item.size_bytes || item.size), checksum: item.sha256 || item.checksum_sha256 || item.checksum || "", guestAgent: Boolean(item.guest_agent ?? item.supports_guest_agent), guestTools: item.guest_tools || null, uefi: Boolean(item.uefi ?? item.supports_uefi), cloudInit: Boolean(item.cloud_init ?? item.supports_cloud_init), available, verifiedAt: item.verified_at || item.metadata?.verified_at || null };
  }

  function renderImages() {
    const query = $("#image-library-search")?.value.trim().toLowerCase() || "";
    const stateFilter = $("#image-state-filter")?.value || ""; const modeFilter = $("#image-mode-filter")?.value || "";
    const filtered = state.images.filter((image) => (!query || [image.name, image.slug, image.os_family, image.version, image.architecture].join(" ").toLowerCase().includes(query)) && (!stateFilter || image.status === stateFilter) && (!modeFilter || image.mode === modeFilter));
    $("#images-empty")?.classList.toggle("hidden", state.images.length > 0); $("#images-no-results")?.classList.toggle("hidden", !state.images.length || filtered.length > 0);
    const grid = $("#image-grid"); if (!grid) return;
    grid.classList.toggle("hidden", filtered.length === 0);
    grid.innerHTML = filtered.map((image) => {
      const ready = image.status === "ready";
      const progress = clamp(image.progress);
      const remote = Boolean(image.source_url);
      const canVerify = Boolean(image.local_path || image.path || remote) && image.status !== "downloading";
      const verifyLabel = remote && !image.available ? "Download & verify" : "Verify";
      const verifyTitle = remote && !image.available
        ? "Download this HTTPS image and publish it only after its SHA-256 matches"
        : "Hash this local image and validate its SHA-256";
      return `<article class="panel group overflow-hidden"><div class="h-1 bg-gradient-to-r from-orbit-400 via-plasma-500 to-nebula-500 opacity-70"></div><div class="p-5"><div class="flex items-start gap-3"><span class="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-orbit-400/10 to-nebula-400/15 text-sm font-normal text-orbit-300">${escapeHtml((image.os_family || image.name).slice(0, 2).toUpperCase())}</span><div class="min-w-0 flex-1"><h2 class="truncate text-base font-normal text-white" title="${escapeHtml(image.name)}">${escapeHtml(image.name)}</h2><p class="mt-1 truncate text-xs text-slate-500">${escapeHtml(image.version || image.slug || "")}${image.architecture ? ` · ${escapeHtml(image.architecture)}` : ""}</p></div>${statusBadge(ready ? "running" : image.status).replace("Running", "Ready")}</div><div class="mt-4 flex flex-wrap gap-1.5"><span class="badge border-${image.mode === "manual" ? "amber" : "emerald"}-300/20 text-${image.mode === "manual" ? "amber" : "emerald"}-200">${escapeHtml(image.mode)}</span>${image.guestAgent ? '<span class="badge border-orbit-300/20 text-orbit-300">Guest agent</span>' : '<span class="badge border-white/10 text-slate-500">No agent</span>'}${image.uefi ? '<span class="badge border-plasma-300/20 text-plasma-300">UEFI</span>' : ""}</div><dl class="mt-4 grid grid-cols-2 gap-3 rounded-xl bg-white/[.025] p-3 text-xs"><div><dt class="text-slate-600">Size</dt><dd class="mt-1 text-slate-300">${image.sizeBytes ? bytes(image.sizeBytes) : "Unknown"}</dd></div><div><dt class="text-slate-600">Checksum</dt><dd class="mt-1 truncate font-mono text-slate-300" title="${escapeHtml(image.checksum)}">${image.checksum ? `${escapeHtml(image.checksum.slice(0, 10))}…` : "Not set"}</dd></div><div><dt class="text-slate-600">Cloud-init</dt><dd class="mt-1 text-slate-300">${image.cloudInit ? "Supported" : "No"}</dd></div><div><dt class="text-slate-600">Last verified</dt><dd class="mt-1 text-slate-300">${image.verifiedAt ? relativeTime(image.verifiedAt) : "Never"}</dd></div></dl>${image.status === "downloading" ? `<div class="mt-4"><div class="flex justify-between text-xs text-slate-500"><span>${escapeHtml(image.status_message || "Downloading")}</span><span>${Math.round(progress)}%</span></div><div class="metric-track mt-2"><div class="metric-fill" style="width:${progress}%"></div></div></div>` : ""}<div class="mt-5 flex justify-end gap-2"><button type="button" class="btn-secondary px-3 py-2" data-image-action="verify" data-image-id="${escapeHtml(image.id)}" ${canVerify ? "" : "disabled"} title="${canVerify ? verifyTitle : "Verification requires a local file or HTTPS source URL"}">${verifyLabel}</button><button type="button" class="btn-danger px-3 py-2" data-image-action="delete" data-image-id="${escapeHtml(image.id)}">Delete</button></div></div></article>`;
    }).join("");
  }

  async function loadImages() {
    $("#images-loading")?.classList.remove("hidden"); $("#images-error")?.classList.add("hidden");
    try { const payload = await apiFirst(["/api/v1/isos", "/api/v1/images"]); state.images = listPayload(payload).items.map(normalizeImage); setText("#image-summary", `${state.images.filter((item) => item.status === "ready").length} ready · ${state.images.filter((item) => item.status === "downloading").length} downloading · ${state.images.filter((item) => ["missing", "error"].includes(item.status)).length} unavailable`); renderImages(); setLiveState("live", "Live"); }
    catch (error) { $("#images-error")?.classList.remove("hidden"); setText("#images-error-message", `${error.message}${error.requestId ? ` · Request ${error.requestId}` : ""}`); setLiveState("error", "Unavailable"); }
    finally { $("#images-loading")?.classList.add("hidden"); }
  }

  function setImageSource(type) {
    $$('[data-image-source]').forEach((section) => section.classList.toggle("hidden", section.dataset.imageSource !== type));
    $$('input[name="source_type"]').forEach((input) => { const label = input.closest("label"); const active = input.value === type; label?.classList.toggle("border-plasma-400/30", active); label?.classList.toggle("bg-plasma-500/10", active); label?.classList.toggle("border-white/[.07]", !active); label?.classList.toggle("bg-white/[.025]", !active); });
    const url = $("#image-url");
    const file = $("#image-file");
    const path = $("#image-path");
    const checksum = $("#image-import-form [name='sha256']");
    if (url) url.required = type === "url";
    if (file) file.required = type === "upload";
    if (path) path.required = type === "local";
    if (checksum) checksum.required = type === "url";
  }

  async function uploadImage(formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest(); xhr.open("POST", "/api/v1/isos/upload"); xhr.responseType = "json"; xhr.setRequestHeader("Accept", "application/json"); const csrf = csrfToken(); if (csrf) xhr.setRequestHeader("X-CSRF-Token", csrf);
      xhr.upload.addEventListener("progress", (event) => { if (event.lengthComputable) onProgress(event.loaded * 100 / event.total); });
      xhr.addEventListener("load", () => { if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response); else { const detail = xhr.response?.error || {}; reject(new ApiError(detail.message || `Upload failed with status ${xhr.status}`, xhr.status, detail.code, detail.request_id)); } }); xhr.addEventListener("error", () => reject(new ApiError("The upload connection failed."))); xhr.send(formData);
    });
  }

  async function initImages() {
    $("#image-library-search")?.addEventListener("input", renderImages); $("#image-state-filter")?.addEventListener("change", renderImages); $("#image-mode-filter")?.addEventListener("change", renderImages);
    $$('[data-rescan-images]').forEach((button) => button.addEventListener("click", loadImages));
    $$('[data-open-image-dialog]').forEach((button) => button.addEventListener("click", () => $("#image-dialog")?.showModal())); $$('[data-close-image-dialog]').forEach((button) => button.addEventListener("click", () => $("#image-dialog")?.close()));
    $("[data-clear-image-filters]")?.addEventListener("click", () => { $("#image-library-search").value = ""; $("#image-state-filter").value = ""; $("#image-mode-filter").value = ""; renderImages(); });
    $$('input[name="source_type"]').forEach((input) => input.addEventListener("change", () => setImageSource(input.value)));
    setImageSource($('input[name="source_type"]:checked')?.value || "url");
    document.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-image-action]");
      if (!button || button.disabled) return;
      const image = state.images.find((item) => String(item.id) === button.dataset.imageId);
      const originalLabel = button.textContent;
      try {
        if (button.dataset.imageAction === "delete") {
          const approved = await confirmAction({ title: `Delete ${image?.name || "image"}?`, message: "Only the catalog entry is removed. Local image files and existing VM disks are not changed.", phrase: image?.name || "", confirmLabel: "Delete entry" });
          if (!approved) return;
          await apiFirst([`/api/v1/isos/${encodeURIComponent(button.dataset.imageId)}`, `/api/v1/images/${encodeURIComponent(button.dataset.imageId)}`], { method: "DELETE" });
          toast("Catalog entry deleted", "success");
        } else if (button.dataset.imageAction === "verify") {
          button.disabled = true;
          button.textContent = image?.source_url && !image?.available ? "Downloading…" : "Verifying…";
          await apiFirst([`/api/v1/isos/${encodeURIComponent(button.dataset.imageId)}/verify`, `/api/v1/images/${encodeURIComponent(button.dataset.imageId)}/verify`], { method: "POST", body: {} });
          toast(image?.source_url && !image?.available ? "Remote image downloaded and verified" : "Image checksum verified", "success");
        }
        await loadImages();
      } catch (error) {
        toast(error.message, "error", error.requestId);
      } finally {
        if (button.isConnected) { button.disabled = false; button.textContent = originalLabel; }
      }
    });
    $("#image-import-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      if (!form.reportValidity()) return;
      const values = formObject(form);
      const source = values.source_type;
      const progress = $("#image-import-progress");
      const errorBox = $("#image-dialog-error");
      errorBox?.classList.add("hidden");
      progress?.classList.remove("hidden");
      setText("#image-progress-label", source === "url" ? "Preparing secure download…" : "Uploading…");
      setText("#image-progress-percent", "0%");
      try {
        let response;
        if (source === "upload") {
          const data = new FormData();
          for (const [key, value] of new FormData(form).entries()) {
            if (key !== "source_type") data.append(key, value);
          }
          response = await uploadImage(data, (value) => {
            setProgress("#image-progress-bar", value);
            setText("#image-progress-percent", `${Math.round(value)}%`);
          });
        } else {
          const checksum = String(values.sha256 || "").trim();
          if (source === "url" && !/^[a-fA-F0-9]{64}$/.test(checksum)) {
            throw new ApiError("A 64-character SHA-256 checksum is required for remote downloads.");
          }
          response = await api("/api/v1/isos", {
            method: "POST",
            headers: { "Idempotency-Key": randomUuid() },
            body: {
              source_url: source === "url" ? (values.url || null) : null,
              local_path: source === "local" ? (values.path || null) : null,
              name: values.name,
              slug: values.slug,
              version: null,
              os_family: values.os_family || "unknown",
              architecture: values.architecture,
              install_mode: String(values.provisioning_mode).replaceAll("-", "_"),
              checksum_sha256: checksum || null,
              size_bytes: null,
              supports_guest_agent: Boolean(values.guest_agent),
              supports_cloud_init: values.provisioning_mode === "cloud-init",
              uefi: Boolean(values.uefi),
              enabled: true,
              metadata: {
                ...(values.guest_tools_provisioner ? { guest_tools_provisioner: values.guest_tools_provisioner } : {}),
                ...(values.signed_virtio_serial_driver ? { virtio_serial_driver: "installed_signed" } : {}),
              },
            },
          });
          if (source === "url" || source === "local") {
            const image = response?.data?.image || response?.image;
            if (!image?.id) throw new ApiError("The server did not return the image identifier.");
            setProgress("#image-progress-bar", 15);
            setText("#image-progress-label", source === "url" ? "Downloading and verifying SHA-256…" : "Hashing and verifying local image…");
            setText("#image-progress-percent", source === "url" ? "Secure" : "Verifying");
            response = await api(`/api/v1/isos/${encodeURIComponent(image.id)}/verify`, { method: "POST", body: {} });
            setProgress("#image-progress-bar", 100);
            setText("#image-progress-percent", "Verified");
          }
        }
        if (response?.operation || response?.data?.operation) {
          await followOperation(response?.data || response, (operation) => {
            setProgress("#image-progress-bar", operation.progress || 5);
            setText("#image-progress-label", operation.message || operation.status);
          });
        }
        form.reset();
        setImageSource("url");
        $("#image-dialog")?.close();
        toast(source === "url" ? "Remote image downloaded and verified" : source === "local" ? "Local image verified" : "Image import accepted", "success");
        await loadImages();
      } catch (error) {
        if (errorBox) {
          errorBox.textContent = `${error.message}${error.requestId ? ` · ${error.requestId}` : ""}`;
          errorBox.classList.remove("hidden");
        }
      } finally {
        progress?.classList.add("hidden");
        setProgress("#image-progress-bar", 0);
        setText("#image-progress-label", "Uploading…");
        setText("#image-progress-percent", "0%");
      }
    });
    await loadImages();
  }

  function settingsValues(settings, section) {
    const nested = settings[section] || {};
    return { ...settings, ...nested };
  }

  function showSettingsTab(name) {
    $$('[data-settings-tab]').forEach((button) => {
      const active = button.dataset.settingsTab === name;
      button.className = active ? "min-w-max w-full rounded-xl bg-nebula-500/15 px-3 py-2.5 text-left text-sm font-normal text-white ring-1 ring-nebula-400/20" : "min-w-max w-full rounded-xl px-3 py-2.5 text-left text-sm text-slate-500 hover:bg-white/5 hover:text-white";
    });
    $$('[data-settings-panel]').forEach((panel) => panel.classList.toggle("hidden", panel.dataset.settingsPanel !== name));
    history.replaceState(null, "", `${location.pathname}#${name}`);
    if (name === "api") loadApiKeys();
    if (name === "updates") loadUpdates();
    if (name === "security") loadAdmins();
  }

  async function loadSettings() {
    try {
      const [payload, authPayload] = await Promise.all([api("/api/v1/settings"), api("/api/v1/auth/me")]);
      const settings = payload?.data || payload?.settings || payload || {};
      state.auth = authPayload?.data || authPayload || {};
      const permissions = asArray(state.auth.permissions);
      const allows = (permission) => permissions.includes("*") || permissions.includes(permission);
      for (const form of $$('[data-settings-form]')) {
        const section = form.dataset.settingsForm;
        if (section === "account") continue;
        const values = settingsValues(settings, section);
        if (section === "storage") fillForm(form, { ...values, snapshot_retention: values.snapshot_retention ?? values.backups?.snapshot_retention, backup_compression: values.backup_compression ?? values.backups?.compression, backup_target: values.backup_target ?? values.backups?.target, verify_backups: values.verify_backups ?? values.backups?.verify });
        else if (section === "network") fillForm(form, { ...values, dns_servers: values.dns_servers || settings.network?.dns_servers || [], default_traffic_quota_gb: finite(values.default_traffic_quota_bytes) / GiB });
        else fillForm(form, values);
        form.dataset.dirty = "false";
        if (!allows("settings:write")) $$('input, select, textarea, button[type="submit"]', form).forEach((control) => { control.disabled = true; });
      }
      fillForm($("#account-form"), { username: state.auth.admin?.username || "admin" });
      $$('input[name="scopes"]', $("#api-key-form") || document).forEach((input) => {
        input.disabled = !allows(input.value);
        input.closest("label")?.classList.toggle("opacity-40", input.disabled);
      });
      $$('[data-open-api-key-dialog]').forEach((button) => { button.disabled = !allows("api_keys:write"); });
      $$('[data-open-admin-dialog]').forEach((button) => { button.disabled = !allows("admins:write"); });
      $("#admins-read-only")?.classList.toggle("hidden", allows("admins:write"));
      setText("#encryption-key-status", "An environment-owned AES-256-GCM key protects recoverable guest credentials.");
      const runtime = settings.runtime || {};
      setText("#settings-runtime-libvirt", runtime.libvirt_uri || "Not reported");
      setText("#settings-runtime-backend", runtime.hypervisor_mode ? `${String(runtime.hypervisor_mode).toUpperCase()} backend` : "Not reported");
      setText("#settings-runtime-bridge", runtime.network_bridge || "Not reported");
      setText("#settings-runtime-console", runtime.vnc_ttl_seconds ? `Loopback-only VNC relay · ${runtime.vnc_ttl_seconds / 60} minute token` : "Loopback-only VNC relay");
      setText("#settings-runtime-vm-storage", runtime.vm_storage || "Not reported");
      setText("#settings-runtime-iso-storage", runtime.iso_storage || "Not reported");
      setText("#settings-runtime-cloud-init-storage", runtime.cloud_init_storage || "Not reported");
      setText("#settings-summary", `${settings.general?.node_name || "Local node"} · saved settings and read-only runtime details`);
      const canManageHostNetworkSecurity = allows("network:write");
      $("#ip-ownership-guard-enabled")?.toggleAttribute("disabled", !canManageHostNetworkSecurity);
      $("#bcp38-enabled")?.toggleAttribute("disabled", !canManageHostNetworkSecurity);
      $("#save-host-network-security")?.toggleAttribute("disabled", !canManageHostNetworkSecurity);
      $("#host-network-security-panel")?.classList.toggle("opacity-60", !canManageHostNetworkSecurity);
      try {
        const networkSecurity = await api("/api/v1/network/security");
        const profile = networkSecurity?.data?.profile || networkSecurity?.profile || {};
        const ownershipToggle = $("#ip-ownership-guard-enabled"); if (ownershipToggle) { ownershipToggle.checked = profile.ip_ownership_guard_enabled !== false; ownershipToggle.dataset.original = String(ownershipToggle.checked); }
        const toggle = $("#bcp38-enabled"); if (toggle) { toggle.checked = profile.bcp38_enabled === true; toggle.dataset.original = String(toggle.checked); }
        setText("#ip-ownership-guard-state", profile.last_error ? `Not applied: ${profile.last_error}` : profile.ip_ownership_guard_enabled !== false ? `Enabled · revision ${profile.revision}${profile.applied_revision === profile.revision ? " applied" : " pending"}` : "Disabled · managed-pool ownership is not enforced");
        setText("#bcp38-state", profile.last_error ? `Not applied: ${profile.last_error}` : profile.bcp38_enabled ? `Enabled · revision ${profile.revision}${profile.applied_revision === profile.revision ? " applied" : " pending"}` : "Disabled · no BCP38 packet filtering is active");
      } catch (error) { setText("#ip-ownership-guard-state", error.message); setText("#bcp38-state", error.message); }
      setLiveState("live", "Saved");
    } catch (error) { const alert = $("#settings-alert"); if (alert) { alert.textContent = `${error.message}${error.requestId ? ` · Request ${error.requestId}` : ""}`; alert.classList.remove("hidden"); } setLiveState("error", "Unavailable"); }
  }

  async function loadApiKeys() {
    const loading = $("#api-keys-loading"); loading?.classList.remove("hidden");
    try {
      const keys = listPayload(await api("/api/v1/api-keys")).items; const target = $("#api-keys-list");
      $("#api-keys-empty")?.classList.toggle("hidden", keys.length > 0);
      if (target) target.innerHTML = keys.map((key) => `<div class="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between"><div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><p class="font-normal text-slate-200">${escapeHtml(key.name)}</p>${key.revoked_at ? '<span class="badge border-rose-300/20 text-rose-200">Revoked</span>' : '<span class="badge border-emerald-300/20 text-emerald-200">Active</span>'}</div><p class="mt-1 truncate font-mono text-xs text-slate-600">${escapeHtml(key.prefix || key.id)}… · ${escapeHtml(asArray(key.permissions || key.scopes).join(", ") || "No permissions")}</p><p class="mt-1 text-xs text-slate-600">${key.last_used_at ? `Last used ${relativeTime(key.last_used_at)}` : "Never used"}${key.expires_at ? ` · Expires ${dateTime(key.expires_at)}` : ""}</p></div>${key.revoked_at ? "" : `<button type="button" class="btn-danger shrink-0 px-3 py-2" data-revoke-api-key="${escapeHtml(key.id)}">Revoke</button>`}</div>`).join("");
    } catch (error) { toast(error.message, "error", error.requestId); }
    finally { loading?.classList.add("hidden"); }
  }

  function adminRoleLabel(role) {
    return ({ super_admin: "Super administrator", admin: "Administrator", read_only: "Read-only auditor" })[role] || String(role || "Unknown").replaceAll("_", " ");
  }

  const adminPermissionLabels = {
    "host:read": "View node health", "vms:read": "View virtual machines",
    "vms:create": "Create virtual machines", "vms:edit": "Edit VM identity and policy",
    "vms:power": "Power and suspend VMs", "vms:reinstall": "Rebuild / reinstall VMs",
    "vms:resources:write": "Change CPU, RAM, disk or speed", "vms:traffic:write": "Change or reset traffic quota",
    "vms:network:write": "Change VM networking and firewall", "vms:delete": "Delete virtual machines",
    "vms:snapshots:write": "Manage VM snapshots", "vms:password:read": "Reveal stored VM passwords",
    "vms:password:write": "Change VM passwords", "vms:vnc": "Open VNC consoles",
    "network:read": "View node networks", "network:write": "Manage node networks and IPs",
    "isos:read": "View images and ISOs", "isos:write": "Manage images and ISOs",
    "settings:read": "View settings", "settings:write": "Change settings",
    "admins:read": "View administrators", "api_keys:read": "View API keys",
    "api_keys:write": "Manage API keys", "audit:read": "View audit logs",
    "updates:read": "View available updates", "jobs:read": "View operations",
    "jobs:write": "Cancel operations",
  };

  function adminPermissionInputs(available, selected, disabled = false) {
    const granted = new Set(asArray(selected));
    return asArray(available).map((permission) => `<label class="flex items-start gap-2 rounded-lg border border-white/[.06] p-2 text-xs text-slate-300"><input type="checkbox" data-admin-permission value="${escapeHtml(permission)}" ${granted.has(permission) ? "checked" : ""} ${disabled ? "disabled" : ""}><span>${escapeHtml(adminPermissionLabels[permission] || permission)}</span></label>`).join("");
  }

  async function loadAdmins() {
    const loading = $("#admins-loading"); loading?.classList.remove("hidden");
    try {
      const response = await api("/api/v1/admins");
      const admins = listPayload(response).items;
      const grantable = asArray(response?.grantable_permissions || Object.keys(adminPermissionLabels));
      state.adminGrantablePermissions = grantable;
      const createPermissions = $("[data-admin-create-permissions]");
      if (createPermissions && !createPermissions.children.length) {
        createPermissions.innerHTML = adminPermissionInputs(grantable, grantable, true);
      }
      const target = $("#admins-list");
      const permissions = asArray(state.auth?.permissions);
      const writable = permissions.includes("*") || permissions.includes("admins:write");
      const currentId = state.auth?.admin?.id || "";
      $("#admins-empty")?.classList.toggle("hidden", admins.length > 0);
      if (target) target.innerHTML = admins.map((admin) => {
        const isCurrent = admin.id === currentId;
        const roleOptions = ["super_admin", "admin", "read_only"].map((role) => `<option value="${role}" ${admin.role === role ? "selected" : ""}>${escapeHtml(adminRoleLabel(role))}</option>`).join("");
        const customDisabled = !writable || admin.role === "super_admin" || admin.uses_role_defaults;
        return `<div class="py-5" data-admin-row="${escapeHtml(admin.id)}"><div class="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between"><div class="min-w-0"><div class="flex flex-wrap items-center gap-2"><p class="font-normal text-slate-100">${escapeHtml(admin.username)}</p>${isCurrent ? '<span class="badge border-orbit-300/20 text-orbit-200">Current account</span>' : ""}${admin.enabled ? '<span class="badge border-emerald-300/20 text-emerald-200">Enabled</span>' : '<span class="badge border-rose-300/20 text-rose-200">Disabled</span>'}</div><p class="mt-1 text-xs text-slate-600">Created ${dateTime(admin.created_at)}${admin.last_login_at ? ` · Last login ${dateTime(admin.last_login_at)}` : " · Never signed in"}</p></div><div class="flex flex-col gap-3 sm:flex-row sm:items-end"><label><span class="label">Access level</span><select class="field min-w-52" data-admin-role ${writable ? "" : "disabled"}>${roleOptions}</select></label><label class="flex h-[2.75rem] items-center gap-2 rounded-xl border border-white/[.08] px-3 text-sm text-slate-300"><input type="checkbox" data-admin-enabled ${admin.enabled ? "checked" : ""} ${writable ? "" : "disabled"}>Enabled</label><div class="flex flex-wrap gap-2"><button type="button" class="btn-secondary px-3 py-2" data-save-admin ${writable ? "" : "disabled"}>Save</button>${isCurrent ? "" : `<button type="button" class="btn-secondary px-3 py-2" data-reset-admin-password data-admin-name="${escapeHtml(admin.username)}" ${writable ? "" : "disabled"}>Password</button><button type="button" class="btn-danger px-3 py-2" data-delete-admin data-admin-name="${escapeHtml(admin.username)}" ${writable ? "" : "disabled"}>Delete</button>`}</div></div></div><details class="mt-4 rounded-xl border border-white/[.07] p-3"><summary class="cursor-pointer text-sm text-slate-300">Fine-grained privileges</summary><label class="mt-3 flex items-center gap-2 text-xs text-slate-400"><input type="checkbox" data-admin-role-defaults ${admin.uses_role_defaults ? "checked" : ""} ${!writable || admin.role === "super_admin" ? "disabled" : ""}>Use role defaults</label><div data-admin-permissions class="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3 ${customDisabled ? "opacity-40" : ""}">${adminPermissionInputs(grantable, admin.permissions, customDisabled)}</div></details></div>`;
      }).join("");
    } catch (error) { toast(error.message, "error", error.requestId); }
    finally { loading?.classList.add("hidden"); }
  }

  function updateSelectionState() {
    const selected = $$('[data-update-component]:checked').length;
    const accepted = Boolean($("#updates-maintenance")?.checked);
    const canApprove = state.updates?.activation_executor_available === true
      && (asArray(state.auth?.permissions).includes("*") || asArray(state.auth?.permissions).includes("updates:write"))
      && state.auth?.admin?.role === "super_admin";
    $("#approve-update")?.toggleAttribute("disabled", !canApprove || !accepted || selected === 0);
  }

  function updateRollbackSelectionState() {
    const accepted = Boolean($("#updates-rollback-maintenance")?.checked);
    const canApprove = state.updates?.enabled !== false
      && state.updates?.activation_executor_available === true
      && Boolean(state.updates?.rollback_point)
      && (asArray(state.auth?.permissions).includes("*") || asArray(state.auth?.permissions).includes("updates:write"))
      && state.auth?.admin?.role === "super_admin";
    $("#approve-rollback")?.toggleAttribute("disabled", !canApprove || !accepted);
  }

  function renderUpdates(payload = {}) {
    const update = payload?.data || payload || {};
    state.updates = update;
    const snapshot = update.state || {};
    const release = snapshot.release || null;
    const disabled = $("#updates-disabled");
    if (disabled) {
      disabled.textContent = update.enabled === false ? (update.reason || "Signed updates are disabled on this node.") : "";
      disabled.classList.toggle("hidden", update.enabled !== false);
    }
    setText("#updates-current", update.current_version || snapshot.current_version || "Unknown");
    setText("#updates-latest", release?.tag || "Not checked");
    setText("#updates-signer", release ? `${release.signer_key_id} · ${release.manifest_sha256}` : "Not checked");
    setText("#updates-executor", update.activation_executor_available ? "Installed and ready" : "Unavailable (activation remains blocked)");
    const executorStatus = update.latest_executor_status || asArray(update.executor_statuses)[0] || null;
    setText("#updates-executor-state", executorStatus
      ? `${String(executorStatus.outcome || "unknown").replace(/_/g, " ")} · ${executorStatus.phase || "unknown phase"} · ${executorStatus.message || "No detail"} · ${dateTime(executorStatus.updated_at)}`
      : "No operation has been recorded.");
    $("#check-updates")?.toggleAttribute("disabled", update.enabled === false || !(asArray(state.auth?.permissions).includes("*") || asArray(state.auth?.permissions).includes("updates:write")));
    const staged = new Map(asArray(snapshot.staged).map((item) => [item.component, item]));
    const components = asArray(release?.manifest?.components);
    const target = $("#updates-components");
    if (target) target.innerHTML = components.length ? components.map((item) => {
      const delivery = item.delivery || {};
      const archive = delivery.type === "signed_archive";
      const stagedItem = staged.get(item.component);
      const packages = asArray(delivery.packages).map((entry) => `${entry.name}=${entry.candidate_version}`).join(", ");
      const ready = !archive || Boolean(stagedItem);
      return `<div class="rounded-xl border border-white/[.07] bg-white/[.02] p-4"><div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><label class="flex min-w-0 items-start gap-3"><input type="checkbox" class="mt-1 h-4 w-4" data-update-component="${escapeHtml(item.component)}" ${ready ? "" : "disabled"}><span><span class="block text-sm font-normal text-slate-200">${escapeHtml(item.component)} · ${escapeHtml(item.version)}</span><span class="mt-1 block break-all text-xs leading-5 text-slate-500">${archive ? (stagedItem ? `Verified archive staged · ${escapeHtml(stagedItem.sha256)}` : `Signed archive · ${bytes(delivery.size_bytes || 0)}`) : `Distribution packages · ${escapeHtml(packages || "manifest allowlist")}`}</span></span></label>${archive && !stagedItem ? `<button type="button" class="btn-secondary shrink-0" data-stage-update="${escapeHtml(item.component)}">Verify &amp; stage</button>` : '<span class="badge shrink-0 border-emerald-300/20 text-emerald-200">Ready to select</span>'}</div></div>`;
    }).join("") : '<div class="rounded-xl border border-dashed border-white/10 p-6 text-center text-sm text-slate-500">Run a signed release check to see available components.</div>';
    $("#updates-approval")?.classList.toggle("hidden", components.length === 0);
    if ($("#updates-maintenance")) $("#updates-maintenance").checked = false;
    const rollback = update.rollback_point || null;
    $("#updates-rollback")?.classList.toggle("hidden", !rollback);
    setText("#updates-rollback-from", rollback?.release || "—");
    setText("#updates-rollback-to", rollback?.previous_release || "—");
    setText("#updates-rollback-size", rollback ? bytes(rollback.snapshot_size_bytes) : "—");
    setText("#updates-rollback-id", rollback ? `Activation ${rollback.activation_id}` : "");
    if ($("#updates-rollback-maintenance")) $("#updates-rollback-maintenance").checked = false;
    setText("#updates-state", snapshot.last_queued_request_id ? `Latest approval request: ${snapshot.last_queued_request_id}` : release ? "No component is selected by default. Review and select only what you intend to update." : "Release checks verify an Ed25519 signature and SHA-256 digests before any component can be selected.");
    updateSelectionState();
    updateRollbackSelectionState();
  }

  async function loadUpdates() {
    try {
      renderUpdates(await api("/api/v1/updates"));
    } catch (error) {
      state.updates = null;
      $("#updates-rollback")?.classList.add("hidden");
      $("#approve-update")?.setAttribute("disabled", "");
      $("#approve-rollback")?.setAttribute("disabled", "");
      setText("#updates-state", error.message);
      toast(error.message, "error", error.requestId);
    }
  }

  function settingBody(form) {
    const values = formObject(form);
    const section = form.dataset.settingsForm;
    const numeric = ["sample_interval_seconds", "metrics_retention_days", "cpu_overcommit_ratio", "memory_overcommit_ratio", "guest_agent_timeout_seconds", "min_free_disk_gb", "snapshot_retention", "mtu", "default_port_limit_mbps", "session_lifetime_minutes", "login_rate_limit", "api_rate_limit"];
    numeric.forEach((key) => { if (key in values && values[key] !== "") values[key] = finite(values[key]); });
    ["ntp_servers", "trusted_proxies", "admin_ip_allowlist", "dns_servers"].forEach((key) => { if (key in values) values[key] = splitLines(values[key]); });
    if ("default_traffic_quota_gb" in values) { values.default_traffic_quota_bytes = finite(values.default_traffic_quota_gb) > 0 ? finite(values.default_traffic_quota_gb) * GiB : null; delete values.default_traffic_quota_gb; }
    return { [section]: values };
  }

  async function initSettings() {
    $$('[data-settings-tab]').forEach((button) => button.addEventListener("click", () => showSettingsTab(button.dataset.settingsTab)));
    $$('[data-settings-form]').forEach((form) => {
      form.addEventListener("input", () => { form.dataset.dirty = "true"; });
      if (form.id === "account-form") return;
      form.addEventListener("submit", async (event) => { event.preventDefault(); const submit = $("button[type='submit']", form); submit.disabled = true; try { await api("/api/v1/settings", { method: "PATCH", body: settingBody(form) }); form.dataset.dirty = "false"; toast("Settings saved", "success"); setLiveState("live", "Saved"); } catch (error) { toast(error.message, "error", error.requestId); } finally { submit.disabled = false; } });
    });
    $("#account-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const values = formObject(form); if (values.new_password && values.new_password !== values.confirm_password) { toast("New passwords do not match", "error"); return; } try { await apiFirst(["/api/v1/admin/credentials", "/api/v1/settings/credentials", "/api/v1/auth/credentials"], { method: "PUT", body: { username: values.username || null, current_password: values.current_password, new_password: values.new_password || null } }); form.reset(); form.elements.username.value = values.username; toast("Administrator account updated; please sign in again", "success"); window.setTimeout(() => location.assign("/login"), 1000); } catch (error) { toast(error.message, "error", error.requestId); } });
    $$('[data-open-admin-dialog]').forEach((button) => button.addEventListener("click", () => $("#admin-dialog")?.showModal()));
    $$('[data-close-admin-dialog]').forEach((button) => button.addEventListener("click", () => $("#admin-dialog")?.close()));
    $$('[data-close-admin-password-dialog]').forEach((button) => button.addEventListener("click", () => $("#admin-password-dialog")?.close()));
    $("#admin-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return; const values = formObject(form); const errorBox = $("#admin-error"); errorBox?.classList.add("hidden"); if (values.password !== values.confirm_password) { if (errorBox) { errorBox.textContent = "Passwords do not match"; errorBox.classList.remove("hidden"); } return; } const useRoleDefaults = Boolean(form.elements.use_role_defaults?.checked); const permissions = $$('[data-admin-create-permissions] [data-admin-permission]:checked', form).map((input) => input.value); const submit = $("button[type='submit']", form); submit.disabled = true; try { await api("/api/v1/admins", { method: "POST", body: { username: values.username, password: values.password, role: values.role, use_role_defaults: useRoleDefaults, permissions: useRoleDefaults ? null : permissions } }); form.reset(); $("#admin-dialog")?.close(); toast("Administrator created", "success"); await loadAdmins(); } catch (error) { if (errorBox) { errorBox.textContent = `${error.message}${error.requestId ? ` · ${error.requestId}` : ""}`; errorBox.classList.remove("hidden"); } } finally { submit.disabled = false; } });
    $("#admin-password-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return; const values = formObject(form); const errorBox = $("#admin-password-error"); errorBox?.classList.add("hidden"); if (values.password !== values.confirm_password) { if (errorBox) { errorBox.textContent = "Passwords do not match"; errorBox.classList.remove("hidden"); } return; } const submit = $("button[type='submit']", form); submit.disabled = true; try { await api(`/api/v1/admins/${encodeURIComponent(values.admin_id)}/credentials`, { method: "PUT", body: { username: null, password: values.password } }); form.reset(); $("#admin-password-dialog")?.close(); toast("Password changed and existing sessions revoked", "success"); await loadAdmins(); } catch (error) { if (errorBox) { errorBox.textContent = `${error.message}${error.requestId ? ` · ${error.requestId}` : ""}`; errorBox.classList.remove("hidden"); } } finally { submit.disabled = false; } });
    $$('[data-open-api-key-dialog]').forEach((button) => button.addEventListener("click", () => $("#api-key-dialog")?.showModal())); $$('[data-close-api-key-dialog]').forEach((button) => button.addEventListener("click", () => $("#api-key-dialog")?.close()));
    $("#api-key-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return; const values = formObject(form); const errorBox = $("#api-key-error"); errorBox?.classList.add("hidden"); try { const response = await api("/api/v1/api-keys", { method: "POST", body: { name: values.name, permissions: asArray(values.scopes), expires_at: unixSeconds(values.expires_at), ip_allowlist: splitLines(values.ip_allowlist) } }); const secret = response?.data?.token || response?.data?.key || response?.data?.secret || response?.key || response?.token || response?.secret; if (!secret) throw new ApiError("The API key was created but its one-time secret was not returned."); $("#api-key-dialog")?.close(); form.reset(); setText("#api-key-secret", secret); $("#api-key-secret-dialog")?.showModal(); await loadApiKeys(); } catch (error) { if (errorBox) { errorBox.textContent = `${error.message}${error.requestId ? ` · ${error.requestId}` : ""}`; errorBox.classList.remove("hidden"); } } });
    $("[data-copy-api-key]")?.addEventListener("click", () => copyText($("#api-key-secret")?.textContent || "", "API key copied"));
    $("[data-close-api-key-secret]")?.addEventListener("click", () => { setText("#api-key-secret", ""); $("#api-key-secret-dialog")?.close(); });
    $("#save-host-network-security")?.addEventListener("click", async () => { const ownershipToggle = $("#ip-ownership-guard-enabled"); const bcp38Toggle = $("#bcp38-enabled"); const ownershipEnabled = Boolean(ownershipToggle?.checked); const bcp38Enabled = Boolean(bcp38Toggle?.checked); if (!ownershipEnabled && ownershipToggle?.dataset.original === "true") { const approved = await confirmAction({ title: "Disable managed IP ownership protection?", message: "Guests could claim free, reserved, host-owned, or another VM's address from a managed subnet by changing their in-guest network configuration. Disable only when an equivalent upstream filter is already enforced.", confirmLabel: "Disable protection" }); if (!approved) { ownershipToggle.checked = true; return; } } if (bcp38Enabled && bcp38Toggle?.dataset.original !== "true") { const approved = await confirmAction({ title: "Enable full hypervisor BCP38 filtering?", message: "Guest packets with any source address not assigned in Vexa-VM will be dropped. This is host-only and adds broader packet-filtering cost than the managed-pool ownership guard.", confirmLabel: "Enable BCP38" }); if (!approved) { bcp38Toggle.checked = false; return; } } try { await api("/api/v1/network/security", { method: "PATCH", body: { ip_ownership_guard_enabled: ownershipEnabled, bcp38_enabled: bcp38Enabled } }); toast("Host network-security policy applied", "success"); await loadSettings(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#check-updates")?.addEventListener("click", async (event) => { const button = event.currentTarget; button.disabled = true; setText("#updates-state", "Fetching and verifying the signed release manifest…"); try { await api("/api/v1/updates/check", { method: "POST" }); toast("Signed release verified", "success"); await loadUpdates(); } catch (error) { setText("#updates-state", error.message); toast(error.message, "error", error.requestId); } finally { button.disabled = false; } });
    $("#updates-maintenance")?.addEventListener("change", updateSelectionState);
    $("#updates-rollback-maintenance")?.addEventListener("change", updateRollbackSelectionState);
    $("#updates-components")?.addEventListener("change", (event) => { if (event.target.matches("[data-update-component]")) updateSelectionState(); });
    $("#updates-components")?.addEventListener("click", async (event) => { const button = event.target.closest("[data-stage-update]"); if (!button) return; const release = state.updates?.state?.release; if (!release) return; button.disabled = true; button.textContent = "Staging…"; try { await api("/api/v1/updates/stage", { method: "POST", body: { component: button.dataset.stageUpdate, manifest_sha256: release.manifest_sha256 } }); toast("Verified component staged", "success"); await loadUpdates(); } catch (error) { toast(error.message, "error", error.requestId); button.disabled = false; button.textContent = "Verify & stage"; } });
    $("#approve-update")?.addEventListener("click", async () => { const release = state.updates?.state?.release; const components = $$('[data-update-component]:checked').map((input) => input.dataset.updateComponent); if (!release || !components.length || !$("#updates-maintenance")?.checked) return; const approved = await confirmAction({ title: `Install ${release.tag}?`, message: `Selected components: ${components.join(", ")}. The signed request expires after 15 minutes and the privileged executor will health-check and roll back the application on failure.`, confirmLabel: "Approve update" }); if (!approved) return; try { const response = await api("/api/v1/updates/approve", { method: "POST", body: { expected_release: release.tag, expected_manifest_sha256: release.manifest_sha256, components, maintenance_impact_accepted: true } }); const request = response?.data?.request || response?.request || {}; toast("Signed update request approved", "success"); setText("#updates-state", `Activation request ${request.request_id || "queued"} was accepted by the privileged executor.`); await loadUpdates(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#approve-rollback")?.addEventListener("click", async () => { const rollback = state.updates?.rollback_point; const button = $("#approve-rollback"); if (!rollback || !$("#updates-rollback-maintenance")?.checked || !button) return; const approved = await confirmAction({ title: `Restore ${rollback.previous_release}?`, message: `This queues a privileged rollback from ${rollback.release} to ${rollback.previous_release}. Management access may restart; the executor will independently verify the root-owned snapshot before restoring it.`, confirmLabel: "Approve rollback" }); if (!approved) return; button.disabled = true; try { const response = await api("/api/v1/updates/rollback", { method: "POST", body: { expected_activation_id: rollback.activation_id, expected_previous_release: rollback.previous_release, maintenance_impact_accepted: true } }); const request = response?.data?.request || response?.request || {}; state.updates.rollback_point = null; $("#updates-rollback")?.classList.add("hidden"); toast("Application rollback approved", "success"); setText("#updates-state", `Rollback request ${request.request_id || "queued"} was accepted by the privileged executor.`); } catch (error) { toast(error.message, "error", error.requestId); updateRollbackSelectionState(); } });
    document.addEventListener("click", async (event) => {
      const apiKeyButton = event.target.closest("[data-revoke-api-key]");
      if (apiKeyButton) { const approved = await confirmAction({ title: "Revoke API key?", message: "Automation using this key will immediately lose access.", confirmLabel: "Revoke key" }); if (!approved) return; try { await api(`/api/v1/api-keys/${encodeURIComponent(apiKeyButton.dataset.revokeApiKey)}`, { method: "DELETE" }); toast("API key revoked", "success"); await loadApiKeys(); } catch (error) { toast(error.message, "error", error.requestId); } return; }
      const row = event.target.closest("[data-admin-row]"); if (!row) return;
      const id = row.dataset.adminRow;
      if (event.target.closest("[data-save-admin]")) { const button = event.target.closest("[data-save-admin]"); const role = $("[data-admin-role]", row)?.value; const useRoleDefaults = role === "super_admin" || Boolean($("[data-admin-role-defaults]", row)?.checked); const permissions = $$('[data-admin-permission]:checked', row).map((input) => input.value); button.disabled = true; try { await api(`/api/v1/admins/${encodeURIComponent(id)}`, { method: "PATCH", body: { role, enabled: Boolean($("[data-admin-enabled]", row)?.checked), use_role_defaults: useRoleDefaults, permissions: useRoleDefaults ? null : permissions } }); toast("Administrator access updated", "success"); await loadAdmins(); } catch (error) { toast(error.message, "error", error.requestId); button.disabled = false; } return; }
      const passwordButton = event.target.closest("[data-reset-admin-password]"); if (passwordButton) { const form = $("#admin-password-form"); form?.reset(); if (form) form.elements.admin_id.value = id; setText("#admin-password-target", `Set a new password for ${passwordButton.dataset.adminName}. Every active session for this account will be revoked.`); $("#admin-password-error")?.classList.add("hidden"); $("#admin-password-dialog")?.showModal(); return; }
      const deleteButton = event.target.closest("[data-delete-admin]"); if (deleteButton) { const approved = await confirmAction({ title: `Delete ${deleteButton.dataset.adminName}?`, message: "The account and all of its panel sessions will be permanently removed. Audit records are retained.", confirmLabel: "Delete administrator" }); if (!approved) return; deleteButton.disabled = true; try { await api(`/api/v1/admins/${encodeURIComponent(id)}`, { method: "DELETE" }); toast("Administrator deleted", "success"); await loadAdmins(); } catch (error) { toast(error.message, "error", error.requestId); deleteButton.disabled = false; } }
    });
    document.addEventListener("change", (event) => {
      const createForm = event.target.closest("#admin-form");
      if (createForm && (event.target.matches("[name='use_role_defaults']") || event.target.matches("[name='role']"))) {
        const superAdmin = createForm.elements.role?.value === "super_admin";
        if (superAdmin) createForm.elements.use_role_defaults.checked = true;
        const disabled = superAdmin || Boolean(createForm.elements.use_role_defaults?.checked);
        $$('[data-admin-create-permissions] [data-admin-permission]', createForm).forEach((input) => { input.disabled = disabled; });
        $("[data-admin-create-permissions]", createForm)?.classList.toggle("opacity-40", disabled);
        return;
      }
      const row = event.target.closest("[data-admin-row]");
      if (!row || !(event.target.matches("[data-admin-role-defaults]") || event.target.matches("[data-admin-role]"))) return;
      const superAdmin = $("[data-admin-role]", row)?.value === "super_admin";
      const defaults = $("[data-admin-role-defaults]", row);
      if (defaults && superAdmin) defaults.checked = true;
      const disabled = superAdmin || Boolean(defaults?.checked);
      $$('[data-admin-permission]', row).forEach((input) => { input.disabled = disabled; });
      $("[data-admin-permissions]", row)?.classList.toggle("opacity-40", disabled);
    });
    window.addEventListener("beforeunload", (event) => { if ($$('[data-settings-form]').some((form) => form.dataset.dirty === "true")) { event.preventDefault(); event.returnValue = ""; } });
    await loadSettings();
    const initial = location.hash.slice(1); showSettingsTab(["general", "virtualization", "storage", "network", "console", "security", "updates", "api"].includes(initial) ? initial : "general");
  }

  function initDocs() {
    $("#docs-search")?.addEventListener("input", (event) => {
      const query = event.target.value.trim().toLowerCase(); let visible = 0;
      $$('[data-doc-section]').forEach((section) => { const match = !query || section.textContent.toLowerCase().includes(query); section.classList.toggle("hidden", !match); if (match) visible += 1; });
      $("#docs-no-results")?.classList.toggle("hidden", visible > 0);
    });
    $$('[data-copy-code]').forEach((button) => button.addEventListener("click", () => { const container = button.closest("div")?.parentElement || button.parentElement; const code = $("code", container); if (code) copyText(code.textContent, "Example copied"); }));
    const anchors = $$('#docs-content section[id]');
    if ("IntersectionObserver" in window) {
      const observer = new IntersectionObserver((entries) => { const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]; if (!visible) return; $$('nav a[href^="#"]').forEach((link) => { const active = link.hash === `#${visible.target.id}`; link.classList.toggle("bg-white/[.05]", active); link.classList.toggle("text-white", active); }); }, { rootMargin: "-20% 0px -65%", threshold: [0, .25, .5] });
      anchors.forEach((section) => observer.observe(section));
    }
  }

  function publicToken(kind) {
    const parts = location.pathname.split("/").filter(Boolean);
    return parts[0] === kind && parts[1] && parts[1] !== "session" ? decodeURIComponent(parts.slice(1).join("/")) : "";
  }

  async function exchangePublicToken(kind) {
    const token = publicToken(kind);
    if (!token) return null;
    const response = await apiFirst(["/api/public/session/exchange", "/api/public/session", "/api/public/token/exchange", "/api/public/v1/session"], { method: "POST", body: { token } });
    history.replaceState(null, "", `/${kind}/session`);
    return response?.data || response;
  }

  function publicMetrics(vm) {
    return vm.metrics || vm.usage || {};
  }

  function renderPublicVm(raw) {
    const vm = normalizeVm(raw);
    state.publicVm = vm;
    document.title = `${vm.name} status · Vexa VM`;
    setText("#public-vm-name", vm.name);
    const badge = $("#public-vm-state"); if (badge) badge.outerHTML = statusBadge(vm.state).replace("<span ", '<span id="public-vm-state" ');
    setText("#public-vm-summary", `${vm.osName}${vm.osVersion ? ` ${vm.osVersion}` : ""} · ${vm.hostname}${raw.uptime_seconds ? ` · uptime ${formatDuration(raw.uptime_seconds)}` : ""}`);
    const maintenance = raw.maintenance || {};
    const maintenanceEnabled = maintenance.enabled === true;
    $("#public-maintenance-banner")?.classList.toggle("hidden", !maintenanceEnabled);
    setText("#public-maintenance-reason", maintenance.reason || "Changes are temporarily unavailable.");
    const guestTools = raw.guest_tools || {};
    setText("#public-guest-tools-status", !guestTools.enabled ? "Live guest changes are unavailable; saved values apply during a compatible reinstall." : guestTools.connected ? "Vexa Guest Tools is connected; supported changes apply immediately." : guestTools.status === "pending" ? "Vexa Guest Tools installation is pending the next guest boot." : "Vexa Guest Tools is installed but not currently reachable; saved values remain pending.");
    const isRunning = statusInfo(vm.state).key === "running";
    $$('[data-public-power="start"]').forEach((button) => button.classList.toggle("hidden", isRunning));
    $$('[data-public-power="shutdown"]').forEach((button) => button.classList.toggle("hidden", !isRunning));
    const allowed = vm.allowedActions;
    const hasScope = (...scopes) => allowed.includes("*") || scopes.some((scope) => allowed.includes(scope));
    const canFirewallRead = hasScope("firewall:read", "firewall:write", "vm:firewall", "firewall");
    const canFirewallWrite = hasScope("firewall:write", "vm:firewall", "firewall");
    $("#public-firewall-panel")?.classList.toggle("hidden", !canFirewallRead);
    state.publicFirewallAllowed = canFirewallRead;
    state.publicFirewallWritable = canFirewallWrite && !maintenanceEnabled;
    const canPower = hasScope("vm:power", "power:write", "power");
    $$('[data-public-power]').forEach((button) => { const stateAllows = button.dataset.publicPower === "start" ? !isRunning : isRunning; button.classList.toggle("hidden", !canPower || !stateAllows); button.toggleAttribute("disabled", maintenanceEnabled); });
    const canReinstall = hasScope("vm:reinstall", "reinstall:write", "reinstall");
    $$('[data-public-reinstall]').forEach((button) => { button.classList.toggle("hidden", !canReinstall); button.toggleAttribute("disabled", maintenanceEnabled); });
    const canConsole = hasScope("vm:vnc", "console:write", "vnc", "console");
    $$('[data-public-console]').forEach((button) => button.classList.toggle("hidden", !canConsole));
    const canDns = hasScope("vm:dns", "dns:write", "dns");
    const dnsWritable = canDns && !maintenanceEnabled;
    $("#public-dns-form")?.classList.toggle("opacity-60", !dnsWritable);
    $$("#public-dns-form textarea, #public-dns-form button").forEach((control) => { control.disabled = !dnsWritable; });
    $("[data-public-reveal-secret]")?.toggleAttribute("disabled", !hasScope("vm:password:read", "password:read", "password"));
    const canChangePassword = hasScope("vm:password:write", "password:write", "password");
    $$('[data-public-reset-password]').forEach((button) => { button.classList.toggle("hidden", !canChangePassword); button.toggleAttribute("disabled", maintenanceEnabled); });
    const canManageSsh = hasScope("ssh:write", "ssh_keys");
    $$('[data-public-ssh-keys]').forEach((button) => { button.classList.toggle("hidden", !canManageSsh); button.toggleAttribute("disabled", maintenanceEnabled); });
    [$("#public-firewall-profile-form"), $("#public-firewall-rule-form")].filter(Boolean).forEach((form) => {
      form.classList.toggle("opacity-60", !state.publicFirewallWritable);
      $$("input, select, button", form).forEach((control) => { control.disabled = !state.publicFirewallWritable; });
    });
    setText("#public-firewall-permission-state", state.publicFirewallWritable ? "You can enable, disable and remove your customer-owned rules." : maintenanceEnabled ? "Read-only while provider maintenance is active." : "This link has read-only firewall access.");
    setText("#public-cpu", percent(vm.cpuPct, 1)); setProgress("#public-cpu-bar", vm.cpuPct); setText("#public-cpu-detail", `${vm.cpu} allocated vCPU`);
    setText("#public-ram", percent(vm.ramPct, 1)); setProgress("#public-ram-bar", vm.ramPct); setText("#public-ram-detail", `${bytes(vm.ramUsed)} of ${bytes(vm.ramTotal)}`);
    setText("#public-network", bitsPerSecond((vm.rxBps + vm.txBps) * 8)); setText("#public-network-detail", `↓ ${byteRate(vm.rxBps)} · ↑ ${byteRate(vm.txBps)} · ${vm.portMbps || "—"} Mbit/s maximum`);
    setText("#public-traffic", vm.trafficBlocked ? "Blocked" : (vm.trafficLimit ? percent(vm.trafficPct, 1) : "Unlimited")); setProgress("#public-traffic-bar", vm.trafficPct || 0); setText("#public-traffic-detail", vm.trafficBlocked ? `${bytes(vm.trafficUsed)} used · network disabled` : (vm.trafficLimit ? `${bytes(vm.trafficUsed)} of ${bytes(vm.trafficLimit)}` : `${bytes(vm.trafficUsed)} transferred`));
    setText("#public-metrics-updated", raw.metrics_updated_at ? `Updated ${relativeTime(raw.metrics_updated_at)}` : "Live");
    const samples = asArray(raw.metrics?.samples || raw.metric_samples || raw.samples || raw.history);
    renderChart($("#public-performance-chart"), [{ label: "CPU %", values: samples.map((item) => item.cpu_pct ?? item.cpu_percent) }, { label: "RAM %", values: samples.map((item) => item.ram_pct ?? item.memory_pct ?? (finite(item.memory_total_bytes) ? finite(item.memory_used_bytes) * 100 / finite(item.memory_total_bytes) : 0)), color: "#aa55f7" }], { label: `${vm.name} usage`, max: 100, formatY: (value) => `${Math.round(value)}%` });
    const plan = [["Operating system", vm.osName], ["vCPU", vm.cpu], ["Memory", bytes(vm.ramTotal)], ["Disk", bytes(vm.diskTotal, 0)], ["Port speed", vm.portMbps ? `${vm.portMbps} Mbit/s` : "Uncapped"], ["Traffic", vm.trafficLimit ? bytes(vm.trafficLimit) : "Unlimited"]];
    const planTarget = $("#public-plan"); if (planTarget) planTarget.innerHTML = plan.map(([label, value]) => `<div class="flex justify-between gap-4 py-3"><dt class="text-sm text-slate-500">${escapeHtml(label)}</dt><dd class="text-right text-sm font-normal text-slate-200">${escapeHtml(value)}</dd></div>`).join("");
    const addresses = [...vm.publicV4.map((address) => ({ address, type: "Public IPv4" })), ...vm.publicV6.map((address) => ({ address, type: "Public IPv6" })), ...vm.privateV4.map((address) => ({ address, type: "Private IPv4" })), ...vm.privateV6.map((address) => ({ address, type: "Private IPv6" }))];
    const addressTarget = $("#public-addresses"); if (addressTarget) addressTarget.innerHTML = addresses.length ? addresses.map((item) => `<div class="flex items-center justify-between gap-3 rounded-xl border border-white/[.07] bg-white/[.025] p-3"><div class="min-w-0"><p class="text-[10px] uppercase tracking-wider text-slate-600">${escapeHtml(item.type)}</p><p class="mt-1 overflow-x-auto font-mono text-sm text-orbit-300">${escapeHtml(item.address)}</p></div><button type="button" class="btn-secondary shrink-0 px-3 py-2" data-copy="${escapeHtml(item.address)}">Copy</button></div>`).join("") : '<p class="text-sm text-slate-500">No addresses are assigned.</p>';
    const netFacts = [["Gateway", raw.gateway || raw.gateway_ip || "—"], ["MAC address", raw.mac_address || raw.mac || "—"]]; const netTarget = $("#public-network-facts"); if (netTarget) netTarget.innerHTML = netFacts.map(([label, value]) => `<div><dt class="text-xs text-slate-600">${escapeHtml(label)}</dt><dd class="mt-1 overflow-x-auto font-mono text-sm text-slate-300">${escapeHtml(value)}</dd></div>`).join("");
    fillForm($("#public-dns-form"), { dns_servers: vm.dns });
    const activity = asArray(raw.activity || raw.operations);
    const activityTarget = $("#public-activity"); if (activityTarget) activityTarget.innerHTML = activity.length ? activity.map((item) => `<li class="flex gap-3 py-4"><span class="mt-1 h-2 w-2 shrink-0 rounded-full ${item.status === "failed" ? "bg-rose-300" : item.status === "running" ? "bg-orbit-300" : "bg-nebula-300"}"></span><div class="min-w-0 flex-1"><p class="text-sm font-normal text-slate-300">${escapeHtml(item.title || item.kind || item.action)}</p><p class="mt-1 text-xs text-slate-600">${escapeHtml(item.message || item.status || "")}</p></div><time class="shrink-0 text-xs text-slate-600">${escapeHtml(relativeTime(item.created_at))}</time></li>`).join("") : '<li class="py-4 text-sm text-slate-500">No recent operations.</li>';
    $$('[data-copy]').forEach((button) => button.addEventListener("click", () => copyText(button.dataset.copy, "Address copied")));
  }

  function renderPublicFirewall(payload = {}) {
    const profile = payload.profile || payload.data?.profile || {};
    const rules = asArray(payload.rules || payload.data?.rules);
    fillForm($("#public-firewall-profile-form"), { firewall_enabled: profile.firewall_enabled === true, ddos_enabled: profile.ddos_enabled === true });
    const target = $("#public-firewall-rules");
    if (!target) return;
    target.innerHTML = rules.length ? rules.map((rule) => {
      const ports = asArray(rule.destination_ports).map((range) => Number(range.start) === Number(range.end) ? range.start : `${range.start}-${range.end}`).join(", ") || "all ports";
      const actions = state.publicFirewallWritable ? `<div class="flex shrink-0 gap-2"><button type="button" class="btn-secondary px-3 py-2" data-public-firewall-toggle="${escapeHtml(rule.id)}" data-enabled="${rule.enabled ? "true" : "false"}">${rule.enabled ? "Disable" : "Enable"}</button><button type="button" class="btn-danger px-3 py-2" data-public-firewall-delete="${escapeHtml(rule.id)}">Delete</button></div>` : '<span class="text-xs text-slate-600">Read only</span>';
      return `<div class="flex items-center justify-between gap-3 py-3"><div class="min-w-0"><p class="text-sm text-slate-200">${escapeHtml(rule.action)} ${escapeHtml(rule.protocol)} · ${escapeHtml(ports)}</p><p class="mt-1 text-xs text-slate-500">${rule.enabled ? "Enabled" : "Off"} · ${escapeHtml(rule.description || "Customer rule")}</p></div>${actions}</div>`;
    }).join("") : '<p class="py-3 text-sm text-slate-500">No rules configured.</p>';
  }

  async function loadPublicFirewall() {
    if (!state.publicFirewallAllowed) return;
    const payload = await apiFirst(["/api/public/vm/firewall"]);
    renderPublicFirewall(payload?.data || payload);
  }

  function formatDuration(seconds) {
    const value = Math.max(0, finite(seconds)); const days = Math.floor(value / 86400); const hours = Math.floor((value % 86400) / 3600); const minutes = Math.floor((value % 3600) / 60);
    return `${days ? `${days}d ` : ""}${hours ? `${hours}h ` : ""}${minutes}m`.trim();
  }

  async function loadPublicVm() {
    if (state.publicVmLoading) return;
    state.publicVmLoading = true;
    try {
      const [vmResult, metricsResult] = await Promise.allSettled([
        apiFirst(["/api/public/vm", "/api/public/v1/vm"]),
        apiFirst(["/api/public/vm/metrics?range=24h", "/api/public/v1/vm/metrics?range=24h"]),
      ]);
      if (vmResult.status === "rejected") throw vmResult.reason;
      const payload = vmResult.value;
      const vm = payload?.data || payload?.vm || payload;
      const metricPayload = metricsResult.status === "fulfilled" ? (metricsResult.value?.data || metricsResult.value) : {};
      const metricItems = asArray(metricPayload.items || metricPayload.samples || vm.metric_samples);
      const latest = metricItems.at(-1) || metricPayload.metrics || vm.metrics || metricPayload;
      renderPublicVm({ ...vm, metrics: { ...latest, samples: metricItems }, metrics_updated_at: latest.sampled_at || metricPayload.sampled_at });
      await loadPublicFirewall();
      $("#status-loading")?.classList.add("hidden"); $("#status-error")?.classList.add("hidden"); $("#status-content")?.classList.remove("hidden");
    } finally {
      state.publicVmLoading = false;
    }
  }

  async function publicPower(action) {
    const impact = ["hard-stop", "reset"].includes(action);
    if (["shutdown", "hard-stop", "reset"].includes(action)) { const approved = await confirmAction({ title: action === "shutdown" ? "Shut down server?" : action === "hard-stop" ? "Force stop server?" : "Hard reboot server?", message: impact ? "Unsaved data inside the guest may be lost." : "The operating system receives a graceful shutdown request.", confirmLabel: "Continue", danger: impact }); if (!approved) return; }
    const apiAction = action === "hard-stop" ? "force-off" : action;
    try { const response = await apiFirst([`/api/public/actions/${encodeURIComponent(apiAction)}`, `/api/public/vm/actions/${encodeURIComponent(apiAction)}`, `/api/public/v1/power`], { method: "POST", body: { action: apiAction } }); toast(`${action} requested`, "success"); showPublicOperation(response); await followPublicOperation(response); await loadPublicVm(); } catch (error) { toast(error.message, "error", error.requestId); }
  }

  function showPublicOperation(payload) {
    const operation = payload?.data?.operation || payload?.operation || payload;
    const progress = operation.progress ?? operation.progress_percent;
    const panel = $("#public-operation"); panel?.classList.remove("hidden"); setText("#public-operation-title", operation.kind || operation.title || "Operation in progress"); setText("#public-operation-message", operation.message || operation.status || "Accepted"); setText("#public-operation-percent", `${Math.round(finite(progress))}%`); setProgress("#public-operation-bar", progress ?? 5);
  }

  async function followPublicOperation(payload) {
    const directOperation = payload?.id && (payload?.status || payload?.kind) ? payload : null;
    const operation = payload?.data?.operation || payload?.operation || directOperation;
    if (!operation?.id) return;
    if (["succeeded", "failed", "cancelled"].includes(operation.status)) {
      const terminalError = operationTerminalError(operation);
      if (terminalError) throw terminalError;
      return;
    }
    for (let attempt = 0; attempt < 120; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      try {
        const result = await apiFirst([`/api/public/jobs/${encodeURIComponent(operation.id)}`, `/api/public/v1/operations/${encodeURIComponent(operation.id)}`]);
        const current = result?.data || result?.operation || result;
        showPublicOperation(current);
        if (["succeeded", "failed", "cancelled"].includes(current.status)) {
          const terminalError = operationTerminalError(current);
          if (terminalError) throw terminalError;
          return;
        }
      } catch (error) {
        if (![404, 405].includes(error.status)) throw error;
        throw new ApiError(
          "Operation status is no longer available. Refresh the status page before retrying the action.",
          error.status,
          "operation_status_unavailable",
          error.requestId,
        );
      }
    }
    throw new ApiError("The operation is still running. Refresh the status page to check its progress.", 408, "operation_timeout");
  }

  function openPublicAction(mode) {
    const dialog = $("#public-action-dialog"); const form = $("#public-action-form"); const fields = $("#public-action-fields"); if (!dialog || !form || !fields) return; form.dataset.action = mode;
    if (mode === "password") { setText("#public-action-title", "Change server password"); setText("#public-action-description", state.publicVm?.guest_tools?.connected ? "Vexa Guest Tools will apply the encrypted password inside the running server." : "The encrypted password is saved now and will apply on the next compatible reinstall if Guest Tools is unavailable."); fields.innerHTML = `<label><span class="label">New password</span><input name="password" type="password" minlength="12" class="field" autocomplete="new-password" required></label>`; }
    else if (mode === "reinstall") { setText("#public-action-title", `Reinstall ${state.publicVm?.name || "server"}`); setText("#public-action-description", "This permanently replaces the system disk. Your resource limits and IP assignments stay unchanged."); fields.innerHTML = `<div class="space-y-4"><label><span class="label">Operating system</span><select name="image_id" class="field" required><option value="">Select an image…</option></select></label><label data-reinstall-password><span class="label">New administrator password</span><input name="password" type="password" minlength="12" class="field" autocomplete="new-password" required></label><div class="hidden rounded-xl border border-amber-300/20 bg-amber-300/[.07] p-4 text-sm leading-6 text-amber-100" data-manual-password-notice>Manual installers set credentials interactively through VNC. The old stored password is removed only after the reinstall succeeds.</div><label><span class="label">Type ${escapeHtml(state.publicVm?.name || "server")} to confirm</span><input name="confirmation" class="field" required autocomplete="off"></label></div>`; const select = $("select[name='image_id']", fields); select?.addEventListener("change", () => updateReinstallPasswordMode(select, fields, true)); loadPublicImages(select).then(() => updateReinstallPasswordMode(select, fields, true)); }
    else if (mode === "ssh") { setText("#public-action-title", "Manage SSH keys"); setText("#public-action-description", state.publicVm?.guest_tools?.connected ? "One public key per line. Vexa Guest Tools will update its protected managed block now." : "One public key per line. Keys are saved and remain pending until Guest Tools reconnects or the next compatible reinstall."); fields.innerHTML = `<label><span class="label">SSH public keys</span><textarea name="ssh_keys" class="field min-h-40 resize-y font-mono text-xs"></textarea></label>`; }
    $("#public-action-error")?.classList.add("hidden"); dialog.showModal();
  }

  async function loadPublicImages(select) {
    try { const images = listPayload(await apiFirst(["/api/public/isos", "/api/public/images", "/api/public/v1/images"])).items.map(normalizeImage).filter(isReadyImage); if (select) select.insertAdjacentHTML("beforeend", images.map((image) => `<option value="${escapeHtml(image.id || image.slug)}" data-install-mode="${escapeHtml(imageMode(image))}" data-os-family="${escapeHtml(image.os_family || "")}">${escapeHtml(imageLabel(image))} · ${escapeHtml(imageMode(image))}</option>`).join("")); } catch (error) { toast(error.message, "error", error.requestId); }
  }

  async function initPublicStatus() {
    try { await exchangePublicToken("status"); await loadPublicVm(); $("#public-session-state")?.classList.add("flex"); }
    catch (error) { $("#status-loading")?.classList.add("hidden"); $("#status-error")?.classList.remove("hidden"); setText("#status-error-message", error.status === 410 ? "This link expired or was revoked. Ask your provider for a new link." : error.message); setText("#status-error-request", error.requestId ? `Request ${error.requestId}` : ""); return; }
    $$('[data-public-power]').forEach((button) => button.addEventListener("click", () => publicPower(button.dataset.publicPower)));
    $("[data-public-more]")?.addEventListener("click", () => $("#public-more-menu")?.classList.toggle("hidden"));
    $$('[data-public-console]').forEach((button) => button.addEventListener("click", async () => { try { const response = await apiFirst(["/api/public/vnc-token", "/api/public/vm/vnc-token", "/api/public/v1/vnc-link"], { method: "POST", body: {} }); const url = response?.data?.url || response?.url; if (!url) throw new ApiError("Console link was not returned."); window.open(url, "_blank", "noopener,noreferrer"); } catch (error) { toast(error.message, "error", error.requestId); } }));
    $("#public-dns-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); try { const response = await apiFirst(["/api/public/dns", "/api/public/vm/dns", "/api/public/v1/dns"], { method: "PUT", body: { dns_servers: splitLines(values.dns_servers) } }); toast(guestApplyMessage(response, "DNS configuration saved"), guestApplyKind(response)); await loadPublicVm(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#public-firewall-profile-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const values = formObject(event.currentTarget); try { await api("/api/public/vm/firewall", { method: "PUT", body: { firewall_enabled: Boolean(values.firewall_enabled), ddos_enabled: Boolean(values.ddos_enabled) } }); toast("Network protection updated", "success"); await loadPublicFirewall(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("#public-firewall-rule-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const values = formObject(form); try { await api("/api/public/vm/firewall/rules", { method: "POST", body: { priority: 1000, direction: "ingress", action: "drop", protocol: values.protocol, source_cidr: null, destination_cidr: null, source_ports: [], destination_ports: parsePortRanges(values.destination_ports), log: false, enabled: Boolean(values.enabled), description: "Customer port block" } }); form.reset(); toast("Port rule created", "success"); await loadPublicFirewall(); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("[data-public-reveal-secret]")?.addEventListener("click", async () => { try { const response = await apiFirst(["/api/public/password", "/api/public/vm/password", "/api/public/v1/password"]); const secret = response?.data?.password || response?.password; if (!secret) throw new ApiError("No default password is available."); revealSecret($("#public-secret"), $("#public-secret-timer"), secret); } catch (error) { toast(error.message, "error", error.requestId); } });
    $("[data-public-reset-password]")?.addEventListener("click", () => openPublicAction("password")); $("[data-public-reinstall]")?.addEventListener("click", () => openPublicAction("reinstall")); $("[data-public-ssh-keys]")?.addEventListener("click", () => openPublicAction("ssh"));
    $("[data-close-public-action]")?.addEventListener("click", () => $("#public-action-dialog")?.close());
    $("#public-action-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; const values = formObject(form); const mode = form.dataset.action; const errorBox = $("#public-action-error"); errorBox?.classList.add("hidden"); try { let response; if (mode === "password") response = await apiFirst(["/api/public/password", "/api/public/vm/password", "/api/public/v1/password"], { method: "PUT", body: { password: values.password } }); else if (mode === "reinstall") { if (values.confirmation !== state.publicVm.name) throw new ApiError("The server name does not match."); const password = String(values.password || "").trim(); response = await apiFirst(["/api/public/reinstall", "/api/public/vm/reinstall", "/api/public/v1/reinstall"], { method: "POST", headers: { "Idempotency-Key": randomUuid() }, body: { image_id: values.image_id, ...(password ? { password } : {}) } }); } else response = await apiFirst(["/api/public/ssh-keys", "/api/public/vm/ssh-keys", "/api/public/v1/ssh-keys"], { method: "PUT", body: { ssh_keys: splitLines(values.ssh_keys) } }); form.reset(); $("#public-action-dialog")?.close(); toast(mode === "reinstall" ? "Reinstall started" : guestApplyMessage(response, mode === "ssh" ? "SSH keys saved" : "Credential updated"), mode === "reinstall" ? "success" : guestApplyKind(response)); if (response?.operation || response?.data?.operation) { showPublicOperation(response); await followPublicOperation(response); } await loadPublicVm(); } catch (error) { if (errorBox) { errorBox.textContent = `${error.message}${error.requestId ? ` · Request ${error.requestId}` : ""}`; errorBox.classList.remove("hidden"); } } });
    $("[data-refresh-public]")?.addEventListener("click", loadPublicVm);
    document.addEventListener("click", async (event) => { const toggle = event.target.closest("[data-public-firewall-toggle]"); const remove = event.target.closest("[data-public-firewall-delete]"); if (!toggle && !remove) return; if (!state.publicFirewallWritable) return; const ruleId = toggle?.dataset.publicFirewallToggle || remove?.dataset.publicFirewallDelete; if (remove) { const approved = await confirmAction({ title: "Delete port block?", message: "Traffic to this port will no longer be blocked by this rule.", confirmLabel: "Delete rule" }); if (!approved) return; } try { if (toggle) await api(`/api/public/vm/firewall/rules/${encodeURIComponent(ruleId)}`, { method: "PATCH", body: { enabled: toggle.dataset.enabled !== "true" } }); else await api(`/api/public/vm/firewall/rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" }); toast(toggle ? "Firewall rule updated" : "Firewall rule deleted", "success"); await loadPublicFirewall(); } catch (error) { toast(error.message, "error", error.requestId); } });
    window.setInterval(() => { if (!document.hidden) loadPublicVm().catch(() => {}); }, 10000);
  }

  async function initVnc() {
    let session;
    try {
      session = await exchangePublicToken("vnc");
      if (!session?.websocket_url && !session?.ws_url) {
        const info = await apiFirst(["/api/public/vnc-session", "/api/public/vnc", "/api/public/v1/vnc"]);
        session = info?.data || info;
      }
    } catch (error) {
      vncOverlay("Console link unavailable", error.status === 410 ? "This console link expired or was revoked. Request a new link from the server status page." : error.message, false, error.requestId);
      setText("#vnc-status", "Unavailable");
      $("#vnc-status-dot")?.classList.replace("bg-amber-300", "bg-rose-300");
      return;
    }
    const websocketUrl = session?.websocket_url || session?.ws_url || session?.url;
    if (!websocketUrl) {
      vncOverlay("Console could not start", "The node did not return a WebSocket endpoint for this session.", false, session?.request_id);
      return;
    }
    setText("#vnc-title", session.vm_name ? `${session.vm_name} console` : "Secure console");
    let RFB;
    try { const module = await import("/static/vendor/novnc/core/rfb.js"); RFB = module.default; }
    catch { vncOverlay("Console client is missing", "The self-hosted noVNC client could not be loaded. Ask the administrator to rebuild static assets.", false); return; }
    let rfb = null;
    let fit = true;
    const screen = $("#vnc-screen");
    const connect = () => {
      try { rfb?.disconnect(); } catch { /* already disconnected */ }
      setText("#vnc-status", "Connecting…"); $("#vnc-status-dot")?.classList.remove("bg-rose-300", "bg-emerald-300"); $("#vnc-status-dot")?.classList.add("bg-amber-300");
      $("#vnc-overlay")?.classList.remove("hidden");
      rfb = new RFB(screen, websocketUrl, { credentials: { password: session.ticket || session.password || "" }, shared: false });
      rfb.scaleViewport = true; rfb.resizeSession = true; rfb.clipViewport = false; rfb.focusOnClick = true;
      rfb.addEventListener("connect", () => { setText("#vnc-status", "Connected"); $("#vnc-status-dot")?.classList.remove("bg-amber-300", "bg-rose-300"); $("#vnc-status-dot")?.classList.add("bg-emerald-300"); $("#vnc-overlay")?.classList.add("hidden"); screen?.focus(); });
      rfb.addEventListener("disconnect", (event) => { setText("#vnc-status", event.detail.clean ? "Disconnected" : "Connection lost"); $("#vnc-status-dot")?.classList.remove("bg-amber-300", "bg-emerald-300"); $("#vnc-status-dot")?.classList.add("bg-rose-300"); if (!event.detail.clean) vncOverlay("Connection lost", "The console connection ended unexpectedly. You can reconnect while this 10-minute session remains valid.", true); });
      rfb.addEventListener("securityfailure", (event) => vncOverlay("Console security error", event.detail.reason || "The console rejected this session.", false));
      rfb.addEventListener("credentialsrequired", () => vncOverlay("Console credentials required", "This VNC backend requested a credential that the session did not provide.", false));
    };
    $("[data-vnc-fit]")?.addEventListener("click", () => { fit = !fit; rfb.scaleViewport = fit; setText("[data-vnc-fit]", fit ? "Fit" : "1:1"); });
    $("[data-vnc-fullscreen]")?.addEventListener("click", async () => { try { if (!document.fullscreenElement) await document.documentElement.requestFullscreen(); else await document.exitFullscreen(); } catch { toast("Fullscreen is not available in this browser", "error"); } });
    $("[data-vnc-cad]")?.addEventListener("click", () => rfb?.sendCtrlAltDel());
    $("[data-vnc-reconnect]")?.addEventListener("click", connect);
    $("[data-vnc-disconnect]")?.addEventListener("click", () => { rfb?.disconnect(); vncOverlay("Console disconnected", "The VNC connection is closed. Reconnect before the session expires.", true); });
    $("#vnc-overlay-action")?.addEventListener("click", connect);
    const rawExpiry = session.expires_at || session.expiresAt; const expiry = rawExpiry ? (typeof rawExpiry === "number" ? (rawExpiry < 1e12 ? rawExpiry * 1000 : rawExpiry) : new Date(rawExpiry).getTime()) : Date.now() + 600_000;
    const tick = () => {
      const seconds = Math.max(0, Math.ceil((expiry - Date.now()) / 1000)); const minutes = String(Math.floor(seconds / 60)).padStart(2, "0"); const remainder = String(seconds % 60).padStart(2, "0"); setText("#vnc-countdown", `${minutes}:${remainder}`);
      if (seconds <= 60) $("#vnc-countdown")?.classList.add("border-rose-300/30", "text-rose-200");
      if (seconds <= 0) { window.clearInterval(timer); try { rfb?.disconnect(); } catch {} vncOverlay("Session expired", "Request a new console link from the server status page or your administrator.", false); setText("#vnc-status", "Expired"); }
    };
    const timer = window.setInterval(tick, 1000); tick(); connect();
  }

  function vncOverlay(title, message, canReconnect, requestId = "") {
    const overlay = $("#vnc-overlay"); overlay?.classList.remove("hidden"); setText("#vnc-overlay-title", title); setText("#vnc-overlay-message", message); setText("#vnc-request-id", requestId ? `Request ${requestId}` : ""); $("#vnc-overlay-action")?.classList.toggle("hidden", !canReconnect); const icon = $("#vnc-overlay-icon"); if (icon) icon.innerHTML = canReconnect ? "↻" : "!";
  }

  function initError() {
    const params = new URLSearchParams(location.search); const code = params.get("code"); const requestId = params.get("request_id");
    if (code) setText("#error-code", code.replaceAll("_", " ")); if (params.get("message")) setText("#error-message", params.get("message")); if (requestId) setText("#error-request-id", `Request ${requestId}`);
    $("[data-error-back]")?.addEventListener("click", () => history.back());
  }

  const initializers = {
    login: initLogin,
    overall: initOverall,
    vms: initVms,
    "vm-create": initVmCreate,
    "vm-detail": initVmDetail,
    network: initNetwork,
    isos: initImages,
    settings: initSettings,
    logs: initLogs,
    docs: initDocs,
    "public-status": initPublicStatus,
    "public-vnc": initVnc,
    error: initError,
  };

  document.addEventListener("DOMContentLoaded", async () => {
    initGlobalUi();
    try { await initializers[page]?.(); }
    catch (error) { console.error(error); toast(error?.message || "The page could not be initialized.", "error", error?.requestId); }
  });
})();
