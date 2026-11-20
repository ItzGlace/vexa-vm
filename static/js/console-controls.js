(function (root) {
  "use strict";
  function textKeys(text) {
    if (typeof text !== "string" || [...text].length > 2000) throw new Error("Send at most 2,000 characters at a time.");
    return [...text.replace(/\r\n/g, "\n")].map((char) => {
      const code = char.codePointAt(0);
      if (code === 10 || code === 13) return 0xff0d;
      if (code === 9) return 0xff09;
      if (code < 32 || code === 127) throw new Error("Text contains unsupported control characters.");
      return code <= 255 ? code : 0x01000000 | code;
    });
  }
  if (typeof module !== "undefined") module.exports = { textKeys };
  let rfb = null; let initialized = false; let remoteClipboard = ""; let busy = false; let pending = [];
  const byId = (id) => document.getElementById(id);
  const message = (text) => { byId("vnc-input-status").textContent = text; };
  async function type(text) {
    if (!rfb) { message("Connect to the console first."); return; }
    let keys;
    try { keys = textKeys(text); } catch (error) { message(error.message); return; }
    if (pending.length + keys.length > 4000) { message("Typing queue is full. Wait before sending more text."); return; }
    pending.push(...keys);
    if (busy) return;
    busy = true;
    const current = rfb;
    try {
      while (pending.length) {
        const key = pending.shift();
        if (current !== rfb || document.hidden) { pending = []; message("Typing stopped. Return to the console before sending more text."); return; }
        current.sendKey(key);
        await new Promise((resolve) => setTimeout(resolve, 12));
      }
      message("Text sent as keystrokes using the guest keyboard layout.");
    } finally { busy = false; }
  }
  root.VexaConsole = { attach(client) {
    rfb = client; pending = []; remoteClipboard = "";
    const received = byId("vnc-clipboard-received"); if (received) received.value = "";
    client.addEventListener("clipboard", (event) => {
      remoteClipboard = String(event.detail.text || "").slice(0, 65536);
      received.value = remoteClipboard; message("Guest clipboard received. Choose Copy to device to copy it.");
    });
    client.addEventListener("disconnect", () => { if (rfb === client) { rfb = null; pending = []; remoteClipboard = ""; received.value = ""; } });
    if (initialized) return; initialized = true;
    document.querySelector("[data-vnc-tools]").onclick = () => { byId("vnc-tools").hidden = !byId("vnc-tools").hidden; };
    document.querySelector("[data-vnc-paste]").onclick = async () => {
      try { byId("vnc-clipboard-send").value = (await navigator.clipboard.readText()).slice(0,65536); message("Device clipboard loaded. Choose Send clipboard or Type text."); }
      catch { message("Clipboard permission unavailable. Paste into the text box manually."); }
    };
    document.querySelector("[data-vnc-send-clipboard]").onclick = () => {
      const text = byId("vnc-clipboard-send").value;
      if (!rfb || text.length > 65536) { message("Connect first and use at most 64 KiB of clipboard text."); return; }
      rfb.clipboardPasteFrom(text); message("Clipboard offered to the guest. It requires a guest desktop clipboard agent; terminals/BIOS use Type text.");
    };
    document.querySelector("[data-vnc-type]").onclick = () => type(byId("vnc-clipboard-send").value);
    document.querySelector("[data-vnc-copy]").onclick = async () => {
      try { await navigator.clipboard.writeText(remoteClipboard); message("Guest clipboard copied to this device."); }
      catch { received.focus(); received.select(); message("Select and copy the received text manually."); }
    };
    document.querySelector("[data-vnc-mobile-keyboard]").onclick = () => { const input = byId("vnc-mobile-input"); input.hidden = !input.hidden; if (!input.hidden) input.focus(); };
    const mobile = byId("vnc-mobile-input");
    const flush = () => { if (!mobile.value) return; const value = mobile.value; mobile.value = ""; type(value); };
    mobile.addEventListener("input", (event) => { if (!event.isComposing) flush(); });
    mobile.addEventListener("compositionend", () => setTimeout(flush, 0));
    mobile.addEventListener("beforeinput", (event) => { if (event.inputType === "deleteContentBackward") { event.preventDefault(); rfb?.sendKey(0xff08); } });
    document.querySelectorAll("[data-vnc-key]").forEach((button) => { button.onclick = () => rfb?.sendKey(Number(button.dataset.vncKey)); });
    document.querySelector("[data-vnc-drag]").onclick = (event) => { if (rfb) { rfb.dragViewport = !rfb.dragViewport; event.currentTarget.setAttribute("aria-pressed", String(rfb.dragViewport)); message(rfb.dragViewport ? "Touch drag pans the view." : "Touch drag controls the remote pointer."); } };
    document.querySelectorAll("#vnc-tools textarea").forEach((input) => input.addEventListener("focus", () => rfb?.blur()));
  } };
})(typeof globalThis !== "undefined" ? globalThis : window);
