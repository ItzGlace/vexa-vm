/* Ed25519 generation stays on the user's device. No server request contains the private key. */
(function (root) {
  "use strict";
  const utf8 = (text) => new TextEncoder().encode(text);
  const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const part of parts) { out.set(part, at); at += part.length; } return out; };
  const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const str = (value) => concat(u32(value.length), value);
  const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const decode = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  async function generate() {
    if (!root.crypto?.subtle) throw new Error("Key generation requires HTTPS or localhost and a browser with Ed25519 support.");
    const pair = await root.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const jwk = await root.crypto.subtle.exportKey("jwk", pair.privateKey);
    const publicBytes = decode(jwk.x); const seed = decode(jwk.d);
    const publicBlob = concat(str(utf8("ssh-ed25519")), str(publicBytes));
    const check = root.crypto.getRandomValues(new Uint8Array(4));
    const inner = concat(check, check, str(utf8("ssh-ed25519")), str(publicBytes), str(concat(seed, publicBytes)), str(utf8("vexa")));
    const padding = Uint8Array.from({ length: 8 - inner.length % 8 }, (_, n) => n + 1);
    const blob = concat(utf8("openssh-key-v1\0"), str(utf8("none")), str(utf8("none")), str(new Uint8Array()), u32(1), str(publicBlob), str(concat(inner, padding)));
    const encoded = b64(blob).match(/.{1,70}/g).join("\n");
    seed.fill(0);
    const label = ["OPENSSH", "PRIVATE", "KEY"].join(" ");
    return { publicKey: `ssh-ed25519 ${b64(publicBlob)} vexa`, privateKey: `-----BEGIN ${label}-----\n${encoded}\n-----END ${label}-----\n` };
  }
  root.VexaSshKeys = { generate };
  if (typeof module !== "undefined") module.exports = { generate };
  if (!root.document) return;
  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-generate-ssh]"); if (!button) return;
    button.disabled = true;
    let dialog;
    try {
      let keys = await generate();
      dialog = document.createElement("dialog"); dialog.className = "panel max-w-xl w-full p-6 text-slate-200";
      dialog.innerHTML = '<h2 class="text-lg text-white">Save your SSH key</h2><p class="my-3 text-sm">Download the private key now and keep it on your device. It is not password-encrypted. Never share it or paste it into the panel. Only the public key belongs on a server.</p><label class="label">Public key<textarea class="field mt-2 font-mono text-xs" rows="4" readonly></textarea></label><div class="mt-4 flex flex-wrap gap-3"><button type="button" class="btn-primary" data-download-key>Download private key</button><button type="button" class="btn-secondary" data-copy-public>Copy public key</button><button type="button" class="btn-secondary" data-close-key>Close</button></div><p class="mt-3 text-xs" role="status"></p>';
      dialog.querySelector("textarea").value = keys.publicKey;
      dialog.querySelector("[data-download-key]").onclick = () => {
        const url = URL.createObjectURL(new Blob([keys.privateKey], { type: "application/octet-stream" }));
        const link = document.createElement("a"); link.href = url; link.download = "vexa_ed25519"; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
        dialog.querySelector('[role="status"]').textContent = "Private key downloaded. On Linux/macOS run chmod 600 vexa_ed25519 before using ssh -i vexa_ed25519 user@server.";
      };
      dialog.querySelector("[data-copy-public]").onclick = async () => {
        try { await navigator.clipboard.writeText(keys.publicKey); dialog.querySelector('[role="status"]').textContent = "Public key copied. Add it to your server's authorized keys."; }
        catch { dialog.querySelector("textarea").select(); dialog.querySelector('[role="status"]').textContent = "Select and copy the public key manually."; }
      };
      dialog.querySelector("[data-close-key]").onclick = () => dialog.close();
      dialog.addEventListener("close", () => { keys = null; dialog.remove(); }, { once: true });
      document.body.append(dialog); dialog.showModal();
    } catch (error) { dialog?.remove(); alert(error.message || "This browser cannot generate Ed25519 keys. Use ssh-keygen -t ed25519 on your device."); }
    finally { button.disabled = false; }
  });
})(typeof globalThis !== "undefined" ? globalThis : window);
