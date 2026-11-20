/* Disk recovery always asks for a stopped VM, an account, and backup acknowledgement. */
(function () {
  "use strict";
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-recover-vm], [data-public-recover]"); if (!button) return;
    const publicMode = button.hasAttribute("data-public-recover");
    const dialog = document.createElement("dialog"); dialog.className = "panel max-w-xl w-full p-6 text-slate-200";
    dialog.innerHTML = '<form class="space-y-4"><h2 class="text-lg text-white">Offline account recovery</h2><p class="text-sm">Shut down the VM and create a tested disk backup first. No guest app is needed. A failed disk edit may require restoring the backup. This does not unlock encrypted disks or domain accounts. Windows: local password is cleared; set a new password through VNC immediately. Existing EFS/DPAPI-protected secrets may become inaccessible.</p><label class="block"><span class="label">Recovery method</span><select name="method" class="field"><option value="linux-libguestfs">Linux · libguestfs</option><option value="linux-shadow">Linux · direct shadow hash fallback</option><option value="windows-sam">Windows · clear local SAM password</option></select></label><label class="block"><span class="label">Local account name</span><input name="username" class="field" required maxlength="64" autocomplete="off" placeholder="root or Administrator"></label><label class="block" data-password-field><span class="label">New Linux password</span><input name="password" class="field" type="password" required minlength="12" maxlength="256" autocomplete="new-password"></label><label class="block"><span class="label">Type the exact VM name</span><input name="confirmation" class="field" required autocomplete="off"></label><label class="flex gap-2"><input type="checkbox" name="backup_confirmed" required>I have a tested backup and the VM is fully shut down.</label><p role="status" class="text-sm"></p><div class="flex gap-3"><button class="btn-danger" type="submit">Recover account</button><button class="btn-secondary" type="button" data-cancel>Cancel</button></div></form>';
    const form = dialog.querySelector("form");
    form.elements.method.onchange = () => { const windows = form.elements.method.value === "windows-sam"; form.elements.password.required = !windows; form.elements.password.disabled = windows; dialog.querySelector("[data-password-field]").hidden = windows; };
    dialog.querySelector("[data-cancel]").onclick = () => dialog.close();
    form.onsubmit = async (event) => {
      event.preventDefault(); if (!form.reportValidity()) return;
      const submit = form.querySelector('[type="submit"]'); submit.disabled = true;
      const status = dialog.querySelector('[role="status"]'); status.textContent = "Recovering… keep the VM stopped until this request finishes.";
      const body = { method: form.elements.method.value, username: form.elements.username.value, confirmation: form.elements.confirmation.value, backup_confirmed: form.elements.backup_confirmed.checked };
      if (body.method !== "windows-sam") body.password = form.elements.password.value;
      const cookieName = publicMode ? "vexa_status_csrf" : "vexa_csrf";
      const cookie = document.cookie.split("; ").find((item) => item.startsWith(cookieName + "="));
      const id = location.pathname.split("/").filter(Boolean).pop();
      try {
        const response = await fetch(publicMode ? "/api/public/vm/recovery" : `/api/v1/vms/${encodeURIComponent(id)}/recovery`, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": decodeURIComponent(cookie?.slice(cookieName.length + 1) || "") }, body: JSON.stringify(body) });
        const result = await response.json(); if (!response.ok) throw new Error(result.error?.message || "Recovery failed. Inspect the backup before retrying.");
        form.elements.password.value = ""; status.textContent = result.message; submit.hidden = true;
      } catch (error) { status.textContent = error.message; }
      finally { submit.disabled = false; }
    };
    dialog.addEventListener("close", () => { form.reset(); dialog.remove(); }, { once: true });
    document.body.append(dialog); dialog.showModal();
  });
})();
