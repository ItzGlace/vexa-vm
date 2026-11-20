# Console, clipboard, and mobile access

Open a console from the administrator VM page or an authorized customer status link. The existing
one-time link exchange, same-origin WebSocket, loopback VNC target, and ten-minute session expiry
remain in force. The update does not make QEMU's VNC port publicly accessible.

**Keyboard & clipboard** opens controls that work on desktop and phone browsers:

- **Read device clipboard** asks the browser for clipboard permission, then places text in the send
  box for review. **Send clipboard** offers it through VNC clipboard sharing. The guest desktop and
  its VNC clipboard integration must support this; a plain KVM text console usually does not.
- Text received from the guest appears in **Guest clipboard**. **Copy to device** copies it only when
  requested. The page does not silently read or overwrite the local clipboard. If clipboard access
  is denied, select/copy/paste manually in the text fields. HTTPS is required for browser clipboard APIs.
- **Type text** sends up to 2,000 Unicode characters as keystrokes (CRLF becomes Enter). It works
  without guest clipboard support, including login prompts and text consoles. Newlines can execute
  commands: inspect the text first. Input uses the guest keyboard layout; unsupported Unicode may
  not appear in firmware, and this is not file transfer.
- **Phone keyboard** opens a large-text input for Android/iOS keyboards, including composition/IME
  input and Backspace. Special buttons provide Esc, Tab, Enter, function keys, Delete and arrows.
  Ctrl+Alt+Del stays available in the toolbar. noVNC supplies the touch pointer gestures.
- **Touch pan** switches between dragging the viewport and controlling the remote pointer. **Fit**
  scales the display to the available viewport. Dynamic viewport height accommodates mobile browser
  toolbars; the control panel scrolls on small screens. Fullscreen depends on browser support.

The typing queue is bounded and stops on session replacement, disconnect, or hidden document. Clipboard
buffers clear on disconnect; do not leave sensitive text in the send box on a shared device. Reconnecting
uses the remaining lifetime of the existing session and does not extend its ten-minute expiry.

SSH generation is available on the VM creation, VM detail, and customer status pages. It creates an
Ed25519 key pair with browser WebCrypto on HTTPS/localhost, downloads an OpenSSH private key, and
lets the user copy the public key. The private key is unencrypted and never uploaded or stored by Vexa.
Save it safely, set `chmod 600 vexa_ed25519` on Linux/macOS, and add **only the public key** to the guest.
Generation does not automatically install the public key. Use the creation form, guest authorized_keys,
or the existing Guest Tools SSH-key controls as appropriate. Unsupported browsers can use
`ssh-keygen -t ed25519` locally. Browser downloads and AI/session transcripts must not be used as a
private-key backup service.
