#!/usr/bin/env bash
set -Eeuo pipefail

readonly TARGET="${1:?usage: package-deb.sh <rust-target> [output-directory]}"
readonly OUTPUT_DIR="${2:-dist}"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${PROJECT_ROOT}/Cargo.toml" | head -n1)"
readonly ARCHIVE="${OUTPUT_DIR}/vexa-vm-${TARGET}.tar.gz"

[[ "${TARGET}" == "x86_64-unknown-linux-gnu" ]] || {
  printf 'unsupported Debian target: %s\n' "${TARGET}" >&2
  exit 1
}
[[ -n "${VERSION}" && -f "${ARCHIVE}" ]] || {
  printf 'build the release archive before the Debian package: %s\n' "${ARCHIVE}" >&2
  exit 1
}
command -v dpkg-deb >/dev/null || {
  printf 'dpkg-deb is required\n' >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"
staging="$(mktemp -d)"
cleanup() { rm -rf -- "${staging}"; }
trap cleanup EXIT

release="${staging}/opt/vexa-vm/releases/${VERSION}"
mkdir -p "${release}"
tar -xzf "${ARCHIVE}" -C "${release}" --no-same-owner --no-same-permissions

install -Dm0644 "${PROJECT_ROOT}/deploy/vexa-vm.service" \
  "${staging}/lib/systemd/system/vexa-vm.service"
install -Dm0644 "${PROJECT_ROOT}/deploy/vexa-update-executor-ready.service" \
  "${staging}/lib/systemd/system/vexa-update-executor-ready.service"
install -Dm0644 "${PROJECT_ROOT}/deploy/vexa-update-dispatch.service" \
  "${staging}/lib/systemd/system/vexa-update-dispatch.service"
install -Dm0644 "${PROJECT_ROOT}/deploy/vexa-update-dispatch.path" \
  "${staging}/lib/systemd/system/vexa-update-dispatch.path"
install -Dm0644 "${PROJECT_ROOT}/packaging/debian/copyright" \
  "${staging}/usr/share/doc/vexa-vm/copyright"
install -Dm0644 "${PROJECT_ROOT}/README.md" \
  "${staging}/usr/share/doc/vexa-vm/README.md"

mkdir -p "${staging}/DEBIAN"
installed_size="$(du -sk "${staging}" | awk '{print $1}')"
cat > "${staging}/DEBIAN/control" <<CONTROL
Package: vexa-vm
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Vexa-VM contributors <noreply@users.noreply.github.com>
Homepage: https://github.com/ItzGlace/vexa-vm
Installed-Size: ${installed_size}
Suggests: libguestfs-tools, chntpw, python3, openssh-client
Depends: adduser, ca-certificates, curl, openssl, sqlite3, qemu-kvm, qemu-utils, libvirt-daemon-system, libvirt-clients, virtinst, cloud-image-utils, genisoimage, p7zip-full, dnsmasq-base, iproute2, nftables, systemd
Description: open-source KVM virtualization panel and API
 Vexa-VM is a Rust control plane for a single KVM/libvirt node with a web
 panel, REST API, VM lifecycle, image library, metrics, customer portal,
 noVNC console gateway, dual-stack IP management, quotas and audit records.
CONTROL
sed "s/@VERSION@/${VERSION}/g" "${PROJECT_ROOT}/packaging/debian/postinst.in" \
  > "${staging}/DEBIAN/postinst"
install -m0755 "${PROJECT_ROOT}/packaging/debian/prerm" "${staging}/DEBIAN/prerm"
chmod 0755 "${staging}/DEBIAN/postinst"

find "${staging}/opt" -type d -exec chmod 0755 {} +
find "${staging}/opt" -type f -exec chmod 0644 {} +
chmod 0755 "${release}/bin/vexa-vm" "${release}/bin/vexa-update-helper" \
  "${release}/guest-tools/vexa-guest-tools-linux-x86_64"

package="${OUTPUT_DIR}/vexa-vm_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group --build "${staging}" "${package}" >/dev/null
(cd "${OUTPUT_DIR}" && sha256sum "$(basename "${package}")" > "$(basename "${package}").sha256")
printf '%s\n' "${package}"
