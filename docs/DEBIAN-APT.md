# Debian package and APT repository

Vexa-VM publishes an `amd64` Debian package alongside the immutable release archive. The package
contains the same compiled binaries, templates, migrations, static assets, manuals, and Linux/Windows
Guest Tools as the archive.

## Install a release package

```bash
curl -fLO https://github.com/ItzGlace/vexa-vm/releases/download/v0.1.8/vexa-vm_0.1.8_amd64.deb
curl -fLO https://github.com/ItzGlace/vexa-vm/releases/download/v0.1.8/vexa-vm_0.1.8_amd64.deb.sha256
sha256sum -c vexa-vm_0.1.8_amd64.deb.sha256
sudo apt install ./vexa-vm_0.1.8_amd64.deb
```

On a fresh install, the package creates a root-only
`/var/lib/vexa-vm/INITIAL_ADMIN_PASSWORD`. Read it once, sign in as `admin`, change the password,
and securely remove the file. The application listens on `127.0.0.1:8080` until the operator
configures a TLS reverse proxy.

Package removal does not delete the SQLite database, encryption key, ISO library, VM disks, or
backups. This prevents an accidental `apt remove` from destroying guest data.

## Build the package locally

After building the application and both Guest Tools targets:

```bash
./scripts/package-release.sh x86_64-unknown-linux-gnu dist
./scripts/package-deb.sh x86_64-unknown-linux-gnu dist
dpkg-deb --info dist/vexa-vm_0.1.8_amd64.deb
```

## Publish the signed repository

APT clients must never be told to trust an unsigned repository. Repository publication therefore
stays disabled until the owner configures a dedicated offline-backed OpenPGP signing key.

1. Create a signing-only OpenPGP key and store its encrypted backup offline.
2. Add the ASCII-armored private key to the GitHub Actions secret `VEXA_APT_GPG_PRIVATE_KEY`.
3. Set repository variable `VEXA_APT_GPG_KEY_ID` to its full fingerprint.
4. Set repository variable `VEXA_APT_ENABLED` to `true`.
5. Enable GitHub Pages with **GitHub Actions** as its source.
6. Publish a signed Vexa-VM tag. The APT workflow builds `Packages`, `Release`, `InRelease`,
   `Release.gpg`, and the binary public key, then deploys only that repository to Pages.

The private key is imported into a temporary GitHub Actions keyring and is never placed in the
source tree or release artifacts. Rotate it by publishing the new public key through an independently
trusted channel before switching signatures.

After the first successful publication, users can configure the repository exactly as shown in the
main README and install with `sudo apt install vexa-vm`.
