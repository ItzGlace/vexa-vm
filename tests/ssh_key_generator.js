const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { generate } = require('../static/js/ssh-keys.js');
(async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vexa-key-test-'));
  try {
    const first = await generate(); const second = await generate();
    assert.notEqual(first.publicKey, second.publicKey);
    const file = path.join(directory, 'id_ed25519'); fs.writeFileSync(file, first.privateKey, { mode: 0o600 });
    const derived = execFileSync('ssh-keygen', ['-y', '-f', file], { encoding: 'utf8' }).trim().split(' ').slice(0, 2).join(' ');
    assert.equal(derived, first.publicKey.split(' ').slice(0, 2).join(' '));
    fs.writeFileSync(path.join(directory,'message'), 'vexa support key test');
    execFileSync('ssh-keygen', ['-Y','sign','-f',file,'-n','vexa-test',path.join(directory,'message')], { stdio: 'pipe' });
    console.log('SSH private key imports in OpenSSH, matches its public key, signs data, and differs on each generation');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
