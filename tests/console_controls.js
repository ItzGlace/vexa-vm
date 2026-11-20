const assert = require('node:assert/strict');
const { textKeys } = require('../static/js/console-controls.js');
assert.deepEqual(textKeys('a\r\n\tÉ😀'), [97,0xff0d,0xff09,201,0x0101f600]);
assert.throws(() => textKeys('a\0b'));
assert.throws(() => textKeys('a'.repeat(2001)));
assert.equal(textKeys('x'.repeat(2000)).length,2000);
console.log('Console typing handles Enter, Tab, Unicode, rejects control injection, and bounds input');
