// Synthetic software fixtures only. Does not train or reopen the SMS holdout.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { loadPyodide } from '../docs/vendor/pyodide/pyodide.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const fixtures = [
  ['Please transfer funds now. Keep this secret.', 'bank.example'],
  ['Do not give anybody your OTP.', 'bank.example'],
  ['Your account is suspended. Enter your password.', 'bank.example'],
  ['Hi, can we meet after class?', ''],
  ['I am your boss; buy gift cards immediately.', ''],
  ['This is your bank. Send money now.', ''],
  ['https://bank.example.attacker.example/login', 'bank.example'],
  ['https://bank.example@attacker.example/', 'bank.example'],
  ['https://bank.example/login', 'bank.example'],
  ['http://bank.example/login', 'bank.example'],
  ['https://support.bank.example/', 'bank.example'],
  ['https://xn--pple-43d.example/', 'bank.example'],
  ['https://[bad/', 'bank.example'],
  ['www.attacker.example', ''],
  ['<img src=x onerror=alert(1)> https://attacker.example/', ''],
  ['hello\u202e.exe', ''],
  ['Hey mum, this is my new number, transfer money.', ''],
  ['Your parcel needs a fee; pay now.', ''],
  ['A recorded voice said to reveal my verification code.', ''],
  ['Prize winner! Send your seed phrase.', ''],
  ['This order was shipped; no action required.', ''],
  ['Korean text: 안녕하세요 회의 일정입니다', ''],
  ['Urgent meeting today. We will not ask for passwords.', ''],
  ['I need help with a school project.', ''],
  ['ＦＲＥＥ prize １２３٤٥٦ Straße ﬃ', ''],
  ['https://bücher.example/login', 'bücher.example'],
  ['https://faß.example/', 'faß.example'],
  ['https://BANK.EXAMPLE./login', ' bank.example. '],
  ['😀 Enter your OTP https://bank.example@fraud.example/', 'bank.example'],
  ['', ''], ['x'.repeat(8193), ''], ['hello', 'https://bank.example/path'],
  ['hello', 'invalid'], ['hello', 'a'.repeat(254)]
];
const wrapper = `
import json
from core import SpamModel, analyze
_model = SpamModel.load(json.load(open('model.json')))
def checked(text, domain):
    try:
        return {'result': analyze(text, _model, domain)}
    except ValueError as error:
        return {'error': str(error)}
`;
const native = spawnSync('python3', ['-c', wrapper + '\nimport sys\nprint(json.dumps([checked(*case) for case in json.load(sys.stdin)],ensure_ascii=False))'], {
  cwd: root, input: JSON.stringify(fixtures), encoding: 'utf8'
});
assert.equal(native.status, 0, native.stderr);
const expected = JSON.parse(native.stdout);
const pyodide = await loadPyodide({ indexURL: fileURLToPath(new URL('../docs/vendor/pyodide/', import.meta.url)) });
for (const name of ['core.py', 'model.json']) {
  const bytes = readFileSync(root + name);
  assert.deepEqual(readFileSync(root + 'docs/' + name), bytes, `${name}: frozen copy`);
  pyodide.FS.writeFile('/home/pyodide/' + name, bytes);
}
pyodide.runPython(wrapper + '\ndef checked_json(text, domain):\n    return json.dumps(checked(text, domain), ensure_ascii=False)');
const checked = pyodide.globals.get('checked_json');
fixtures.forEach(([text, domain], index) => {
  assert.deepEqual(JSON.parse(checked(text, domain)), expected[index], `case ${index + 1}`);
});
checked.destroy();
console.log(JSON.stringify({
  passed: fixtures.length, total: fixtures.length,
  scope: 'Synthetic runtime-equivalence checks, not an SMS evaluation or modern fraud benchmark',
  model_sha256: createHash('sha256').update(readFileSync(root + 'model.json')).digest('hex'),
  core_sha256: createHash('sha256').update(readFileSync(root + 'core.py')).digest('hex')
}));
