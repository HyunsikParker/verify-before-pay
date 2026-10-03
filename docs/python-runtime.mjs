import { loadPyodide } from './vendor/pyodide/pyodide.mjs';

const hashes = {
  'core.py': '6a39dab6370c8d4b04f05a7eedafba23e1aad0f570493a255caf2f713fe11994',
  'model.json': 'e3a024c6b54156da921b03ce9878cd4d043557ce590a4aeb9363d89bd7f321de'
};

async function frozenFile(name) {
  const response = await fetch(new URL(name, import.meta.url));
  if (!response.ok) throw new Error('A required analysis file could not load. Reload to try again.');
  const bytes = await response.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const hex = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
  if (hex !== hashes[name]) throw new Error('Analysis file integrity check failed. No message was examined.');
  return new Uint8Array(bytes);
}

export async function createAnalyzer() {
  const [pyodide, core, model] = await Promise.all([
    loadPyodide({ indexURL: new URL('./vendor/pyodide/', import.meta.url).href }),
    frozenFile('core.py'), frozenFile('model.json')
  ]);
  pyodide.FS.writeFile('/home/pyodide/core.py', core);
  pyodide.FS.writeFile('/home/pyodide/model.json', model);
  pyodide.runPython(`
import json
from core import SpamModel, analyze
with open('model.json') as model_file:
    _model = SpamModel.load(json.load(model_file))
def _analyze_json(text, domain):
    return json.dumps(analyze(text, _model, domain), ensure_ascii=False)
`);
  const analyze = pyodide.globals.get('_analyze_json');
  return (text, domain) => JSON.parse(analyze(text, domain));
}
