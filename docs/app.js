import { createAnalyzer } from './python-runtime.mjs';
'use strict';
const form = document.querySelector('#analysis-form');
const message = document.querySelector('#message');
const domain = document.querySelector('#domain');
const result = document.querySelector('#result');
const error = document.querySelector('#error');
const submit = document.querySelector('#analyze');
let requestId = 0;
let analyzeLocally;
const status = document.querySelector('#runtime-status');
createAnalyzer().then(analyzer => {
  analyzeLocally = analyzer; submit.disabled = false; submit.textContent = 'Examine message';
  status.textContent = 'Ready. Analysis runs in this browser; message text is not sent.';
}).catch(() => {
  status.textContent = 'The local analysis could not load. Reload this page to try again.';
  submit.textContent = 'Analysis unavailable';
});
function node(tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}
function linkForDisplay(link, characters) {
  if (!link.host) return link;
  const raw = characters.slice(link.start, link.end).join('');
  try {
    // Parsing only: never visit the URL or change the frozen Python analysis.
    const url = new URL(/^www\./i.test(raw) ? 'https://' + raw : raw);
    const host = url.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
    if (host !== link.host) return {
      host: null, displayLabel: 'Ambiguous link host',
      warnings: ['URL host interpretations differ. Do not open it; verify through an independently obtained contact or official app.']
    };
  } catch {
    return {host: null, warnings: ['Malformed URL: do not open it']};
  }
  return link;
}
function resetResults() {
  requestId += 1; result.replaceChildren(); result.hidden = true;
  document.querySelector('#empty').hidden = false; error.hidden = true;
}
document.querySelector('#example').addEventListener('click', () => {
  resetResults();
  message.value = 'Fictional example: This is your bank. Urgent: enter your OTP to avoid suspension. Visit https://bank.example@fraud.example/login';
  domain.value = 'bank.example'; message.focus();
});
document.querySelector('#clear').addEventListener('click', () => {
  form.reset(); resetResults(); message.focus();
});
message.addEventListener('input', resetResults);
domain.addEventListener('input', resetResults);
form.addEventListener('submit', async event => {
  event.preventDefault(); if (!analyzeLocally) return; const currentRequest = ++requestId;
  submit.disabled = true; submit.textContent = 'Examining…'; error.hidden = true;
  try {
    const data = analyzeLocally(message.value, domain.value);
    if (currentRequest !== requestId) return;
    result.replaceChildren(node('p','Sender identity: unverified','identity'));
    result.append(node('p',`Old SMS spam signal: ${data.spam_signal}. Model score: ${data.spam_model_score.toFixed(3)}.`,'signal'));
    result.append(node('p',data.score_meaning,'limits'));
    result.append(node('h3','Request wording'));
    if (!data.evidence.length) result.append(node('p','No listed wording cues found. This does not establish safety.'));
    for (const item of data.evidence) {
      const row = node('div','','evidence');
      row.append(node('strong',item.label),node('span',`“${item.text}”`),node('span',item.meaning)); result.append(row);
    }
    result.append(node('h3','Link hosts'));
    if (!data.links.length) result.append(node('p','No supported web links found.'));
    const characters = Array.from(message.value); // Python offsets count Unicode code points.
    for (const originalLink of data.links) {
      const link = linkForDisplay(originalLink, characters);
      const row = node('div','','link'); row.append(node('strong',link.displayLabel || link.host || 'Malformed link'));
      row.append(node('span','Sender authenticity remains unverified.'));
      for (const warning of link.warnings) row.append(node('p',warning,'warning'));
      result.append(row);
    }
    result.append(node('h3','Verify independently'));
    const steps = document.createElement('ol');
    for (const step of data.verification_steps) steps.append(node('li',step)); result.append(steps);
    result.append(node('h3','Limits'));
    for (const limit of data.limitations) result.append(node('p',limit,'limits'));
    result.hidden = false; document.querySelector('#empty').hidden = true;
  } catch (e) {
    if (currentRequest === requestId) {error.textContent = /Expected domain|Use a domain/.test(e.message) ? 'Use an independently obtained hostname, without a URL path or credentials.' : 'Enter 1 to 8192 characters of message text and a valid optional hostname.'; error.hidden = false;}
  } finally {submit.disabled = false; submit.textContent = 'Examine message';}
});
