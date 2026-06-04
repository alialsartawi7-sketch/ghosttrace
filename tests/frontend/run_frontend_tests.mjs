#!/usr/bin/env node
/*
 * GhostTrace — Frontend security test harness (zero dependencies).
 *
 * The frontend is a single-page vanilla-JS app embedded in templates/index.html
 * with no build step, so there's nothing to "import". This harness extracts the
 * security-critical helper functions straight from the HTML and executes the
 * REAL source in a sandbox, then asserts behaviour. It guards the two things
 * most likely to regress dangerously:
 *
 *   1. escHtml / safeLog  — the DOM-XSS hardening (v6.3). If these stop
 *      escaping, stored/reflected payloads become live again.
 *   2. _normHost / _sameTarget — the target-mixing guard. If these break,
 *      a recon for one domain can be stapled onto another domain's report.
 *
 * Run directly:   node tests/frontend/run_frontend_tests.mjs
 * Or via pytest:  pytest tests/test_frontend.py   (skips if node is absent)
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = join(HERE, '..', '..', 'templates', 'index.html');

// ── Extract single-line `function NAME(...) {...}` definitions from the HTML ──
function extractFn(html, name) {
  for (const line of html.split('\n')) {
    const t = line.trim();
    if (t.startsWith(`function ${name}(`) || t.startsWith(`function ${name} (`)) {
      return t;
    }
  }
  throw new Error(`could not find function "${name}" in index.html`);
}

const html = readFileSync(INDEX_HTML, 'utf8');
const NAMES = ['escHtml', 'safeLog', '_normHost', '_sameTarget'];
const src = NAMES.map((n) => extractFn(html, n)).join('\n');

// Run the real source in an isolated context, then export the functions.
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(src + '\n' + NAMES.map((n) => `this.${n}=${n};`).join(''), sandbox);
const { escHtml, safeLog, _normHost, _sameTarget } = sandbox;

// ── Tiny assertion runner ──
let pass = 0;
const failures = [];
const eq = (name, got, want) => {
  if (got === want) pass++;
  else failures.push(`${name}\n       got:  ${JSON.stringify(got)}\n       want: ${JSON.stringify(want)}`);
};
const ok = (name, cond, detail = '') => {
  if (cond) pass++;
  else failures.push(`${name}${detail ? '\n       ' + detail : ''}`);
};

// ───────────────────────── escHtml (XSS escaping) ─────────────────────────
eq('escHtml escapes <script>',
  escHtml('<script>alert(1)</script>'),
  '&lt;script&gt;alert(1)&lt;/script&gt;');
eq('escHtml escapes attribute-breakout payload',
  escHtml('"><img src=x onerror=alert(1)>'),
  '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
eq('escHtml escapes ampersand', escHtml('a & b'), 'a &amp; b');
eq('escHtml escapes single quote', escHtml("o'brien"), 'o&#39;brien');
eq('escHtml handles null', escHtml(null), '');
eq('escHtml handles undefined', escHtml(undefined), '');
eq('escHtml stringifies numbers', escHtml(42), '42');
ok('escHtml output has no raw "<" for a tag payload',
  !escHtml('<b>x</b>').includes('<'),
  `output: ${escHtml('<b>x</b>')}`);

// ───────────────────────── safeLog (whitelist) ─────────────────────────
// Allowed styling tags (hl/muted/val) are restored...
eq('safeLog restores whitelisted <span class="hl">',
  safeLog('hello <span class="hl">world</span>'),
  'hello <span class="hl">world</span>');
ok('safeLog restores single-quoted whitelisted span',
  safeLog("x <span class='val'>y</span>").includes('<span class="val">'),
  `output: ${safeLog("x <span class='val'>y</span>")}`);
// ...but anything else stays escaped (no live injection).
ok('safeLog keeps <script> inert',
  !safeLog('<script>alert(1)</script>').includes('<script'),
  `output: ${safeLog('<script>alert(1)</script>')}`);
ok('safeLog does NOT restore a non-whitelisted span class',
  !safeLog('<span class="evil">x</span>').includes('<span class="evil">'),
  `output: ${safeLog('<span class="evil">x</span>')}`);
ok('safeLog neutralises img/onerror inside a fake span',
  !safeLog('<span class="hl"><img src=x onerror=alert(1)></span>').includes('<img'),
  `output: ${safeLog('<span class="hl"><img src=x onerror=alert(1)></span>')}`);

// ───────────────────────── _normHost ─────────────────────────
eq('_normHost strips scheme/www/path/case',
  _normHost('HTTPS://WWW.Zu.Edu.EG/path?x=1'), 'zu.edu.eg');
eq('_normHost strips trailing dot', _normHost('zu.edu.eg.'), 'zu.edu.eg');
eq('_normHost trims whitespace', _normHost('  Example.COM  '), 'example.com');
eq('_normHost handles empty', _normHost(''), '');

// ───────────────────────── _sameTarget (mixing guard) ─────────────────────────
ok('_sameTarget: different domains are NOT same (the ltuc/zu bug)',
  !_sameTarget('zu.edu.eg', 'ltuc.com'));
ok('_sameTarget: subdomain matches parent',
  _sameTarget('admin.zu.edu.eg', 'zu.edu.eg'));
ok('_sameTarget: parent matches subdomain',
  _sameTarget('zu.edu.eg', 'mail.zu.edu.eg'));
ok('_sameTarget: normalised forms match (scheme/www/slash)',
  _sameTarget('zu.edu.eg/', 'https://www.zu.edu.eg'));
ok('_sameTarget: identical hosts match', _sameTarget('zu.edu.eg', 'zu.edu.eg'));
ok('_sameTarget: empty target is never a match', !_sameTarget('', 'zu.edu.eg'));
ok('_sameTarget: lookalike "notzu.edu.eg" is NOT a match for "zu.edu.eg"',
  !_sameTarget('notzu.edu.eg', 'zu.edu.eg'));
ok('_sameTarget: "xzu.edu.eg" is NOT a subdomain of "zu.edu.eg"',
  !_sameTarget('xzu.edu.eg', 'zu.edu.eg'));

// ── Report ──
const total = pass + failures.length;
console.log(`\nFrontend security helpers — ${pass}/${total} checks passed`);
if (failures.length) {
  console.log('\nFAILURES:');
  for (const f of failures) console.log('  ✗ ' + f);
  process.exit(1);
}
console.log('All frontend security checks passed ✓');
process.exit(0);
