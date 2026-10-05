// The UI is plain HTML with inline <script> blocks, so a syntax slip in one of
// them disables the whole page (nothing is defined, Analyze does nothing) while
// every server test stays green. Compile each inline script without running it.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const pages = fs.readdirSync(path.join(__dirname, '..', 'public')).filter((f) => f.endsWith('.html'));

for (const page of pages) {
  test(`${page}: every inline script parses`, () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', page), 'utf8');
    const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/gi)]
      .filter(([, attrs]) => !/type=["']?(application\/ld\+json|text\/template)/i.test(attrs))
      .map(([, , body]) => body);
    for (const [i, body] of scripts.entries()) {
      assert.doesNotThrow(() => new vm.Script(body, { filename: `${page} <script #${i + 1}>` }), `${page} script #${i + 1}`);
    }
  });
}

test('shared browser modules parse', () => {
  const dir = path.join(__dirname, '..', 'public', 'shared');
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    assert.doesNotThrow(() => new vm.Script(fs.readFileSync(path.join(dir, f), 'utf8'), { filename: f }), f);
  }
});
