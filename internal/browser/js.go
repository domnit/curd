package browser

// Fixed, curd-authored functions evaluated in an isolated world with
// Runtime.callFunctionOn. Agent input (selectors, numbers) is passed only as
// JSON-encoded call arguments and is never spliced into this source. Page
// scripts cannot reach an isolated world.

const jsPrelude = `let e; try { e = document.querySelector(sel); } catch (x) { return {err: 'invalid'}; }`

const jsText = `function(sel, max) {` + jsPrelude + `
  if (!e) return {err: 'nomatch'};
  let t = e.innerText; if (typeof t !== 'string') t = e.textContent || '';
  return {v: t.length > max ? t.slice(0, max) : t, n: t.length};
}`

const jsHTML = `function(sel, max) {` + jsPrelude + `
  if (!e) return {err: 'nomatch'};
  const t = e.outerHTML || '';
  return {v: t.length > max ? t.slice(0, max) : t, n: t.length};
}`

const jsExists = `function(sel) {` + jsPrelude + `
  return {v: !!e};
}`

const jsVisible = `function(sel) {` + jsPrelude + `
  if (!e) return {v: false};
  const r = e.getBoundingClientRect(), cs = getComputedStyle(e);
  return {v: r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) !== 0};
}`

const jsClickPoint = `function(sel) {` + jsPrelude + `
  if (!e) return {err: 'nomatch'};
  e.scrollIntoView({block: 'center', inline: 'center'});
  const r = e.getBoundingClientRect();
  if (r.width === 0 && r.height === 0) return {err: 'hidden'};
  const x = r.left + r.width / 2, y = r.top + r.height / 2;
  const top = document.elementFromPoint(x, y);
  return {x: x, y: y, covered: !(top && (top === e || e.contains(top)))};
}`

const jsFocus = `function(sel) {` + jsPrelude + `
  if (!e) return {err: 'nomatch'};
  e.scrollIntoView({block: 'center', inline: 'center'});
  e.focus();
  if (document.activeElement !== e && !(e.contains && e.contains(document.activeElement))) return {err: 'notfocusable'};
  return {v: true};
}`

// jsWaitStable resolves once the document has seen no DOM mutations for
// quiet milliseconds, or reports a timeout after limit milliseconds.
const jsWaitStable = `function(quiet, limit) {
  return new Promise((resolve) => {
    let t, hard;
    const mo = new MutationObserver(() => { clearTimeout(t); t = setTimeout(done, quiet); });
    function done() { mo.disconnect(); clearTimeout(hard); resolve({timeout: false}); }
    mo.observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
    t = setTimeout(done, quiet);
    hard = setTimeout(() => { mo.disconnect(); clearTimeout(t); resolve({timeout: true}); }, limit);
  });
}`
