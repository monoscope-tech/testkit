(() => {
if (window.__tk) return;
const T = window.__tk = { refs: new Map(), ids: new WeakMap(), next: 1, perf: { lcp: null, lcpAt: 0, cls: 0, inp: 0, long: [], shifts: [] } };
const norm = s => (s || '').replace(/\s+/g, ' ').trim();
const lower = s => norm(s).toLowerCase();
const INTERACTIVE = ['button','link','textbox','checkbox','radio','combobox','listbox','option','slider','spinbutton','switch','tab','menuitem','menuitemcheckbox','menuitemradio','searchbox','treeitem'];
const LANDMARK = ['main','navigation','banner','contentinfo','complementary','region','form','search','dialog','alertdialog'];
const STRUCT = ['heading','alert','status','table','row','cell','columnheader','rowheader','list','listitem','img','paragraph','group','tablist','tabpanel','menu','menubar','progressbar','meter','tree','grid','gridcell','separator','article','figure','toolbar','tooltip'];
const FROM_CONTENT = ['button','link','heading','cell','gridcell','columnheader','rowheader','row','option','tab','menuitem','menuitemcheckbox','menuitemradio','treeitem','listitem','tooltip','checkbox','radio','switch','status','alert'];
const BTN_TYPES = ['button','submit','reset','image'];

T.role = el => {
  const r = el.getAttribute && el.getAttribute('role');
  if (r) return r.split(/\s+/)[0];
  const t = el.tagName.toLowerCase(), ty = (el.getAttribute('type') || '').toLowerCase();
  switch (t) {
    case 'a': case 'area': return el.hasAttribute('href') ? 'link' : null;
    case 'button': case 'summary': return 'button';
    case 'input':
      if (BTN_TYPES.includes(ty)) return 'button';
      if (ty === 'checkbox') return el.getAttribute('switch') !== null ? 'switch' : 'checkbox';
      if (ty === 'radio') return 'radio';
      if (ty === 'range') return 'slider';
      if (ty === 'number') return 'spinbutton';
      if (ty === 'hidden') return null;
      if (ty === 'search') return el.hasAttribute('list') ? 'combobox' : 'searchbox';
      return el.hasAttribute('list') ? 'combobox' : 'textbox';
    case 'textarea': return 'textbox';
    case 'select': return (el.multiple || el.size > 1) ? 'listbox' : 'combobox';
    case 'option': return 'option';
    case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6': return 'heading';
    case 'img': return el.getAttribute('alt') === '' ? null : 'img';
    case 'nav': return 'navigation';
    case 'main': return 'main';
    case 'header': return el.closest('article,section,main,aside,nav') ? null : 'banner';
    case 'footer': return el.closest('article,section,main,aside,nav') ? null : 'contentinfo';
    case 'aside': return 'complementary';
    case 'form': return 'form';
    case 'section': return (el.hasAttribute('aria-label') || el.hasAttribute('aria-labelledby')) ? 'region' : null;
    case 'article': return 'article';
    case 'ul': case 'ol': case 'menu': return 'list';
    case 'li': return 'listitem';
    case 'table': return 'table';
    case 'tr': return 'row';
    case 'td': return 'cell';
    case 'th': return el.closest('thead') || el.getAttribute('scope') === 'col' ? 'columnheader' : 'rowheader';
    case 'thead': case 'tbody': case 'tfoot': return 'rowgroup';
    case 'dialog': return 'dialog';
    case 'progress': return 'progressbar';
    case 'meter': return 'meter';
    case 'hr': return 'separator';
    case 'fieldset': case 'details': return 'group';
    case 'p': return 'paragraph';
    case 'output': return 'status';
    case 'figure': return 'figure';
  }
  if (el.isContentEditable && el.getAttribute('contenteditable') !== null) return 'textbox';
  return null;
};
const text = el => norm(el.innerText !== undefined && el.offsetParent !== undefined ? el.innerText : el.textContent);
T.name = el => {
  const lb = el.getAttribute('aria-labelledby');
  if (lb) return norm(lb.split(/\s+/).map(id => document.getElementById(id)).filter(Boolean).map(text).join(' '));
  const al = el.getAttribute('aria-label');
  if (al && norm(al)) return norm(al);
  const t = el.tagName.toLowerCase(), ty = (el.getAttribute('type') || '').toLowerCase();
  if (t === 'input' && BTN_TYPES.includes(ty)) return norm(el.value || el.getAttribute('alt') || (ty === 'submit' ? 'Submit' : ty === 'reset' ? 'Reset' : ''));
  if (['input', 'textarea', 'select'].includes(t)) {
    const ls = el.labels && [...el.labels].map(text).filter(Boolean);
    if (ls && ls.length) return norm(ls.join(' '));
    return norm(el.getAttribute('placeholder') || el.getAttribute('title') || '');
  }
  if (t === 'img') return norm(el.getAttribute('alt') || el.getAttribute('title') || '');
  if (t === 'table') { const c = el.querySelector('caption'); if (c) return text(c); }
  if (t === 'fieldset') { const l = el.querySelector('legend'); if (l) return text(l); }
  if (t === 'figure') { const c = el.querySelector('figcaption'); if (c) return text(c); }
  const role = T.role(el);
  if (FROM_CONTENT.includes(role)) return text(el);
  return norm(el.getAttribute('title') || '');
};
T.visible = el => {
  if (!el.isConnected) return false;
  if (el.closest('[aria-hidden="true"]')) return false;
  if (el.checkVisibility && !el.checkVisibility({ checkOpacity: false, checkVisibilityCSS: true })) return false;
  const r = el.getBoundingClientRect();
  if (el.tagName === 'OPTION') return true;
  return r.width > 0 && r.height > 0;
};
const deepAll = (root, out = []) => {
  for (const el of root.querySelectorAll('*')) { out.push(el); if (el.shadowRoot) deepAll(el.shadowRoot, out); }
  return out;
};
const nameMatch = (actual, n) => {
  if (!n) return true;
  if (n.Sub !== undefined) return lower(actual).includes(lower(n.Sub));
  if (n.Exact !== undefined) return norm(actual) === norm(n.Exact);
  if (n.Re) return new RegExp(n.Re[0], n.Re[1]).test(norm(actual));
  return true;
};
const isField = el => {
  const r = T.role(el);
  return ['textbox', 'combobox', 'searchbox', 'spinbutton', 'listbox', 'slider', 'checkbox', 'radio', 'switch'].includes(r) ||
    (el.tagName === 'INPUT' && (el.type || '') === 'file');
};
const fieldNames = el => [T.name(el), el.getAttribute('placeholder'), el.getAttribute('name'), el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`) ? text(document.querySelector(`label[for="${CSS.escape(el.id)}"]`)) : null].filter(Boolean);
const head = h => typeof h === 'string' ? [h, null] : Object.entries(h)[0];
// candidates for a locator under the given roots, before position filters
const candidates = (loc, roots) => {
  const [kind, arg] = head(loc.head);
  let out = [];
  for (const root of roots) {
    let all;
    if (kind === 'Css') { all = [...root.querySelectorAll(arg)]; deepAll(root).filter(e => e.shadowRoot).forEach(e => all.push(...e.shadowRoot.querySelectorAll(arg))); }
    else if (kind === 'Ref') { const el = T.refs.get(arg); all = el && el.isConnected && (root === document || root.contains(el)) ? [el] : []; }
    else if (kind === 'Closest') {
      const [a, b] = arg; all = [];
      for (const el of T.query(b, [root])) { let p = el.parentElement; while (p && !matchOne(p, a)) p = p.parentElement; if (p && !all.includes(p)) all.push(p); }
    }
    else all = deepAll(root).filter(el => matchHead(el, kind, arg, loc.name));
    out.push(...all.filter(e => !out.includes(e)));
  }
  out = out.filter(el => (loc.filters || []).every(f => f.Text ? nameMatch(text(el), f.Text) : T.query(f.Has, [el]).length > 0));
  if (kind === 'Css' || kind === 'Ref' || kind === 'Closest') out = out.filter(el => !loc.name || nameMatch(T.name(el) || text(el), loc.name));
  return out;
};
const matchHead = (el, kind, arg, name) => {
  if (kind === 'Role') return T.role(el) === arg && T.visible(el) && nameMatch(T.name(el), name);
  if (kind === 'Field') return isField(el) && T.visible(el) && (!name || fieldNames(el).some(n => nameMatch(n, name)));
  if (kind === 'Testid') return el.getAttribute('data-testid') !== null && nameMatch(el.getAttribute('data-testid'), name);
  if (kind === 'Text') {
    if (!T.visible(el) || ['SCRIPT', 'STYLE', 'HEAD', 'HTML', 'BODY'].includes(el.tagName)) return false;
    if (!nameMatch(text(el), name)) return false;
    return ![...el.children].some(c => T.visible(c) && nameMatch(text(c), name));
  }
  return false;
};
const matchOne = (el, loc) => candidates(loc, [el.parentElement || document]).includes(el);
const frameSel = s => s.startsWith('#') || s.startsWith('.') || s.includes('[') ? s : `iframe[name="${s}"],iframe[title="${s}"],iframe#${CSS.escape(s)}`;
T.frameInfo = spec => {
  const f = deepAll(document).find(e => e.tagName === 'IFRAME' && e.matches(frameSel(spec)));
  if (!f) return null;
  let cross = false; try { cross = !f.contentDocument; } catch (e) { cross = true; }
  const r = f.getBoundingClientRect();
  return { name: f.name, url: f.src, x: r.x + f.clientLeft, y: r.y + f.clientTop, cross };
};
T.query = (loc, roots = [document]) => {
  for (const s of (loc.scope || [])) {
    if (s.Loc) roots = T.query(s.Loc, roots);
    else if (s.Frame) roots = roots.flatMap(r => [...r.querySelectorAll(frameSel(s.Frame))].map(f => { try { return f.contentDocument; } catch (e) { return null; } }).filter(Boolean));
  }
  let els = candidates(loc, roots);
  if (els.length > 1 && loc.name && loc.name.Sub !== undefined) {
    const exact = els.filter(el => lower(head(loc.head)[0] === 'Text' ? text(el) : T.name(el)) === lower(loc.name.Sub));
    if (exact.length === 1) els = exact;
  }
  if (loc.first === true) els = els.slice(0, 1);
  if (loc.first === false) els = els.slice(-1);
  if (loc.nth !== null && loc.nth !== undefined) { const i = loc.nth < 0 ? els.length + loc.nth : loc.nth; els = els[i] ? [els[i]] : []; }
  return els;
};
T.ref = el => { let id = T.ids.get(el); if (!id) { id = T.next++; T.ids.set(el, id); T.refs.set(id, el); } return id; };
const STYLE_KEYS = ['color', 'background-color', 'display', 'visibility', 'opacity', 'font-weight', 'font-size'];
T.describe = el => {
  const cs = getComputedStyle(el), r = el.getBoundingClientRect(), role = T.role(el);
  const attrs = {}; for (const a of el.attributes) attrs[a.name] = a.value;
  const styles = {}; STYLE_KEYS.forEach(k => styles[k] = cs.getPropertyValue(k));
  const d = {
    __el: true, ref: T.ref(el), tag: el.tagName.toLowerCase(), role, name: T.name(el), text: text(el).slice(0, 2000),
    value: 'value' in el && el.tagName !== 'BUTTON' && el.tagName !== 'LI' ? el.value : null,
    visible: T.visible(el), disabled: !!(el.disabled || el.getAttribute('aria-disabled') === 'true' || el.closest('fieldset:disabled')),
    checked: !!(el.checked || el.getAttribute('aria-checked') === 'true'), focused: document.activeElement === el,
    expanded: el.getAttribute('aria-expanded') === 'true' || (el.tagName === 'DETAILS' && el.open),
    invalid: el.getAttribute('aria-invalid') === 'true' || (() => { try { return el.matches(':user-invalid'); } catch (e) { return false; } })(),
    editable: (['INPUT', 'TEXTAREA'].includes(el.tagName) && !el.readOnly && !el.disabled) || el.isContentEditable,
    message: el.validationMessage || null, attrs, styles,
    box: { x: r.x, y: r.y, width: r.width, height: r.height },
  };
  if (role === 'heading') d.level = +(el.getAttribute('aria-level') || el.tagName.slice(1)) || 2;
  if (el.tagName === 'TABLE') d.rows = T.rows(el);
  if (el.tagName === 'FORM') d.fields = Object.fromEntries([...el.elements].filter(isField).map(f => [T.name(f) || f.name, { value: f.value, valid: f.validity.valid, message: f.validationMessage }]));
  if (el.tagName === 'SELECT') d.options = [...el.options].map(o => o.label);
  return d;
};
T.rows = table => {
  const heads = [...table.querySelectorAll('thead th, tr:first-child th')].map(text);
  const body = [...table.querySelectorAll('tr')].filter(tr => tr.querySelector('td'));
  return body.map(tr => { const cells = [...tr.querySelectorAll('td,th')].map(text); return heads.length ? Object.fromEntries(cells.map((c, i) => [heads[i] || `col${i + 1}`, c])) : cells; });
};
T.resolve = loc => T.query(loc).map(T.describe);
const q = s => JSON.stringify(s);
const roleName = el => { const r = T.role(el), n = T.name(el); return r ? (n ? `${r} ${q(n.slice(0, 80))}` : r) : null; };
const unique = (loc, el) => { const r = T.query(loc); return r.length === 1 && r[0] === el; };
const hashy = s => /\d{3,}|[a-f0-9]{6,}|^:r|^ember|^css-|^sc-|^jsx-/i.test(s);
// The most stable locator text that uniquely resolves to `el` (used for refs, errors and recording).
T.locatorFor = el => {
  const tid = el.getAttribute('data-testid');
  if (tid && unique({ head: 'Testid', name: { Exact: tid }, filters: [], scope: [] }, el)) return `testid ${q(tid)}`;
  const r = T.role(el), n = T.name(el);
  if (r && n && unique({ head: { Role: r }, name: { Sub: n }, filters: [], scope: [] }, el)) return `${r} ${q(n)}`;
  if (r && n && unique({ head: { Role: r }, name: { Exact: n }, filters: [], scope: [] }, el)) return `${r} exactly ${q(n)}`;
  if (isField(el)) for (const fn of fieldNames(el)) if (unique({ head: 'Field', name: { Sub: fn }, filters: [], scope: [] }, el)) return `field ${q(fn)}`;
  const tx = text(el);
  if (tx && tx.length < 60 && unique({ head: 'Text', name: { Exact: tx }, filters: [], scope: [] }, el)) return `text exactly ${q(tx)}`;
  if (r && n) {
    for (let p = el.parentElement; p; p = p.parentElement) {
      const pr = T.role(p), pn = T.name(p);
      if (!pr || !pn || !['row', 'listitem', 'dialog', 'form', 'region', 'article', 'navigation', 'group', 'tabpanel'].includes(pr)) continue;
      const outer = { head: { Role: pr }, name: { Sub: pn.slice(0, 40) }, filters: [], scope: [] };
      if (unique({ head: { Role: r }, name: { Sub: n }, filters: [], scope: [{ Loc: outer }] }, el)) return `${r} ${q(n)} in ${pr} ${q(pn.slice(0, 40))}`;
    }
  }
  if (el.id && !hashy(el.id) && document.querySelectorAll('#' + CSS.escape(el.id)).length === 1) return `<#${el.id}/>`;
  const path = []; for (let e = el; e && e !== document.body && e.nodeType === 1; e = e.parentElement) {
    const tag = e.tagName.toLowerCase(), sib = e.parentElement ? [...e.parentElement.children].filter(c => c.tagName === e.tagName) : [];
    path.unshift(sib.length > 1 ? `${tag}:nth-of-type(${sib.indexOf(e) + 1})` : tag);
    if (document.querySelectorAll(path.join(' > ')).length === 1) break;
  }
  return `<${path.join(' > ')}/>`;
};
// actionability (spec §4): returns {ok, reason, x, y, locator}
T.actionable = async (ref, checks) => {
  const el = T.refs.get(ref);
  if (!el || !el.isConnected) return { ok: false, reason: 'detached' };
  el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
  const frame = () => new Promise(r => { requestAnimationFrame(() => r()); setTimeout(r, 50); });
  if (checks.includes('visible') && !T.visible(el)) return { ok: false, reason: 'hidden' };
  if (checks.includes('enabled') && T.describe(el).disabled) return { ok: false, reason: 'disabled' };
  if (checks.includes('editable') && !T.describe(el).editable && el.tagName !== 'SELECT') return { ok: false, reason: 'not editable' };
  let r = el.getBoundingClientRect();
  if (checks.includes('stable')) { await frame(); await frame(); const r2 = el.getBoundingClientRect(); if (r.x !== r2.x || r.y !== r2.y || r.width !== r2.width || r.height !== r2.height) return { ok: false, reason: 'not stable (animating)' }; r = r2; }
  const x = r.x + r.width / 2, y = r.y + r.height / 2;
  if (checks.includes('receives')) {
    const top = el.ownerDocument.elementFromPoint(x, y);
    if (top && top !== el && !el.contains(top) && !top.contains(el) && !(el.labels && [...el.labels].some(l => l.contains(top)))) {
      const dlg = top.closest('[role=dialog],dialog,[role=alertdialog]'), cover = dlg || top;
      return { ok: false, reason: `covered by ${roleName(cover) || cover.tagName.toLowerCase()}`, cover: dlg ? T.locatorFor(dlg) : null };
    }
  }
  let fx = 0, fy = 0;
  try { for (let w = el.ownerDocument.defaultView; w && w !== window.top && w.frameElement; w = w.parent) { const fr = w.frameElement.getBoundingClientRect(); fx += fr.x + w.frameElement.clientLeft; fy += fr.y + w.frameElement.clientTop; } } catch (e) {}
  return { ok: true, x: x + fx, y: y + fy };
};
T.focusSelect = ref => { const el = T.refs.get(ref); el.focus(); if (el.select) el.select(); else if (el.isContentEditable) { const r = document.createRange(); r.selectNodeContents(el); const s = getSelection(); s.removeAllRanges(); s.addRange(r); } return true; };
T.selectOption = (ref, label) => {
  const el = T.refs.get(ref);
  const opt = [...el.options].find(o => lower(o.label) === lower(label) || o.value === label) || [...el.options].find(o => lower(o.label).includes(lower(label)));
  if (!opt) return { ok: false, options: [...el.options].map(o => o.label) };
  el.value = opt.value; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true }));
  return { ok: true, value: opt.label };
};
T.scrollTo = loc => { const el = T.query(loc)[0]; if (el) el.scrollIntoView({ block: 'center' }); return !!el; };
// aria snapshot (Playwright syntax). `all` keeps every named node; otherwise interactive + landmarks + structure.
T.tree = (rootEl, all) => {
  const keep = r => r && (all || INTERACTIVE.includes(r) || LANDMARK.includes(r) || STRUCT.includes(r));
  const walk = el => {
    if (el.nodeType === 3) { const t = norm(el.textContent); return t && el.parentElement && T.visible(el.parentElement) ? [{ role: 'text', name: '', text: t, children: [] }] : []; }
    if (el.nodeType !== 1) return [];
    if (!T.visible(el) && el.tagName !== 'OPTION') return [];
    const kids = [];
    const mixed = el.children.length > 0 && !['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'SELECT'].includes(el.tagName);
    const nodes = el.shadowRoot ? [...el.shadowRoot.children, ...el.childNodes] : mixed ? [...el.childNodes] : [...el.children];
    if (el.tagName === 'IFRAME') { try { nodes.push(...el.contentDocument.body.children); } catch (e) {} }
    for (const c of nodes) for (const k of walk(c)) {
      const last = kids[kids.length - 1];
      if (k.role === 'text' && last && last.role === 'text') last.text += ' ' + k.text; else kids.push(k);
    }
    const r = T.role(el);
    if (keep(r)) {
      const d = { role: r, name: T.name(el), ref: T.ref(el), children: kids };
      const st = T.describe(el); const s = [];
      if (r === 'heading') s.push(`level=${st.level}`);
      ['checked', 'disabled', 'expanded', 'invalid'].forEach(k => st[k] && s.push(k)); if (st.focused) s.push('active');
      d.states = s;
      if (['textbox', 'searchbox', 'combobox', 'spinbutton'].includes(r) && st.value) d.value = st.value;
      if (!kids.length && !d.name && !INTERACTIVE.includes(r)) { const t = text(el); if (t) d.text = t; }
      return [d];
    }
    if (!kids.length && el.children.length === 0 && !['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE'].includes(el.tagName)) {
      const t = text(el); if (t) return [{ role: 'text', name: '', text: t, children: [] }];
    }
    return kids;
  };
  return walk(rootEl);
};
const yamlLines = (nodes, depth, opts, out) => {
  const MAXKIDS = opts.all ? 1e9 : 12;
  nodes.slice(0, MAXKIDS).forEach(n => {
    if (out.length >= opts.max) return;
    const pad = '  '.repeat(depth);
    if (n.role === 'text') { out.push(`${pad}- text: ${q(n.text.slice(0, 80))}`); return; }
    let line = `${pad}- ${n.role}${n.name ? ' ' + q(n.name.slice(0, 80)) : ''}${n.states.map(s => ` [${s}]`).join('')}${opts.refs ? ` [ref=e${n.ref}]` : ''}`;
    const deeper = opts.depth == null || depth + 1 < opts.depth;
    if (n.children.length && deeper) { out.push(line + ':'); yamlLines(n.children, depth + 1, opts, out); }
    else if (n.value) out.push(`${line}: ${q(n.value)}`);
    else if (n.text) out.push(`${line}: ${q(n.text.slice(0, 80))}`);
    else out.push(line);
  });
  if (nodes.length > MAXKIDS) out.push(`${'  '.repeat(depth)}- text: "… ${nodes.length - MAXKIDS} more (snapshot --all)"`);
};
T.snapshot = (loc, opts) => {
  const roots = loc ? T.query(loc) : [document.body];
  if (loc && !roots.length) return { yaml: '', tree: [], missing: true };
  const tree = roots.flatMap(r => { const t = T.tree(r, opts.all); const role = T.role(r); return loc && role ? [{ role, name: T.name(r), ref: T.ref(r), states: [], children: t.length === 1 && t[0].ref === T.ref(r) ? t[0].children : t }] : t; });
  const out = []; yamlLines(tree, 0, { ...opts, max: opts.max || 150 }, out);
  if (out.length >= (opts.max || 150)) out.push('- text: "… truncated (snapshot --all)"');
  return { yaml: out.join('\n'), tree };
};
// semantic summary used for step-report diffs
T.summary = () => {
  const out = new Set();
  for (const el of deepAll(document)) {
    const r = T.role(el);
    if (!r || !(LANDMARK.includes(r) || ['heading', 'alert', 'status', 'table', 'dialog', 'alertdialog', 'button', 'link', 'textbox', 'checkbox', 'radio', 'switch', 'combobox', 'tab', 'listitem', 'row'].includes(r)) || !T.visible(el)) continue;
    const n = T.name(el); if (['button', 'link'].includes(r) && !n) continue;
    const st = (el.checked || el.getAttribute('aria-checked') === 'true') ? ' [checked]' : (el.getAttribute('aria-expanded') === 'true' || (el.tagName === 'SUMMARY' && el.parentElement.open)) ? ' [expanded]' : '';
    out.add((n ? `${r} ${q(n.slice(0, 60))}` : r) + st);
    if (out.size > 400) break;
  }
  return [...out];
};
T.find = needle => deepAll(document).filter(el => T.visible(el) && (lower(T.name(el)).includes(lower(needle)) || (el.children.length === 0 && lower(text(el)).includes(lower(needle))))).slice(0, 20).map(el => ({ locator: T.locatorFor(el), role: T.role(el), name: T.name(el) || text(el).slice(0, 60) }));
T.a11y = loc => {
  const roots = loc ? T.query(loc) : [document.body], v = [];
  for (const root of roots) for (const el of deepAll(root)) {
    if (!T.visible(el)) continue;
    const r = T.role(el), n = T.name(el), d = T.locatorFor;
    if (el.tagName === 'IMG' && !el.hasAttribute('alt')) v.push({ rule: 'image-alt', target: d(el) });
    else if (['button', 'link'].includes(r) && !n) v.push({ rule: `${r}-name`, target: d(el) });
    else if (isField(el) && !fieldNames(el).length) v.push({ rule: 'label', target: d(el) });
  }
  const ids = {}; document.querySelectorAll('[id]').forEach(e => ids[e.id] = (ids[e.id] || 0) + 1);
  Object.entries(ids).filter(([, c]) => c > 1).forEach(([id]) => v.push({ rule: 'duplicate-id', target: `<#${id}/>` }));
  if (!document.documentElement.lang) v.push({ rule: 'html-lang', target: '<html/>' });
  return v;
};
// measure milestones: last DOM mutation time relative to start
T.measureStart = () => { T.m = { t0: performance.now(), dom: 0, shift: 0 }; if (T.mo) T.mo.disconnect(); T.mo = new MutationObserver(() => T.m.dom = performance.now() - T.m.t0); T.mo.observe(document, { subtree: true, childList: true, attributes: true, characterData: true }); return true; };
T.measureRead = () => ({ ...(T.m || {}), now: T.m ? performance.now() - T.m.t0 : 0 });
try {
  new PerformanceObserver(l => { for (const e of l.getEntries()) { T.perf.lcp = e.startTime; T.perf.lcpAt = performance.now(); } }).observe({ type: 'largest-contentful-paint', buffered: true });
  new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) { T.perf.cls += e.value; if (T.m) T.m.shift = performance.now() - T.m.t0; } }).observe({ type: 'layout-shift', buffered: true });
  new PerformanceObserver(l => { for (const e of l.getEntries()) if (e.interactionId) T.perf.inp = Math.max(T.perf.inp, e.duration); }).observe({ type: 'event', buffered: true, durationThreshold: 16 });
  new PerformanceObserver(l => { for (const e of l.getEntries()) T.perf.long.push(e.duration); }).observe({ type: 'longtask', buffered: true });
} catch (e) {}
T.vitals = () => {
  const nav = performance.getEntriesByType('navigation')[0] || {}, fcp = performance.getEntriesByName('first-contentful-paint')[0];
  return { lcp: T.perf.lcp, lcpAge: performance.now() - T.perf.lcpAt, cls: +T.perf.cls.toFixed(4), inp: T.perf.inp, fcp: fcp ? fcp.startTime : null, ttfb: nav.responseStart || null, long: T.perf.long, ready: document.readyState };
};
})();
