/* Dactyloscope — report renderer, used by the probe page once the analysis is back. */
(function () {
  'use strict';
  var L = window.Dacty = {};
  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) { if (k === 'class') el.className = attrs[k]; else if (k === 'text') el.textContent = attrs[k]; else if (k === 'html') el.innerHTML = attrs[k]; else el.setAttribute(k, attrs[k]); }
    (children || []).forEach(function (c) { if (c == null) return; el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return el;
  }
  L.h = h;
  function fmt(v) {
    if (v === null || v === undefined) return '—';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(+v.toFixed(6));
    if (typeof v === 'string') return v;
    if (Array.isArray(v)) { if (v.every(function (x) { return typeof x !== 'object' || x === null; })) return v.map(fmt).join(', '); return JSON.stringify(v); }
    return JSON.stringify(v);
  }
  L.fmt = fmt;
  function cell(v) {
    var td = h('td'); var s = fmt(v);
    if (v === true) td.className = 'ok'; else if (v === false) td.className = 'warn';
    if (s.length > 900) { var d = h('details', null, [h('summary', { text: s.slice(0, 120) + '… (' + s.length + ' chars)' }), h('pre', { text: s })]); td.appendChild(d); } else td.textContent = s;
    return td;
  }
  function kv(obj, opts) {
    opts = opts || {}; var t = h('table', { class: 'kv' });
    var keys = opts.keys || Object.keys(obj || {}).filter(function (k) { return k.indexOf('__') !== 0; });
    keys.forEach(function (k) {
      if (!(k in obj)) return;
      var v = obj[k];
      if (opts.skipObjects && v && typeof v === 'object' && !Array.isArray(v)) return;
      t.appendChild(h('tr', null, [h('th', { text: (opts.labels && opts.labels[k]) || k }), cell(v)]));
    });
    return t;
  }
  L.kv = kv;
  function section(title, n, node, open) { var d = h('details', { class: 'section' }, [h('summary', null, [title, n != null ? h('span', { class: 'n', text: n }) : null]), node]); if (open) d.open = true; return d; }

  // ---------------------------------------------------------------- verdict
  function renderVerdict(r) {
    var a = r.analysis || {}; var score = a.score == null ? 0 : a.score; var verdict = a.verdict || (r.done ? 'unknown' : 'pending');
    var meter = h('div', { class: 'meter' }, [h('div', { class: 'track' }), h('div', { class: 'ticks' }, ['0', '10', '40', '100'].map(function (t) { return h('span', { text: t }); }))]);
    var needle = h('div', { class: 'needle', 'data-score': score }); needle.style.left = Math.min(100, score) + '%'; meter.appendChild(needle);
    var c = a.counts || {};
    var counts = h('div', { class: 'counts' }, [h('span', { class: 'fail' }, [h('b', { text: c.fail || 0 }), ' failing']), h('span', { class: 'warn' }, [h('b', { text: c.warn || 0 }), ' warnings']), h('span', { class: 'info' }, [h('b', { text: c.info || 0 }), ' notes'])]);
    var words = { clean: 'Looks like a real browser', suspicious: 'Some things give it away', automated: 'Detectable as automated or spoofed', pending: 'Probes still running' };
    return h('div', { class: 'verdict' }, [
      h('div', null, [h('div', { class: 'word ' + verdict, text: verdict }), h('div', { class: 'sub', text: words[verdict] || '' })]),
      h('div', null, [meter, counts])
    ]);
  }
  function tri(state, okText, badText, unkText) { return h('span', { class: state === true ? 'ok' : state === false ? 'bad' : 'unk', text: state === true ? okText : state === false ? badText : unkText }); }
  function renderLedger(r) {
    var a = r.analysis || {}; var id = a.identity || {}; var cl = id.claimed || {}; var net = r.network || {};
    var fam = cl.family || '?'; var tlsFam = { chrome: 'chrome', edge: 'chrome', opera: 'chrome', firefox: 'firefox' }[fam];
    var tlsM = (net.tls || {}).match || {}; var h2M = (net.h2 || {}).match || {}; var httpM = (net.http || {}).match || {};
    var tlsState = !net.tls || !net.tls.shape ? null : tlsM.known ? (tlsFam ? tlsM.closest_family === tlsFam : true) : false;
    var h2State = net.http_version !== '2' ? null : h2M.known ? (tlsFam ? h2M.closest_family === tlsFam : true) : false;
    var httpState = httpM.reference ? !(httpM.differences || []).length : null;
    var eng = id.js_engine; var engState = eng && cl.engine ? eng === cl.engine : null;
    return h('div', { class: 'ledger' }, [
      h('div', null, [h('div', { class: 'k', text: 'Claims to be' }), h('div', { class: 'v', text: cap(fam) + (cl.major ? ' ' + cl.major : '') + ' on ' + cap(cl.os || '?') })]),
      h('div', null, [h('div', { class: 'k', text: 'TLS ClientHello' }), h('div', { class: 'v' }, [tri(tlsState, tlsM.closest || 'matches', tlsM.closest ? 'closest ' + tlsM.closest : 'no match', net.tls && net.tls.shape ? 'unknown' : 'not captured')])]),
      h('div', null, [h('div', { class: 'k', text: 'HTTP/2 preface' }), h('div', { class: 'v' }, [tri(h2State, h2M.closest || 'matches', h2M.closest ? 'closest ' + h2M.closest : 'no match', net.http_version === '2' ? 'unknown' : 'HTTP/' + (net.http_version || '1.1'))])]),
      h('div', null, [h('div', { class: 'k', text: 'Navigation headers' }), h('div', { class: 'v' }, [tri(httpState, 'match ' + cap(httpM.reference || ''), (httpM.differences || []).length + ' deviations from ' + cap(httpM.reference || ''), 'no reference')])]),
      h('div', null, [h('div', { class: 'k', text: 'JavaScript engine' }), h('div', { class: 'v' }, [tri(engState, eng || '', (eng || '?') + ', expected ' + (cl.engine || '?'), eng || (r.done ? 'undetermined' : 'pending'))])])
    ]);
  }
  function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }

  // --------------------------------------------------------------- findings
  function renderFindings(r) {
    var fs = (r.analysis || {}).findings || [];
    if (!fs.length) return h('div', { class: 'empty', text: r.done ? 'No findings.' : 'Waiting for the probes…' });
    var ul = h('ul', { class: 'findings' });
    fs.forEach(function (f) {
      var li = h('li', { class: f.severity }, [h('span', { class: 'glyph', text: f.severity === 'fail' ? '✕' : f.severity === 'warn' ? '!' : '·' })]);
      var msg = h('div', { class: 'msg' }, [f.message, h('span', { class: 'id', text: f.id })]);
      if (f.evidence != null && f.evidence !== '') msg.appendChild(h('details', null, [h('summary', { text: 'evidence' }), h('pre', { text: typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 1) })]));
      li.appendChild(msg); ul.appendChild(li);
    });
    return ul;
  }

  // ---------------------------------------------------------------- network
  function seq(list, opts) {
    var d = h('div', { class: 'seq' });
    (list || []).forEach(function (x) { var s = typeof x === 'object' ? x : { id: x }; var label = s.name && s.name !== '?' && s.name !== 'GREASE' ? s.name + ' (' + s.id + ')' : String(s.id); if (s.len != null && opts && opts.len) label += ' ·' + s.len; d.appendChild(h('span', { class: s.id === 'GREASE' ? 'grease' : '', text: label })); });
    return d;
  }
  function renderTls(tls) {
    if (!tls) return h('p', { class: 'muted', text: 'No TLS on this connection (plain HTTP). Use the https port to fingerprint the ClientHello.' });
    if (tls.error) return h('p', { class: 'muted', text: tls.error });
    var d = tls.decoded || {}; var m = tls.match || {}; var wrap = h('div');
    wrap.appendChild(kv({
      'JA3': tls.ja3 && tls.ja3.hash, 'JA3 raw': tls.ja3 && tls.ja3.raw, 'JA3n (sorted extensions)': tls.ja3n && tls.ja3n.hash,
      'JA4': tls.ja4 && tls.ja4.hash, 'JA4_r': tls.ja4 && tls.ja4.raw, 'JA4_o (original order)': tls.ja4 && tls.ja4.original,
      'Match': m.known ? 'exact: ' + (m.exact_matches || []).join(', ') : 'closest ' + m.closest + (m.differences && m.differences.length ? ' — ' + m.differences.join('; ') : ''),
      'Negotiated': tls.negotiated ? tls.negotiated.version + ', ' + tls.negotiated.cipher + ', ALPN ' + tls.negotiated.alpn : null,
      'Versions offered': d.offered_versions, 'SNI': d.sni, 'Record length': d.record_len, 'Session id length': d.session_id_len,
      'GREASE': d.grease ? 'ciphers ' + d.grease.ciphers + ', extensions ' + d.grease.extensions + ', groups ' + d.grease.groups + ', versions ' + d.grease.versions : null,
      'Certificate compression': d.compress_cert, 'PSK modes': d.psk_modes, 'EC point formats': d.ec_point_formats, 'trust_anchors body': d.trust_anchors_len != null ? d.trust_anchors_len + ' bytes' : null
    }));
    wrap.appendChild(h('h3', { text: 'Cipher suites (' + (d.ciphers || []).length + ')' })); wrap.appendChild(seq(d.ciphers));
    wrap.appendChild(h('h3', { text: 'Extensions in wire order (' + (d.extensions || []).length + ')' })); wrap.appendChild(seq(d.extensions, { len: true }));
    wrap.appendChild(h('h3', { text: 'Supported groups' })); wrap.appendChild(seq(d.groups));
    wrap.appendChild(h('h3', { text: 'Key shares' })); wrap.appendChild(seq((d.key_shares || []).map(function (k) { return { id: k.group, name: '', len: k.len }; }), { len: true }));
    wrap.appendChild(h('h3', { text: 'Signature algorithms' })); wrap.appendChild(seq(d.sigalgs));
    wrap.appendChild(h('h3', { text: 'ALPN' })); wrap.appendChild(seq(d.alpn));
    return wrap;
  }
  function renderH2(net) {
    var h2 = net.h2;
    if (net.http_version !== '2') return h('p', { class: 'muted', text: 'The request came over HTTP/' + (net.http_version || '1.1') + ', so there is no HTTP/2 preface to fingerprint.' });
    if (!h2) return h('p', { class: 'muted', text: 'HTTP/2 preface not captured.' });
    var m = h2.match || {}; var wrap = h('div');
    wrap.appendChild(kv({
      'Akamai fingerprint': h2.akamai_fingerprint, 'Match': m.known ? 'exact: ' + (m.exact_matches || []).join(', ') : 'closest ' + m.closest + ' — ' + (m.differences || []).join('; '),
      'SETTINGS': (h2.settings || []).map(function (s) { return s.name + '=' + s.value; }).join(', '), 'WINDOW_UPDATE': h2.window_update, 'PRIORITY frames': (h2.priority_frames || []).length,
      'Pseudo-header order': h2.pseudo_header_order, 'First HEADERS': h2.first_headers ? 'stream ' + h2.first_headers.stream + ', flags ' + h2.first_headers.flags + (h2.first_headers.weight ? ', weight ' + h2.first_headers.weight + (h2.first_headers.exclusive ? ' exclusive' : '') + ' dep ' + h2.first_headers.dep : '') : null,
      'Frame sequence': (h2.frame_sequence || []).join(' → ')
    }));
    return wrap;
  }
  function renderHttp(http) {
    if (!http) return h('p', { class: 'muted', text: 'No request recorded.' });
    var wrap = h('div'); var m = http.match || {};
    var t = h('table', { class: 'kv' });
    (http.headers || []).forEach(function (kvp) { t.appendChild(h('tr', null, [h('th', { text: kvp[0] }), cell(kvp[1])])); });
    wrap.appendChild(kv({ 'Request': http.method + ' ' + http.path + ' HTTP/' + http.version, 'Reference': m.reference ? cap(m.reference) + (m.differences && m.differences.length ? ': ' + m.differences.length + ' deviations' : ': matches') : 'none for this UA' }));
    if (m.differences && m.differences.length) { var ul = h('ul'); m.differences.forEach(function (d) { ul.appendChild(h('li', null, [h('b', { text: d.what + ': ' }), 'observed ', h('code', { text: fmt(d.observed) }), ', expected ', h('code', { text: fmt(d.expected) })])); }); wrap.appendChild(ul); }
    wrap.appendChild(h('h3', { text: 'Headers in wire order' })); wrap.appendChild(t);
    return wrap;
  }
  function renderRequests(reqs) {
    if (!reqs || !reqs.length) return h('p', { class: 'muted', text: 'No subresource requests recorded.' });
    var seen = {}; var t = h('table', { class: 'list' }); t.appendChild(h('tr', null, [h('th', { text: 'Request' }), h('th', { text: 'Accept' }), h('th', { text: 'Sec-Fetch' }), h('th', { text: 'Header names' })]));
    reqs.forEach(function (q) {
      var hd = {}; (q.headers || []).forEach(function (p) { hd[p[0].toLowerCase()] = p[1]; });
      var key = q.method + ' ' + q.path.replace(/\/[^/]+$/, '/*') + '|' + (q.headers || []).map(function (p) { return p[0]; }).join(','); if (seen[key]) return; seen[key] = 1;
      t.appendChild(h('tr', null, [h('td', { class: 'mono', text: q.method + ' ' + q.path + ' (h' + (q.http_version || '1') + ')' }), h('td', { class: 'mono', text: hd.accept || '' }), h('td', { class: 'mono', text: [hd['sec-fetch-site'], hd['sec-fetch-mode'], hd['sec-fetch-dest']].filter(Boolean).join(' / ') }), h('td', { class: 'mono', text: (q.headers || []).map(function (p) { return p[0]; }).filter(function (n) { return n[0] !== ':'; }).join(', ') })]));
    });
    return t;
  }

  // ------------------------------------------------------------------ probes
  var PROBE_TITLES = { navigator: 'Navigator', uadata: 'User-Agent Client Hints (JS)', screen: 'Screen and window', timezone: 'Time zone and locale', document: 'Document', engine: 'Engine tells', apis: 'API surface', automation: 'Automation artefacts', integrity: 'Native function integrity', canvas: 'Canvas', webgl: 'WebGL', audio: 'Audio', fonts: 'Fonts', permissions: 'Permissions', media: 'Media, devices and WebRTC', worker: 'Worker scope', iframe: 'Fresh iframe', storage: 'Storage', timing: 'Timing' };
  var PROBE_ORDER = ['navigator', 'uadata', 'engine', 'apis', 'automation', 'integrity', 'screen', 'timezone', 'canvas', 'webgl', 'audio', 'fonts', 'worker', 'iframe', 'permissions', 'media', 'storage', 'document', 'timing'];
  function renderProbe(name, data) {
    if (!data) return h('p', { class: 'muted', text: 'not collected' });
    if (data.__error__) return h('p', { class: 'bad', text: 'probe threw: ' + data.__error__ });
    var wrap = h('div');
    if (name === 'apis') {
      var on = [], off = []; Object.keys(data).forEach(function (k) { if (k.indexOf('__') === 0) return; (data[k] ? on : off).push(k); });
      wrap.appendChild(h('p', { class: 'small muted', text: on.length + ' of ' + (on.length + off.length) + ' probed APIs present. Hash ' + data.__hash }));
      wrap.appendChild(h('h3', { text: 'Present' })); wrap.appendChild(h('div', { class: 'tags' }, on.map(function (k) { return h('span', { class: 'tag on', text: k }); })));
      wrap.appendChild(h('h3', { text: 'Absent' })); wrap.appendChild(h('div', { class: 'tags' }, off.map(function (k) { return h('span', { class: 'tag off', text: k }); })));
      return wrap;
    }
    if (name === 'integrity') {
      wrap.appendChild(kv({ 'Function.prototype.toString native': data.toStringNative, 'checked': data.checked, 'lies': data.lies }));
      var t = h('table', { class: 'list' }); t.appendChild(h('tr', null, [h('th', { text: 'API' }), h('th', { text: 'native' }), h('th', { text: 'own toString' }), h('th', { text: 'prototype' }), h('th', { text: 'proxy' }), h('th', { text: 'name/length' }), h('th', { text: 'new fn()' })]));
      (data.checks || []).forEach(function (c) { var bad = c.native === false || c.own || c.hasPrototype || c.proxy; t.appendChild(h('tr', { class: bad ? 'bad' : '' }, [h('td', { class: 'mono', text: c.path }), cell(c.present ? c.native : 'absent'), cell(c.own), cell(c.hasPrototype), cell(c.proxy), h('td', { class: 'mono', text: c.present ? c.name + '/' + c.length : '' }), h('td', { class: 'mono', text: c.constructorErr || '' })])); });
      wrap.appendChild(t); return wrap;
    }
    if (name === 'fonts') {
      wrap.appendChild(kv({ 'detected': data.count + ' of ' + data.tested, 'method': data.method, 'hash': data.hash, 'document.fonts': data.fontsApi, 'queryLocalFonts': data.localFonts }));
      wrap.appendChild(h('div', { class: 'tags' }, (data.detected || []).map(function (f) { return h('span', { class: 'tag on', text: f }); }))); return wrap;
    }
    if (name === 'webgl' && data.supported) {
      wrap.appendChild(kv(data, { keys: ['vendor', 'renderer', 'unmaskedVendor', 'unmaskedRenderer', 'version', 'slVersion', 'webgl2', 'webgl2Version', 'renderHash', 'renderHash2', 'extHash', 'paramHash', 'getParameterNative', 'contextAttributes'] }));
      wrap.appendChild(h('h3', { text: 'Extensions (' + (data.extensions || []).length + ')' })); wrap.appendChild(h('div', { class: 'tags' }, (data.extensions || []).map(function (f) { return h('span', { class: 'tag', text: f }); })));
      wrap.appendChild(h('h3', { text: 'Parameters' })); wrap.appendChild(kv(data.params || {}));
      if (data.webgl2Params) { wrap.appendChild(h('h3', { text: 'WebGL2 parameters' })); wrap.appendChild(kv(data.webgl2Params)); }
      wrap.appendChild(h('h3', { text: 'Shader precision' })); wrap.appendChild(kv(data.precision || {})); return wrap;
    }
    if (name === 'engine') {
      wrap.appendChild(kv(data, { skipObjects: true }));
      wrap.appendChild(h('h3', { text: 'Error messages' })); wrap.appendChild(kv(data.errors || {}));
      wrap.appendChild(h('h3', { text: 'Math' })); wrap.appendChild(kv(data.math || {}));
      wrap.appendChild(h('h3', { text: 'CSS support' })); wrap.appendChild(kv(Object.assign({}, data.css || {}, data.styleProps || {}))); return wrap;
    }
    if (name === 'navigator') {
      wrap.appendChild(kv(data, { skipObjects: true, keys: Object.keys(data).filter(function (k) { return k !== 'protoNames' && k !== 'ownNames'; }) }));
      ['connection', 'userAgentData', 'webdriverDescriptor'].forEach(function (k) { if (data[k]) { wrap.appendChild(h('h3', { text: k })); wrap.appendChild(kv(data[k])); } });
      wrap.appendChild(h('h3', { text: 'Navigator.prototype (' + (data.protoNames || []).length + ')' })); wrap.appendChild(h('div', { class: 'tags' }, (data.protoNames || []).map(function (f) { return h('span', { class: 'tag', text: f }); })));
      return wrap;
    }
    // generic: flat values first, nested objects as sub-tables
    wrap.appendChild(kv(data, { skipObjects: true }));
    Object.keys(data).forEach(function (k) { var v = data[k]; if (v && typeof v === 'object' && !Array.isArray(v) && k.indexOf('__') !== 0) { wrap.appendChild(h('h3', { text: k })); wrap.appendChild(kv(v)); } });
    return wrap;
  }

  // ------------------------------------------------------------------ report
  L.renderReport = function (root, r) {
    root.innerHTML = '';
    var net = r.network || {}; var http = net.http || {};
    root.appendChild(h('h1', { text: r.label || 'Report' }));
    root.appendChild(h('p', { class: 'lede' }, [
      (r.created || '') + (r.client ? ' from ' + r.client.ip : '') + ' over ' + (net.scheme || 'http') + ' (HTTP/' + (net.http_version || '1.1') + ')' + (r.probe_ms ? ', probes took ' + Math.round(r.probe_ms / 100) / 10 + ' s' : ''),
      h('br'), h('span', { class: 'mono small', text: http.user_agent || '(no User-Agent)' })
    ]));
    root.appendChild(renderVerdict(r));
    root.appendChild(renderLedger(r));
    var id = (r.analysis || {}).identity || {};
    if (id.js_engine_evidence && id.js_engine_evidence.length) root.appendChild(h('p', { class: 'small muted', text: 'Engine evidence: ' + id.js_engine_evidence.join('; ') }));
    // The server keeps nothing, so the download is the only copy of this report.
    var url = URL.createObjectURL(new Blob([JSON.stringify(r, null, 1)], { type: 'application/json' }));
    var stamp = (r.created || '').replace(/[^0-9]/g, '').slice(0, 14);
    var bar = h('div', { class: 'bar' }, [
      h('a', { class: 'btn', href: url, download: 'dactyloscope-' + (stamp || 'report') + '.json', text: 'Download JSON' }),
      h('a', { class: 'btn', href: '/', text: 'Run again' })
    ]);
    root.appendChild(bar);
    root.appendChild(h('h2', null, ['Findings', h('small', { text: 'what a detector would notice' })]));
    root.appendChild(renderFindings(r));
    root.appendChild(h('h2', null, ['Wire', h('small', { text: 'seen before any JavaScript ran' })]));
    root.appendChild(section('TLS ClientHello', net.tls && net.tls.ja3 ? 'JA3 ' + net.tls.ja3.hash + ', JA4 ' + net.tls.ja4.hash : null, renderTls(net.tls), true));
    root.appendChild(section('HTTP/2 preface', net.h2 ? net.h2.akamai_fingerprint : null, renderH2(net), true));
    root.appendChild(section('Navigation request headers', (http.headers || []).length + ' headers', renderHttp(http), true));
    root.appendChild(section('Subresource requests', (net.requests || []).length + ' seen', renderRequests(net.requests)));
    root.appendChild(h('h2', null, ['In-page probes', h('small', { text: Object.keys(r.probes || {}).length + ' sections' })]));
    var probes = r.probes || {};
    PROBE_ORDER.concat(Object.keys(probes).filter(function (k) { return PROBE_ORDER.indexOf(k) < 0; })).forEach(function (name) {
      if (!(name in probes) && !(r.probe_errors && name in r.probe_errors)) return;
      var data = probes[name] || { __error__: r.probe_errors[name] };
      var sub = null;
      if (name === 'canvas' && data.hash1) sub = data.hash1 + (data.uniform && data.uniform.mismatched ? ', noise' : '');
      if (name === 'webgl') sub = data.unmaskedRenderer || data.renderer || (data.supported === false ? 'unsupported' : null);
      if (name === 'audio') sub = data.fingerprint != null ? String(data.fingerprint) : (data.supported === false ? 'unsupported' : null);
      if (name === 'fonts') sub = data.count + ' fonts';
      if (name === 'apis') sub = data.__count + ' present';
      if (name === 'integrity') sub = data.lies + ' lies';
      if (name === 'timezone') sub = data.iana + ' (' + data.offsetNow + ')';
      if (name === 'screen') sub = data.width + '×' + data.height + ' @' + data.dpr;
      if (name === 'worker') sub = data.ok ? 'ok' : 'unavailable';
      root.appendChild(section(PROBE_TITLES[name] || name, sub, renderProbe(name, data)));
    });
    root.appendChild(h('h2', null, ['Raw JSON']));
    var pre = h('pre', { class: 'json', text: JSON.stringify(r, null, 1) });
    root.appendChild(section('Full report', Math.round(pre.textContent.length / 1024) + ' KB', pre));
  };

  L.topbar = function () {
    return h('div', { class: 'top' }, [h('a', { class: 'brand', href: '/', html: '<img src="/static/logo.svg" alt="">Dactyloscope' })]);
  };
})();
