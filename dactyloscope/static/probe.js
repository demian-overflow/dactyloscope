/* Dactyloscope — in-page probes.
 *
 * Each section runs in isolation and never throws out of its wrapper. Results
 * stay in the page until every section is done, then go to /analyze in one
 * request together with the network seed; the server keeps nothing. Keep this file dependency-free and tolerant of missing APIs: it
 * runs inside the browser under test, which may be far from complete.
 */
(function () {
  'use strict';
  var SEED = window.__DACTY_SEED__ || {};
  var ORDER = [];
  var T0 = Date.now();
  var mouseMoved = false;
  try { window.addEventListener('mousemove', function () { mouseMoved = true; }, { once: true }); } catch (e) {}

  // ---------------------------------------------------------------- utils
  function fnv(str, seed) {
    var h = seed >>> 0;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    return h;
  }
  function hashStr(s) { return (fnv(s, 0x811c9dc5).toString(16) + fnv(s, 0x9747b28c).toString(16)); }
  function hashBytes(arr) {
    var h1 = 0x811c9dc5, h2 = 0x9747b28c;
    for (var i = 0; i < arr.length; i++) {
      h1 = Math.imul(h1 ^ arr[i], 16777619) >>> 0;
      h2 = Math.imul(h2 ^ arr[i], 0x5bd1e995) >>> 0; h2 = (h2 ^ (h2 >>> 13)) >>> 0;
    }
    return h1.toString(16) + h2.toString(16);
  }
  function safe(fn, dflt) { try { var v = fn(); return v === undefined ? (dflt === undefined ? null : dflt) : v; } catch (e) { return dflt === undefined ? null : dflt; } }
  function errStr(e) { try { return (e && e.name ? e.name + ': ' : '') + (e && e.message ? e.message : String(e)); } catch (x) { return 'error'; } }
  function get(path, root) {
    var cur = root || window; var parts = path.split('.');
    for (var i = 0; i < parts.length; i++) { if (cur === null || cur === undefined) return undefined; cur = cur[parts[i]]; }
    return cur;
  }
  function typeOf(v) { return v === null ? 'null' : typeof v; }
  var NATIVE_RE = /^function\s*(?:get |set )?[\w$]*\s*\(\)\s*\{\s*\[native code\]\s*\}$/;
  function isNative(fn) {
    if (typeof fn !== 'function') return null;
    try { return NATIVE_RE.test(Function.prototype.toString.call(fn)); } catch (e) { return false; }
  }
  function withTimeout(p, ms, dflt) {
    return new Promise(function (resolve) {
      var done = false; var t = setTimeout(function () { if (!done) { done = true; resolve(dflt); } }, ms);
      Promise.resolve(p).then(function (v) { if (!done) { done = true; clearTimeout(t); resolve(v); } },
        function (e) { if (!done) { done = true; clearTimeout(t); resolve({ __err: errStr(e) }); } });
    });
  }
  function post(url, body) {
    var txt; try { txt = JSON.stringify(body); } catch (e) { txt = JSON.stringify({ __error__: 'unserialisable: ' + errStr(e) }); }
    return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: txt, credentials: 'omit' });
  }
  function progress(name, state, extra) {
    try { if (window.__DACTY_PROGRESS__) window.__DACTY_PROGRESS__(name, state, extra); } catch (e) {}
  }
  var RESULTS = {};
  var ERRORS = {};
  window.__DACTY_RESULTS__ = RESULTS;
  var SECTION_TIMEOUT_MS = 15000;  // a hung probe must never leave the report unfinished
  async function section(name, fn) {
    progress(name, 'running');
    var t = Date.now(); var out;
    try {
      out = await withTimeout(Promise.resolve().then(fn), SECTION_TIMEOUT_MS, { __err: 'timeout' });
      if (out && out.__err === 'timeout') out = { __error__: 'probe did not finish within ' + SECTION_TIMEOUT_MS + ' ms' };
    } catch (e) { out = { __error__: errStr(e) }; }
    ORDER.push(name);
    if (out && out.__error__) ERRORS[name] = out.__error__; else RESULTS[name] = out;
    progress(name, out && out.__error__ ? 'error' : 'done', { ms: Date.now() - t, out: out });
  }

  // ------------------------------------------------------------ navigator
  function navigatorProbe() {
    var n = navigator; var out = {};
    ['userAgent', 'appVersion', 'appName', 'appCodeName', 'product', 'productSub', 'vendor', 'vendorSub', 'platform', 'oscpu', 'buildID',
      'language', 'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints', 'webdriver', 'doNotTrack', 'globalPrivacyControl', 'cookieEnabled',
      'onLine', 'pdfViewerEnabled'].forEach(function (k) { out[k] = safe(function () { var v = n[k]; return v === undefined ? undefined : v; }, undefined); if (out[k] === undefined) delete out[k]; });
    out.languages = safe(function () { return Array.prototype.slice.call(n.languages || []); }, []);
    out.plugins = safe(function () { return Array.prototype.map.call(n.plugins || [], function (p) { return { name: p.name, filename: p.filename, description: p.description, mimeTypes: p.length }; }); }, []);
    out.mimeTypes = safe(function () { return Array.prototype.map.call(n.mimeTypes || [], function (m) { return m.type; }); }, []);
    out.connection = safe(function () { var c = n.connection; return c ? { effectiveType: c.effectiveType, rtt: c.rtt, downlink: c.downlink, saveData: c.saveData, type: c.type } : null; });
    out.userAgentData = safe(function () { var u = n.userAgentData; return u ? { brands: u.brands, mobile: u.mobile, platform: u.platform } : null; });
    out.protoNames = safe(function () { return Object.getOwnPropertyNames(Object.getPrototypeOf(n)); }, []);
    out.protoHash = hashStr(out.protoNames.join(','));
    out.protoCount = out.protoNames.length;
    out.ownNames = safe(function () { return Object.getOwnPropertyNames(n); }, []);
    out.webdriverDescriptor = safe(function () {
      var pd = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(n), 'webdriver');
      var od = Object.getOwnPropertyDescriptor(n, 'webdriver');
      return { onProto: !!pd, onInstance: !!od, getterNative: pd && pd.get ? isNative(pd.get) : null, protoIsNavigator: Object.getPrototypeOf(n) === (window.Navigator && window.Navigator.prototype) };
    });
    out.uaGetterNative = safe(function () { var d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(n), 'userAgent'); return d && d.get ? isNative(d.get) : null; });
    return out;
  }
  async function uaDataProbe() {
    var u = navigator.userAgentData; if (!u || !u.getHighEntropyValues) return { supported: false };
    var v = await withTimeout(u.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion', 'uaFullVersion', 'fullVersionList', 'wow64', 'formFactors']), 2000, { __err: 'timeout' });
    return { supported: true, highEntropy: v, toJSON: safe(function () { return u.toJSON(); }) };
  }

  // ---------------------------------------------------------------- screen
  function screenProbe() {
    var s = window.screen || {};
    var mq = function (q) { return safe(function () { return window.matchMedia ? window.matchMedia(q).matches : null; }); };
    return {
      width: s.width, height: s.height, availWidth: s.availWidth, availHeight: s.availHeight, availLeft: s.availLeft, availTop: s.availTop,
      colorDepth: s.colorDepth, pixelDepth: s.pixelDepth, dpr: window.devicePixelRatio,
      innerWidth: window.innerWidth, innerHeight: window.innerHeight, outerWidth: window.outerWidth, outerHeight: window.outerHeight,
      screenX: window.screenX, screenY: window.screenY, screenLeft: window.screenLeft, screenTop: window.screenTop,
      orientation: safe(function () { return s.orientation ? { type: s.orientation.type, angle: s.orientation.angle } : null; }),
      isExtended: safe(function () { return s.isExtended; }),
      visualViewport: safe(function () { var v = window.visualViewport; return v ? { width: v.width, height: v.height, scale: v.scale } : null; }),
      clientSize: safe(function () { return [document.documentElement.clientWidth, document.documentElement.clientHeight]; }),
      media: {
        dark: mq('(prefers-color-scheme: dark)'), pointerFine: mq('(pointer: fine)'), pointerCoarse: mq('(pointer: coarse)'), hoverHover: mq('(hover: hover)'),
        reducedMotion: mq('(prefers-reduced-motion: reduce)'), colorGamutP3: mq('(color-gamut: p3)'), hdr: mq('(dynamic-range: high)'),
        forcedColors: mq('(forced-colors: active)'), contrastMore: mq('(prefers-contrast: more)'), standalone: mq('(display-mode: standalone)'),
        anyHover: mq('(any-hover: hover)'), anyPointerFine: mq('(any-pointer: fine)')
      },
      fullscreenEnabled: safe(function () { return document.fullscreenEnabled; }),
      devicePosture: safe(function () { return navigator.devicePosture ? navigator.devicePosture.type : null; })
    };
  }

  // -------------------------------------------------------------- timezone
  function timezoneProbe() {
    var d = new Date(); var jan = new Date(d.getFullYear(), 0, 1), jul = new Date(d.getFullYear(), 6, 1);
    var ro = safe(function () { return Intl.DateTimeFormat().resolvedOptions(); }, {});
    return {
      iana: ro.timeZone || null, offsetNow: d.getTimezoneOffset(), offsetJan: jan.getTimezoneOffset(), offsetJul: jul.getTimezoneOffset(),
      dateString: d.toString(), dateTimeString: safe(function () { return d.toLocaleTimeString(); }),
      intlLocale: ro.locale || null, calendar: ro.calendar, numberingSystem: ro.numberingSystem, hourCycle: ro.hourCycle || null, hour12: ro.hour12,
      numberLocale: safe(function () { return Intl.NumberFormat().resolvedOptions().locale; }),
      numberSample: safe(function () { return (1234567.891).toLocaleString(); }),
      dateSample: safe(function () { return new Date(2020, 0, 31, 13, 5, 7).toLocaleString(); }),
      dateSampleUS: safe(function () { return new Date(2020, 0, 31, 13, 5, 7).toLocaleString('en-US'); }),
      currencySample: safe(function () { return (1234.5).toLocaleString(undefined, { style: 'currency', currency: 'EUR' }); }),
      collation: safe(function () { return Intl.Collator().resolvedOptions().locale; }),
      pluralRules: safe(function () { return Intl.PluralRules().resolvedOptions().locale; }),
      relativeTime: safe(function () { return new Intl.RelativeTimeFormat().format(-1, 'day'); }),
      longOffset: safe(function () { return Intl.DateTimeFormat('en', { timeZoneName: 'longOffset' }).formatToParts(d).filter(function (p) { return p.type === 'timeZoneName'; })[0].value; }),
      tzName: safe(function () { return Intl.DateTimeFormat('en', { timeZoneName: 'long' }).formatToParts(d).filter(function (p) { return p.type === 'timeZoneName'; })[0].value; }),
      supportedTzCount: safe(function () { return Intl.supportedValuesOf ? Intl.supportedValuesOf('timeZone').length : null; }),
      dateParse: safe(function () { return [Date.parse('2020-01-01T00:00:00'), Date.parse('2020-01-01'), Date.parse('Jan 1, 2020')]; })
    };
  }

  // ---------------------------------------------------------------- canvas
  function drawScene(ctx, w, h) {
    ctx.fillStyle = '#f60'; ctx.fillRect(10, 10, 80, 50);
    ctx.fillStyle = '#069'; ctx.font = '11pt Arial'; ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)'; ctx.font = '18pt Arial'; ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 4, 45);
    ctx.globalCompositeOperation = 'multiply';
    ctx.fillStyle = 'rgb(255,0,255)'; ctx.beginPath(); ctx.arc(50, 50, 50, 0, Math.PI * 2, true); ctx.closePath(); ctx.fill();
    ctx.fillStyle = 'rgb(0,255,255)'; ctx.beginPath(); ctx.arc(100, 50, 50, 0, Math.PI * 2, true); ctx.closePath(); ctx.fill();
    ctx.fillStyle = 'rgb(255,255,0)'; ctx.beginPath(); ctx.arc(75, 100, 50, 0, Math.PI * 2, true); ctx.closePath(); ctx.fill();
    ctx.fillStyle = 'rgb(255,0,255)'; ctx.arc(75, 75, 75, 0, Math.PI * 2, true); ctx.arc(75, 75, 25, 0, Math.PI * 2, true); ctx.fill('evenodd');
    var g = ctx.createLinearGradient(0, 0, w, 0); g.addColorStop(0, 'red'); g.addColorStop(0.5, 'green'); g.addColorStop(1, 'blue');
    ctx.globalCompositeOperation = 'source-over'; ctx.fillStyle = g; ctx.fillRect(0, h - 20, w, 20);
    ctx.strokeStyle = '#333'; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(0, 0); ctx.bezierCurveTo(w / 2, h, w, 0, w, h); ctx.stroke();
    ctx.shadowBlur = 4; ctx.shadowColor = 'black'; ctx.font = 'bold 14px serif'; ctx.fillStyle = '#fff'; ctx.fillText('éàü Ж 中文 العربية', 10, h - 30);
  }
  function renderHash(canvas) {
    var w = canvas.width, h = canvas.height; var ctx = canvas.getContext('2d'); if (!ctx) return null;
    drawScene(ctx, w, h);
    var id = ctx.getImageData(0, 0, w, h).data;
    var first = id[0], allSame = true; for (var i = 0; i < id.length; i += 4) { if (id[i] !== first) { allSame = false; break; } }
    return { hash: hashBytes(id), blank: allSame, dataUrlLen: safe(function () { return canvas.toDataURL().length; }) };
  }
  function canvasProbe() {
    var c1 = document.createElement('canvas'); c1.width = 240; c1.height = 140;
    var ctx = c1.getContext('2d'); if (!ctx) return { supported: false };
    var out = { supported: true };
    var r1 = renderHash(c1); out.hash1 = r1.hash; out.blank = r1.blank; out.dataUrlLen = r1.dataUrlLen;
    var c2 = document.createElement('canvas'); c2.width = 240; c2.height = 140; var r2 = renderHash(c2); out.hash2 = r2.hash;
    out.hash3 = safe(function () { if (!window.OffscreenCanvas) return null; var oc = new OffscreenCanvas(240, 140); var r = renderHash(oc); return r ? r.hash : null; });
    out.offscreenSameSize = true;
    // Uniform fill: any deviation is injected noise.
    var c3 = document.createElement('canvas'); c3.width = 64; c3.height = 64; var x = c3.getContext('2d');
    x.fillStyle = 'rgb(127,63,31)'; x.fillRect(0, 0, 64, 64);
    var d = x.getImageData(0, 0, 64, 64).data; var mism = 0;
    for (var i = 0; i < d.length; i += 4) { if (d[i] !== 127 || d[i + 1] !== 63 || d[i + 2] !== 31 || d[i + 3] !== 255) mism++; }
    out.uniform = { pixels: d.length / 4, mismatched: mism, sample: [d[0], d[1], d[2], d[3]] };
    // A second read of the same canvas must be identical (per-read noise).
    var d2 = x.getImageData(0, 0, 64, 64).data; var rm = 0; for (i = 0; i < d.length; i++) if (d[i] !== d2[i]) rm++;
    out.uniform.rereadMismatch = rm;
    out.toDataURLNative = isNative(HTMLCanvasElement.prototype.toDataURL);
    out.getImageDataNative = isNative(CanvasRenderingContext2D.prototype.getImageData);
    out.fillTextNative = isNative(CanvasRenderingContext2D.prototype.fillText);
    out.textWidth = safe(function () { x.font = '20px Arial'; return x.measureText('Cwm fjordbank glyphs vext quiz').width; });
    out.textMetricsKeys = safe(function () { x.font = '20px Arial'; var m = x.measureText('x'); var ks = []; for (var k in m) ks.push(k); return ks; });
    // Emoji: colour emoji fonts produce many colours; tofu produces one or two.
    var c4 = document.createElement('canvas'); c4.width = 60; c4.height = 60; var e = c4.getContext('2d');
    e.fillStyle = '#fff'; e.fillRect(0, 0, 60, 60); e.font = '40px sans-serif'; e.textBaseline = 'top'; e.fillText('😃', 5, 5);
    var ed = e.getImageData(0, 0, 60, 60).data; var colors = {}; var n = 0;
    for (i = 0; i < ed.length; i += 4) { var key = (ed[i] >> 4) + ',' + (ed[i + 1] >> 4) + ',' + (ed[i + 2] >> 4); if (!colors[key]) { colors[key] = 1; n++; } }
    out.emojiColors = n; out.emojiTofu = n < 4; out.emojiWidth = safe(function () { return e.measureText('😃').width; });
    out.winding = safe(function () { x.rect(0, 0, 10, 10); x.rect(2, 2, 6, 6); return x.isPointInPath(5, 5, 'evenodd') === false; });
    out.contextAttrs = safe(function () { return ctx.getContextAttributes(); });
    return out;
  }

  // ------------------------------------------------------------------ webgl
  var GL_PARAMS = ['MAX_TEXTURE_SIZE', 'MAX_CUBE_MAP_TEXTURE_SIZE', 'MAX_RENDERBUFFER_SIZE', 'MAX_VIEWPORT_DIMS', 'MAX_VERTEX_ATTRIBS',
    'MAX_VERTEX_UNIFORM_VECTORS', 'MAX_VARYING_VECTORS', 'MAX_FRAGMENT_UNIFORM_VECTORS', 'MAX_TEXTURE_IMAGE_UNITS', 'MAX_VERTEX_TEXTURE_IMAGE_UNITS',
    'MAX_COMBINED_TEXTURE_IMAGE_UNITS', 'ALIASED_LINE_WIDTH_RANGE', 'ALIASED_POINT_SIZE_RANGE', 'RED_BITS', 'GREEN_BITS', 'BLUE_BITS', 'ALPHA_BITS',
    'DEPTH_BITS', 'STENCIL_BITS', 'SUBPIXEL_BITS', 'SAMPLE_BUFFERS', 'SAMPLES', 'MAX_ANISOTROPY'];
  var GL2_PARAMS = ['MAX_3D_TEXTURE_SIZE', 'MAX_ARRAY_TEXTURE_LAYERS', 'MAX_COLOR_ATTACHMENTS', 'MAX_DRAW_BUFFERS', 'MAX_ELEMENT_INDEX',
    'MAX_UNIFORM_BUFFER_BINDINGS', 'MAX_UNIFORM_BLOCK_SIZE', 'MAX_VERTEX_UNIFORM_COMPONENTS', 'MAX_FRAGMENT_UNIFORM_COMPONENTS', 'MAX_SAMPLES',
    'MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS', 'MAX_VERTEX_OUTPUT_COMPONENTS', 'MAX_FRAGMENT_INPUT_COMPONENTS', 'MAX_TEXTURE_LOD_BIAS'];
  function glParams(gl, names) {
    var out = {};
    names.forEach(function (n) {
      var c = gl[n]; if (n === 'MAX_ANISOTROPY') { var ext = gl.getExtension('EXT_texture_filter_anisotropic'); c = ext ? ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT : undefined; }
      if (c === undefined) return;
      var v = safe(function () { return gl.getParameter(c); }); if (v && v.length !== undefined && typeof v !== 'string') v = Array.prototype.slice.call(v);
      out[n] = v;
    });
    return out;
  }
  function glPrecision(gl) {
    var out = {}; var shaders = { vertex: gl.VERTEX_SHADER, fragment: gl.FRAGMENT_SHADER };
    var kinds = { highFloat: gl.HIGH_FLOAT, mediumFloat: gl.MEDIUM_FLOAT, lowFloat: gl.LOW_FLOAT, highInt: gl.HIGH_INT, mediumInt: gl.MEDIUM_INT, lowInt: gl.LOW_INT };
    for (var s in shaders) for (var k in kinds) { var f = safe(function () { return gl.getShaderPrecisionFormat(shaders[s], kinds[k]); }); if (f) out[s + '.' + k] = [f.rangeMin, f.rangeMax, f.precision]; }
    return out;
  }
  function glRender(gl, w, h) {
    var vs = 'attribute vec2 p;attribute vec3 c;varying vec3 v;void main(){v=c;gl_Position=vec4(p,0.0,1.0);}';
    var fs = 'precision mediump float;varying vec3 v;void main(){gl_FragColor=vec4(v*abs(sin(v.x*37.0+v.y*11.0)),1.0);}';
    function sh(t, src) { var s = gl.createShader(t); gl.shaderSource(s, src); gl.compileShader(s); return s; }
    var prog = gl.createProgram(); gl.attachShader(prog, sh(gl.VERTEX_SHADER, vs)); gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, fs)); gl.linkProgram(prog); gl.useProgram(prog);
    var buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-0.8, -0.8, 1, 0, 0, 0.8, -0.8, 0, 1, 0, 0, 0.9, 0, 0, 1, -0.3, 0.2, 1, 1, 0, 0.5, 0.5, 0, 1, 1, 0.1, -0.9, 1, 0, 1]), gl.STATIC_DRAW);
    var p = gl.getAttribLocation(prog, 'p'), c = gl.getAttribLocation(prog, 'c');
    gl.enableVertexAttribArray(p); gl.vertexAttribPointer(p, 2, gl.FLOAT, false, 20, 0);
    gl.enableVertexAttribArray(c); gl.vertexAttribPointer(c, 3, gl.FLOAT, false, 20, 8);
    gl.clearColor(0.1, 0.2, 0.3, 1); gl.clear(gl.COLOR_BUFFER_BIT); gl.drawArrays(gl.TRIANGLES, 0, 6);
    var px = new Uint8Array(w * h * 4); gl.readPixels(0, 0, w, h, gl.RGBA, gl.UNSIGNED_BYTE, px);
    return hashBytes(px);
  }
  function webglProbe() {
    var cv = document.createElement('canvas'); cv.width = 128; cv.height = 128;
    var gl = null; try { gl = cv.getContext('webgl') || cv.getContext('experimental-webgl'); } catch (e) {}
    if (!gl) return { supported: false, webgl2: safe(function () { return !!document.createElement('canvas').getContext('webgl2'); }, false) };
    var out = { supported: true };
    out.vendor = safe(function () { return gl.getParameter(gl.VENDOR); }); out.renderer = safe(function () { return gl.getParameter(gl.RENDERER); });
    out.version = safe(function () { return gl.getParameter(gl.VERSION); }); out.slVersion = safe(function () { return gl.getParameter(gl.SHADING_LANGUAGE_VERSION); });
    var dbg = safe(function () { return gl.getExtension('WEBGL_debug_renderer_info'); });
    out.unmaskedVendor = dbg ? safe(function () { return gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL); }) : null;
    out.unmaskedRenderer = dbg ? safe(function () { return gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); }) : null;
    out.extensions = safe(function () { return gl.getSupportedExtensions(); }, []);
    out.params = glParams(gl, GL_PARAMS); out.precision = glPrecision(gl);
    out.contextAttributes = safe(function () { return gl.getContextAttributes(); });
    out.renderHash = safe(function () { return glRender(gl, 128, 128); });
    out.renderHash2 = safe(function () { var c2 = document.createElement('canvas'); c2.width = 128; c2.height = 128; var g2 = c2.getContext('webgl'); return g2 ? glRender(g2, 128, 128) : null; });
    out.getParameterNative = isNative(WebGLRenderingContext.prototype.getParameter);
    out.getSupportedExtensionsNative = isNative(WebGLRenderingContext.prototype.getSupportedExtensions);
    var c3 = document.createElement('canvas'); var gl2 = null; try { gl2 = c3.getContext('webgl2'); } catch (e) {}
    out.webgl2 = !!gl2;
    if (gl2) { out.webgl2Version = safe(function () { return gl2.getParameter(gl2.VERSION); }); out.webgl2Params = glParams(gl2, GL2_PARAMS); out.webgl2Extensions = safe(function () { return gl2.getSupportedExtensions().length; }); }
    out.extHash = hashStr((out.extensions || []).join(','));
    out.paramHash = hashStr(JSON.stringify(out.params) + JSON.stringify(out.precision));
    return out;
  }

  // ------------------------------------------------------------------ audio
  async function audioProbe() {
    var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!OAC) return { supported: false, audioContext: !!(window.AudioContext || window.webkitAudioContext) };
    var out = { supported: true };
    async function run() {
      var ctx = new OAC(1, 44100, 44100);
      var osc = ctx.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      [['threshold', -50], ['knee', 40], ['ratio', 12], ['attack', 0], ['release', 0.25]].forEach(function (kv) { if (comp[kv[0]] && comp[kv[0]].value !== undefined) comp[kv[0]].value = kv[1]; });
      osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
      var buf = await withTimeout(ctx.startRendering(), 4000, null);
      if (!buf || buf.__err) return { err: buf ? buf.__err : 'timeout' };
      var d = buf.getChannelData(0); var sum = 0; for (var i = 4500; i < 5000; i++) sum += Math.abs(d[i]);
      var bytes = new Uint8Array(d.buffer, d.byteOffset, Math.min(d.byteLength, 44100 * 4));
      return { fingerprint: sum, hash: hashBytes(bytes), sampleRate: ctx.sampleRate, length: buf.length, compressor: safe(function () { return comp.reduction; }) };
    }
    var a = await run(); var b = await run();
    out.fingerprint = a.fingerprint; out.hash1 = a.hash; out.hash2 = b.hash; out.err = a.err || b.err || null; out.sampleRate = a.sampleRate; out.length = a.length;
    out.silenceNonzero = await (async function () {
      var ctx = new OAC(1, 4410, 44100); var g = ctx.createGain(); g.gain.value = 0; var osc = ctx.createOscillator(); osc.connect(g); g.connect(ctx.destination); osc.start(0);
      var buf = await withTimeout(ctx.startRendering(), 3000, null); if (!buf || buf.__err) return null;
      var d = buf.getChannelData(0); var nz = 0; for (var i = 0; i < d.length; i++) if (d[i] !== 0) nz++; return nz;
    })();
    out.getChannelDataNative = isNative(window.AudioBuffer && AudioBuffer.prototype.getChannelData);
    out.copyFromChannelNative = isNative(window.AudioBuffer && AudioBuffer.prototype.copyFromChannel);
    out.audioContext = safe(function () { var AC = window.AudioContext || window.webkitAudioContext; if (!AC) return null; var c = new AC(); var r = { sampleRate: c.sampleRate, state: c.state, baseLatency: c.baseLatency, outputLatency: c.outputLatency, maxChannels: c.destination.maxChannelCount, channelCount: c.destination.channelCount }; try { c.close(); } catch (e) {} return r; });
    return out;
  }

  // ------------------------------------------------------------------ fonts
  var FONTS = ['Arial', 'Arial Black', 'Arial Narrow', 'Bahnschrift', 'Calibri', 'Cambria', 'Cambria Math', 'Candara', 'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel',
    'Courier New', 'Ebrima', 'Franklin Gothic Medium', 'Gabriola', 'Georgia', 'Impact', 'Lucida Console', 'Lucida Sans Unicode', 'Microsoft Sans Serif', 'MS Gothic', 'MV Boli',
    'Palatino Linotype', 'Segoe Print', 'Segoe Script', 'Segoe UI', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Sylfaen', 'Symbol', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Webdings', 'Wingdings',
    'Helvetica', 'Helvetica Neue', 'Menlo', 'Monaco', 'Geneva', 'Lucida Grande', 'American Typewriter', 'Avenir', 'Avenir Next', 'Baskerville', 'Chalkboard', 'Futura', 'Gill Sans', 'Optima', 'Palatino', 'SF Pro', 'Apple Color Emoji', 'PingFang SC', 'Hiragino Sans', 'Skia',
    'DejaVu Sans', 'DejaVu Serif', 'DejaVu Sans Mono', 'Liberation Sans', 'Liberation Serif', 'Liberation Mono', 'Ubuntu', 'Ubuntu Mono', 'Noto Sans', 'Noto Serif', 'Noto Color Emoji', 'Cantarell', 'Nimbus Sans', 'FreeSans', 'Droid Sans', 'Roboto', 'Open Sans', 'Source Sans Pro', 'Fira Sans', 'Inter', 'Lato'];
  function fontsProbe() {
    var bases = ['monospace', 'sans-serif', 'serif'];
    var holder = document.createElement('div'); holder.style.cssText = 'position:absolute;left:-9999px;top:0;visibility:hidden;white-space:nowrap;';
    document.body.appendChild(holder);
    function span(family) { var s = document.createElement('span'); s.style.cssText = 'font-size:72px;line-height:normal;font-family:' + family + ';'; s.textContent = 'mmMwWLliI0O&1@中文'; holder.appendChild(s); return s; }
    var baseSpans = {}; var baseW = {};
    bases.forEach(function (b) { var s = span(b); baseSpans[b] = s; baseW[b] = [s.offsetWidth, s.offsetHeight]; });
    var detected = []; var widths = {};
    FONTS.forEach(function (f) {
      var hit = false; var ws = [];
      bases.forEach(function (b) { var s = span("'" + f + "'," + b); var w = [s.offsetWidth, s.offsetHeight]; ws.push(w[0]); if (w[0] !== baseW[b][0] || w[1] !== baseW[b][1]) hit = true; holder.removeChild(s); });
      if (hit) { detected.push(f); widths[f] = ws; }
    });
    document.body.removeChild(holder);
    var out = { method: 'dom offsetWidth/offsetHeight vs generic fallbacks', tested: FONTS.length, count: detected.length, detected: detected, baseWidths: baseW, hash: hashStr(detected.join(',')) };
    out.fontsApi = safe(function () { return document.fonts ? { size: document.fonts.size, status: document.fonts.status, check: document.fonts.check('12px Arial') } : null; });
    out.localFonts = typeof window.queryLocalFonts === 'function';
    return out;
  }

  // ----------------------------------------------------------------- engine
  function engineProbe() {
    var out = {};
    out.stackFirst = safe(function () { var s = new Error('x').stack || ''; return s.split('\n').slice(0, 3).join('\n'); }, '');
    out.stackFrames = safe(function () { return (new Error('x').stack || '').split('\n').length; });
    out.evalLen = safe(function () { return eval.toString().length; });
    out.nativeToString = safe(function () { return Function.prototype.toString.call(Object); });
    out.getterToString = safe(function () { return Function.prototype.toString.call(Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get); });
    out.errorStackDesc = safe(function () { var d = Object.getOwnPropertyDescriptor(Error.prototype, 'stack'); return !d ? 'none' : d.get ? 'accessor' : 'data'; });
    out.errorInstanceStackOwn = safe(function () { return Object.prototype.hasOwnProperty.call(new Error('x'), 'stack'); });
    out.v8BreakIterator = safe(function () { return typeof Intl.v8BreakIterator === 'function'; }, false);
    out.captureStackTrace = safe(function () { return typeof Error.captureStackTrace; });
    out.stackTraceLimit = safe(function () { return Error.stackTraceLimit; });
    out.errors = {
      nullProp: safe(function () { try { null.x; } catch (e) { return e.message; } }),
      undefProp: safe(function () { try { undefined.x; } catch (e) { return e.message; } }),
      notFunc: safe(function () { try { var o = {}; o.f(); } catch (e) { return e.message; } }),
      toFixed: safe(function () { try { (1).toFixed(200); } catch (e) { return e.message; } }),
      arrayLen: safe(function () { try { new Array(-1); } catch (e) { return e.message; } }),
      jsonCircular: safe(function () { try { var a = {}; a.a = a; JSON.stringify(a); } catch (e) { return e.message.split('\n')[0].slice(0, 80); } }),
      badRegex: safe(function () { try { new RegExp('('); } catch (e) { return e.message; } }),
      constTypeErr: safe(function () { try { eval('const q = 1; q = 2;'); } catch (e) { return e.message; } }),
      bigintMix: safe(function () { try { 1n + 1; } catch (e) { return e.message; } })
    };
    out.math = {};
    [['tan_-1e300', function () { return Math.tan(-1e300); }], ['sin_1e300', function () { return Math.sin(1e300); }], ['sinh_1', function () { return Math.sinh(1); }], ['cosh_1', function () { return Math.cosh(1); }],
      ['tanh_1', function () { return Math.tanh(1); }], ['expm1_1', function () { return Math.expm1(1); }], ['log1p_10', function () { return Math.log1p(10); }], ['cbrt_100', function () { return Math.cbrt(100); }],
      ['exp_1', function () { return Math.exp(1); }], ['atanh_05', function () { return Math.atanh(0.5); }], ['asinh_1', function () { return Math.asinh(1); }], ['acosh_1e308', function () { return Math.acosh(1e308); }],
      ['pow_pi_-100', function () { return Math.pow(Math.PI, -100); }], ['log_pi', function () { return Math.log(Math.PI); }], ['sqrt_2e-300', function () { return Math.sqrt(2e-300); }], ['hypot', function () { return Math.hypot(1e-300, 1e-300); }],
      ['cos_1e100', function () { return Math.cos(1e100); }], ['sin_pi', function () { return Math.sin(Math.PI); }], ['1e21_toString', function () { return (1e21).toString(); }], ['0.1+0.2', function () { return 0.1 + 0.2; }],
      ['toFixed', function () { return (1.005).toFixed(2) + '|' + (2.5).toFixed(0) + '|' + (1e21).toFixed(2); }], ['toPrecision', function () { return (123.456).toPrecision(4); }]
    ].forEach(function (kv) { out.math[kv[0]] = safe(function () { var v = kv[1](); return typeof v === 'number' ? v.toString() : String(v); }); });
    out.mathHash = hashStr(JSON.stringify(out.math));
    out.functionToStringNewline = safe(function () { return Function.prototype.toString.call(Object).indexOf('\n') >= 0; });
    out.defaultFontFamily = safe(function () { var d = document.createElement('div'); d.style.fontFamily = 'initial'; document.body.appendChild(d); var v = getComputedStyle(d).fontFamily; document.body.removeChild(d); return v; });
    out.cssPropertyCount = safe(function () { var n = 0; for (var k in document.body.style) n++; return n; });
    out.cssProtoCount = safe(function () { return Object.getOwnPropertyNames(Object.getPrototypeOf(document.body.style)).length; });
    out.css = {
      mozAppearance: safe(function () { return CSS.supports('-moz-appearance', 'none'); }), webkitAppRegion: safe(function () { return CSS.supports('-webkit-app-region', 'drag'); }),
      zoom: safe(function () { return CSS.supports('zoom', '1'); }), webkitTextStroke: safe(function () { return CSS.supports('-webkit-text-stroke', '1px red'); }),
      mozUserSelect: safe(function () { return CSS.supports('-moz-user-select', 'none'); }), webkitUserSelect: safe(function () { return CSS.supports('-webkit-user-select', 'none'); }),
      has: safe(function () { return CSS.supports('selector(:has(a))'); }), nesting: safe(function () { return CSS.supports('selector(&)'); }),
      containerQueries: safe(function () { return CSS.supports('container-type', 'inline-size'); }), anchor: safe(function () { return CSS.supports('anchor-name', '--a'); }),
      colorMix: safe(function () { return CSS.supports('color', 'color-mix(in srgb, red, blue)'); }), textWrapPretty: safe(function () { return CSS.supports('text-wrap', 'pretty'); }),
      fieldSizing: safe(function () { return CSS.supports('field-sizing', 'content'); }), mozFocusring: safe(function () { return CSS.supports('selector(:-moz-focusring)'); }),
      webkitScrollbar: safe(function () { return CSS.supports('selector(::-webkit-scrollbar)'); })
    };
    out.styleProps = { MozAppearance: safe(function () { return 'MozAppearance' in document.documentElement.style; }), webkitAppearance: safe(function () { return 'webkitAppearance' in document.documentElement.style; }), WebkitLineClamp: safe(function () { return 'WebkitLineClamp' in document.documentElement.style; }) };
    out.windowPropsCount = safe(function () { return Object.getOwnPropertyNames(window).length; });
    out.windowPropsHash = safe(function () { return hashStr(Object.getOwnPropertyNames(window).sort().join(',')); });
    out.windowProtoChain = safe(function () { var c = []; var o = window; while ((o = Object.getPrototypeOf(o)) && c.length < 6) c.push(safe(function () { return o.constructor.name; }, '?') || Object.prototype.toString.call(o)); return c; });
    out.navigatorToString = safe(function () { return Object.prototype.toString.call(navigator); });
    out.documentProto = safe(function () { return Object.getOwnPropertyNames(Document.prototype).length; });
    out.elementProto = safe(function () { return Object.getOwnPropertyNames(HTMLElement.prototype).length + '/' + Object.getOwnPropertyNames(Element.prototype).length; });
    out.arraySort = safe(function () { return [5, 1, 4, 2, 3, 10, 20].sort().join(''); });
    out.localeCompare = safe(function () { return ['b', 'a', 'B', 'A', 'ä'].sort(function (x, y) { return x.localeCompare(y); }).join(''); });
    out.regexpFlags = safe(function () { return Object.getOwnPropertyNames(RegExp.prototype).filter(function (k) { return k.length <= 12 && /^[a-zA-Z]+$/.test(k); }).sort().join(','); });
    out.dateToString = safe(function () { return new Date(0).toString(); });
    out.jsonStringifyFn = safe(function () { return JSON.stringify({ a: function () {}, b: undefined, c: NaN, d: 1e21 }); });
    out.temporal = safe(function () { return typeof Temporal; });
    out.structuredClone = safe(function () { return typeof structuredClone; });
    out.performanceNow = safe(function () { return performance.now().toString(); });
    out.userAgentConsistency = safe(function () { return navigator.userAgent.indexOf(navigator.appVersion) >= 0 || navigator.appVersion === navigator.userAgent.replace('Mozilla/', ''); });
    out.wasm = safe(function () { return typeof WebAssembly === 'object' && WebAssembly.validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])); });
    out.sharedArrayBuffer = typeof SharedArrayBuffer;
    out.crossOriginIsolated = safe(function () { return window.crossOriginIsolated; });
    out.jscLike = safe(function () { return typeof window.webkitConvertPointFromNodeToPage === 'function'; }, false);
    return out;
  }

  // ------------------------------------------------------------------- apis
  var API_PATHS = ['window.chrome', 'navigator.userAgentData', 'navigator.deviceMemory', 'navigator.bluetooth', 'navigator.usb', 'navigator.serial', 'navigator.hid', 'navigator.keyboard',
    'navigator.scheduling', 'navigator.getBattery', 'window.showOpenFilePicker', 'window.webkitRequestFileSystem', 'window.PeriodicSyncManager', 'window.trustedTypes',
    'document.featurePolicy', 'Intl.v8BreakIterator', 'performance.memory', 'window.launchQueue', 'window.documentPictureInPicture',
    'navigator.oscpu', 'navigator.buildID', 'window.mozInnerScreenX', 'window.netscape', 'window.dump',
    'WebAssembly', 'WebSocket', 'IntersectionObserver', 'ResizeObserver', 'OffscreenCanvas', 'BroadcastChannel', 'TextEncoder', 'structuredClone', 'AbortController', 'Intl.Segmenter',
    'crypto.subtle', 'RTCPeerConnection', 'Notification', 'PerformanceObserver', 'CompressionStream', 'navigator.mediaDevices', 'speechSynthesis', 'AudioContext', 'MediaSource',
    'WebGL2RenderingContext', 'navigator.gpu', 'navigator.xr', 'navigator.share', 'navigator.clipboard', 'navigator.credentials', 'navigator.locks', 'navigator.storage', 'navigator.permissions',
    'navigator.serviceWorker', 'navigator.mediaCapabilities', 'navigator.mediaSession', 'navigator.geolocation', 'navigator.wakeLock', 'navigator.presentation', 'navigator.virtualKeyboard',
    'navigator.windowControlsOverlay', 'navigator.ink', 'navigator.login', 'navigator.managed', 'navigator.devicePosture', 'navigator.contacts', 'navigator.setAppBadge', 'navigator.sendBeacon',
    'navigator.vibrate', 'navigator.requestMIDIAccess', 'navigator.getGamepads', 'navigator.registerProtocolHandler', 'navigator.canShare', 'navigator.userActivation', 'navigator.pdfViewerEnabled',
    'window.PaymentRequest', 'window.PushManager', 'window.SharedWorker', 'window.Worker', 'window.WebTransport', 'window.EventSource', 'window.Cache', 'window.caches', 'window.indexedDB',
    'window.localStorage', 'window.sessionStorage', 'window.openDatabase', 'window.requestIdleCallback', 'window.queueMicrotask', 'window.scheduler', 'window.reportError', 'window.ReportingObserver',
    'window.Highlight', 'window.CSSMathSum', 'window.HTMLDialogElement', 'HTMLElement.prototype.showPopover', 'document.startViewTransition', 'window.Sanitizer', 'window.CookieStore',
    'window.NavigateEvent', 'window.navigation', 'window.fence', 'window.sharedStorage', 'window.PressureObserver', 'window.AmbientLightSensor', 'window.Accelerometer', 'window.Gyroscope',
    'window.Magnetometer', 'window.SpeechRecognition', 'window.webkitSpeechRecognition', 'window.MediaStreamTrackProcessor', 'window.VideoEncoder', 'window.AudioEncoder', 'window.ImageDecoder',
    'window.FileSystemHandle', 'window.showDirectoryPicker', 'window.LanguageDetector', 'window.Translator', 'window.Summarizer', 'window.ai', 'window.CSSStartingStyleRule', 'window.Temporal',
    'window.WeakRef', 'window.FinalizationRegistry', 'window.Atomics', 'window.SharedArrayBuffer', 'window.BigInt64Array', 'window.Iterator', 'window.Float16Array',
    'Array.prototype.group', 'Object.groupBy', 'Promise.withResolvers', 'Array.fromAsync', 'Set.prototype.union', 'RegExp.escape', 'Math.sumPrecise', 'Error.isError', 'Uint8Array.fromBase64',
    'window.webkitMediaStream', 'window.webkitRTCPeerConnection', 'window.mozRTCPeerConnection', 'window.webkitURL', 'window.webkitAudioContext', 'window.webkitOfflineAudioContext',
    'window.onmozfullscreenchange', 'document.mozFullScreenEnabled', 'document.webkitFullscreenEnabled', 'document.webkitHidden', 'window.captureEvents', 'window.external',
    'window.chrome.csi', 'window.chrome.loadTimes', 'window.chrome.app', 'window.chrome.runtime', 'window.opr', 'window.opera', 'window.InstallTrigger', 'window.safari', 'window.ApplePaySession',
    'navigator.standalone', 'window.webkit', 'window.MSStream', 'document.documentMode', 'window.StyleMedia', 'window.ondeviceorientationabsolute', 'window.onbeforeinstallprompt',
    'window.BarcodeDetector', 'window.FaceDetector', 'window.TextDetector', 'window.EyeDropper', 'window.CSSLayerBlockRule', 'window.CSSScopeRule', 'window.CSSPositionTryRule', 'window.CSSViewTransitionRule',
    'navigator.hardwareConcurrency', 'navigator.maxTouchPoints', 'navigator.connection', 'navigator.plugins', 'navigator.mimeTypes', 'navigator.doNotTrack', 'navigator.globalPrivacyControl', 'navigator.cookieEnabled', 'navigator.onLine', 'navigator.webdriver'];
  function apisProbe() {
    var out = {};
    API_PATHS.forEach(function (p) {
      out[p] = safe(function () {
        var parts = p.split('.'); var cur = window; var lastParent = null;
        for (var i = 0; i < parts.length; i++) { if (cur === null || cur === undefined) return false; lastParent = cur; cur = cur[parts[i]]; if (cur === undefined && !(parts[i] in Object(lastParent))) return false; }
        return cur !== undefined || (parts[parts.length - 1] in Object(lastParent));
      }, false);
    });
    out['css.-webkit-app-region'] = safe(function () { return CSS.supports('-webkit-app-region', 'drag'); }, false);
    out['css.-moz-appearance'] = safe(function () { return CSS.supports('-moz-appearance', 'none'); }, false);
    out['style.MozAppearance'] = safe(function () { return 'MozAppearance' in document.documentElement.style; }, false);
    out['Error.prototype.stack accessor'] = safe(function () { var d = Object.getOwnPropertyDescriptor(Error.prototype, 'stack'); return !!(d && d.get); }, false);
    var present = Object.keys(out).filter(function (k) { return out[k]; });
    out.__count = present.length; out.__total = Object.keys(out).length - 1; out.__hash = hashStr(present.sort().join(','));
    return out;
  }

  // ------------------------------------------------------------- automation
  var SUSPICIOUS_RE = /cdc_|\$cdc|\$chrome_asyncScriptInfo|webdriver|selenium|_selenium|driver|phantom|nightmare|puppeteer|playwright|__pw|domAutomation|__lastWatir|calledPhantom|awesomium|__stopAllTimers|__webdriver|__fxdriver|geb\b|\$wdc_|_WEBDRIVER_ELEM_CACHE|ChromeDriverw|__$webdriverAsyncExecutor|electron|nodeRequire|__nightmare|_Selenium_IDE_Recorder/i;
  var KNOWN_GLOBALS = ['__webdriver_evaluate', '__selenium_evaluate', '__webdriver_script_function', '__webdriver_script_func', '__webdriver_script_fn', '__fxdriver_evaluate', '__driver_unwrapped',
    '__webdriver_unwrapped', '__driver_evaluate', '__selenium_unwrapped', '__fxdriver_unwrapped', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium', '_WEBDRIVER_ELEM_CACHE', 'ChromeDriverw',
    'webdriverCommand', '__webdriverFunc', '__lastWatirAlert', '__lastWatirConfirm', '__lastWatirPrompt', '$chrome_asyncScriptInfo', '$cdc_asdjflasutopfhvcZLmcfl_', '__playwright__binding__',
    '__pwInitScripts', '__playwright', '_phantom', 'callPhantom', '__nightmare', 'domAutomation', 'domAutomationController', '__puppeteer_evaluation_script__', 'geb', 'awesomium', '__$webdriverAsyncExecutor',
    'cdc_adoQpoasnfa76pfcZLmcfl_Array', 'cdc_adoQpoasnfa76pfcZLmcfl_Promise', 'cdc_adoQpoasnfa76pfcZLmcfl_Symbol', 'cdc_adoQpoasnfa76pfcZLmcfl_Object', 'cdc_adoQpoasnfa76pfcZLmcfl_Proxy', '__stopAllTimers', '__driver_evaluate',
    '__webdriverAsyncExecutor', '__selenium_evaluate_response', 'Cypress', '__cypress', '__antidetect', '__stealth', '__fpjs', 'FingerprintJS'];
  async function automationProbe() {
    var out = {};
    out.webdriver = safe(function () { return navigator.webdriver; });
    out.uaHeadless = /Headless/i.test(navigator.userAgent);
    var globals = safe(function () { return Object.getOwnPropertyNames(window); }, []);
    var sus = globals.filter(function (k) { return SUSPICIOUS_RE.test(k) && k !== 'onwebkitdriverchange'; });
    KNOWN_GLOBALS.forEach(function (k) { if (sus.indexOf(k) < 0 && safe(function () { return k in window; }, false)) sus.push(k); });
    var docSus = KNOWN_GLOBALS.filter(function (k) { return safe(function () { return k in document; }, false); });
    out.globalsSuspicious = sus; out.documentSuspicious = docSus;
    out.documentAttrs = safe(function () { var el = document.documentElement; return ['webdriver', 'selenium', 'driver', 'cd_frame_id_'].filter(function (a) { return el.hasAttribute(a); }); }, []);
    out.chrome = safe(function () { var c = window.chrome; if (!c) return { present: false }; return { present: true, keys: Object.keys(c), app: 'app' in c, csi: 'csi' in c, loadTimes: 'loadTimes' in c, runtime: 'runtime' in c, webstore: 'webstore' in c, csiNative: isNative(c.csi), loadTimesNative: isNative(c.loadTimes), appToString: safe(function () { return Object.prototype.toString.call(c.app); }) }; });
    out.notification = { permission: safe(function () { return Notification.permission; }), queryState: null };
    if (navigator.permissions && navigator.permissions.query) {
      var q = await withTimeout(navigator.permissions.query({ name: 'notifications' }), 1500, null);
      out.notification.queryState = q && q.state ? q.state : (q && q.__err ? q.__err : null);
      out.permissionsQueryNative = isNative(navigator.permissions.query);
    }
    out.pluginsLen = safe(function () { return navigator.plugins.length; });
    out.pluginsProto = safe(function () { return Object.prototype.toString.call(navigator.plugins); });
    out.languagesLen = safe(function () { return navigator.languages.length; });
    out.outerZero = window.outerWidth === 0 || window.outerHeight === 0;
    out.connectionRtt = safe(function () { return navigator.connection ? navigator.connection.rtt : null; });
    out.cdpLeak = (function () {
      var leaked = false;
      try { var e = new Error('probe'); Object.defineProperty(e, 'stack', { get: function () { leaked = true; return ''; } }); console.debug(e); console.log('%c', e); } catch (x) {}
      return leaked;
    })();
    out.processObj = safe(function () { return !!(window.process && window.process.versions) || typeof window.require === 'function' || typeof window.Buffer === 'function'; }, false);
    out.errorStackMarkers = safe(function () { var s = new Error('x').stack || ''; var m = s.match(/puppeteer|playwright|selenium|webdriver|__pw|cdc_|evaluate_script|UtilityScript|pptr:/i); return m ? m[0] : null; });
    out.hasFocus = safe(function () { return document.hasFocus(); });
    out.visibilityState = safe(function () { return document.visibilityState; });
    out.iframeContentWindowNative = isNative(Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get);
    out.functionBindNative = isNative(Function.prototype.bind);
    out.externalToString = safe(function () { return window.external ? String(window.external) : null; });
    out.mouseMoved = mouseMoved;
    out.eventIsTrusted = safe(function () { var ev = new MouseEvent('click'); return ev.isTrusted; });
    out.timingAnomaly = safe(function () { var ds = []; var last = performance.now(); for (var i = 0; i < 300; i++) { var n = performance.now(); if (n !== last) { ds.push(n - last); last = n; } } if (!ds.length) return 'performance.now() never advanced'; ds.sort(function (a, b) { return a - b; }); var min = ds[0]; return min >= 1.0 && ds.length < 5 ? 'min delta ' + min + 'ms over 300 calls' : null; });
    out.perfNowResolution = safe(function () { var ds = []; var last = performance.now(); for (var i = 0; i < 300; i++) { var n = performance.now(); if (n !== last) { ds.push(n - last); last = n; } } ds.sort(function (a, b) { return a - b; }); return ds.length ? ds[0] : null; });
    out.stealthMarkers = safe(function () { var m = []; if (navigator.plugins && navigator.plugins.length && !(navigator.plugins[0] instanceof Plugin)) m.push('plugins not Plugin instances'); if (typeof navigator.plugins.refresh !== 'function') m.push('plugins.refresh missing'); if (window.chrome && window.chrome.runtime && typeof window.chrome.runtime.connect !== 'function') m.push('chrome.runtime.connect missing'); return m; }, []);
    out.userAgentVsAppVersion = safe(function () { return navigator.userAgent.slice(8) === navigator.appVersion; });
    return out;
  }

  // -------------------------------------------------------------- integrity
  var INTEGRITY = [
    ['navigator.userAgent', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent').get; }],
    ['navigator.platform', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform').get; }],
    ['navigator.languages', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages').get; }],
    ['navigator.hardwareConcurrency', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency').get; }],
    ['navigator.deviceMemory', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'deviceMemory').get; }],
    ['navigator.webdriver', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver').get; }],
    ['navigator.plugins', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins').get; }],
    ['navigator.vendor', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'vendor').get; }],
    ['navigator.userAgentData', function () { return Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgentData').get; }],
    ['navigator.permissions.query', function () { return Permissions.prototype.query; }],
    ['navigator.mediaDevices.enumerateDevices', function () { return MediaDevices.prototype.enumerateDevices; }],
    ['screen.width', function () { return Object.getOwnPropertyDescriptor(Screen.prototype, 'width').get; }],
    ['screen.height', function () { return Object.getOwnPropertyDescriptor(Screen.prototype, 'height').get; }],
    ['screen.availWidth', function () { return Object.getOwnPropertyDescriptor(Screen.prototype, 'availWidth').get; }],
    ['screen.colorDepth', function () { return Object.getOwnPropertyDescriptor(Screen.prototype, 'colorDepth').get; }],
    ['window.devicePixelRatio', function () { return Object.getOwnPropertyDescriptor(window, 'devicePixelRatio').get; }],
    ['window.outerWidth', function () { return Object.getOwnPropertyDescriptor(window, 'outerWidth').get; }],
    ['window.innerWidth', function () { return Object.getOwnPropertyDescriptor(window, 'innerWidth').get; }],
    ['HTMLCanvasElement.toDataURL', function () { return HTMLCanvasElement.prototype.toDataURL; }],
    ['HTMLCanvasElement.toBlob', function () { return HTMLCanvasElement.prototype.toBlob; }],
    ['HTMLCanvasElement.getContext', function () { return HTMLCanvasElement.prototype.getContext; }],
    ['CanvasRenderingContext2D.getImageData', function () { return CanvasRenderingContext2D.prototype.getImageData; }],
    ['CanvasRenderingContext2D.fillText', function () { return CanvasRenderingContext2D.prototype.fillText; }],
    ['CanvasRenderingContext2D.measureText', function () { return CanvasRenderingContext2D.prototype.measureText; }],
    ['WebGLRenderingContext.getParameter', function () { return WebGLRenderingContext.prototype.getParameter; }],
    ['WebGLRenderingContext.getExtension', function () { return WebGLRenderingContext.prototype.getExtension; }],
    ['WebGLRenderingContext.getSupportedExtensions', function () { return WebGLRenderingContext.prototype.getSupportedExtensions; }],
    ['WebGLRenderingContext.readPixels', function () { return WebGLRenderingContext.prototype.readPixels; }],
    ['WebGL2RenderingContext.getParameter', function () { return WebGL2RenderingContext.prototype.getParameter; }],
    ['AudioBuffer.getChannelData', function () { return AudioBuffer.prototype.getChannelData; }],
    ['AudioBuffer.copyFromChannel', function () { return AudioBuffer.prototype.copyFromChannel; }],
    ['AnalyserNode.getFloatFrequencyData', function () { return AnalyserNode.prototype.getFloatFrequencyData; }],
    ['OfflineAudioContext.startRendering', function () { return OfflineAudioContext.prototype.startRendering; }],
    ['Date.prototype.getTimezoneOffset', function () { return Date.prototype.getTimezoneOffset; }],
    ['Intl.DateTimeFormat.prototype.resolvedOptions', function () { return Intl.DateTimeFormat.prototype.resolvedOptions; }],
    ['Function.prototype.toString', function () { return Function.prototype.toString; }],
    ['Function.prototype.bind', function () { return Function.prototype.bind; }],
    ['Object.getOwnPropertyDescriptor', function () { return Object.getOwnPropertyDescriptor; }],
    ['Error.captureStackTrace', function () { return Error.captureStackTrace; }],
    ['HTMLIFrameElement.contentWindow', function () { return Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get; }],
    ['Element.getBoundingClientRect', function () { return Element.prototype.getBoundingClientRect; }],
    ['HTMLElement.offsetWidth', function () { return Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth').get; }],
    ['performance.now', function () { return Performance.prototype.now; }],
    ['window.matchMedia', function () { return window.matchMedia; }],
    ['SpeechSynthesis.getVoices', function () { return SpeechSynthesis.prototype.getVoices; }],
    ['RTCPeerConnection', function () { return window.RTCPeerConnection; }],
    ['navigator.getBattery', function () { return Navigator.prototype.getBattery; }],
    ['Storage.getItem', function () { return Storage.prototype.getItem; }],
    ['document.hasFocus', function () { return Document.prototype.hasFocus; }],
    ['window.fetch', function () { return window.fetch; }],
    ['XMLHttpRequest.open', function () { return XMLHttpRequest.prototype.open; }],
    ['Worker', function () { return window.Worker; }],
    ['navigator.sendBeacon', function () { return Navigator.prototype.sendBeacon; }]
  ];
  function integrityProbe() {
    var checks = []; var lies = 0;
    var tsNative = isNative(Function.prototype.toString);
    var tsOwn = safe(function () { return Object.prototype.hasOwnProperty.call(Function.prototype.toString, 'toString'); }, false);
    INTEGRITY.forEach(function (kv) {
      var path = kv[0]; var fn = safe(kv[1], undefined);
      if (typeof fn !== 'function') { checks.push({ path: path, present: false }); return; }
      var c = { path: path, present: true };
      c.native = isNative(fn);
      c.own = safe(function () { return Object.prototype.hasOwnProperty.call(fn, 'toString'); }, false);
      c.hasPrototype = safe(function () { return Object.prototype.hasOwnProperty.call(fn, 'prototype') && !/^[A-Z]/.test(path.split('.').pop()) && path !== 'RTCPeerConnection' && path !== 'Worker'; }, false);
      c.name = safe(function () { return fn.name; }); c.length = safe(function () { return fn.length; });
      c.proxy = safe(function () { try { Object.setPrototypeOf(fn, Object.create(fn)); return false; } catch (e) { return !(e instanceof TypeError); } }, null);
      c.strLen = safe(function () { return Function.prototype.toString.call(fn).length; });
      c.constructorErr = safe(function () { try { new fn(); return null; } catch (e) { return e.message.slice(0, 60); } });
      if (c.native === false || c.own || c.hasPrototype || c.proxy) lies++;
      checks.push(c);
    });
    return { toStringNative: tsNative, toStringOwn: tsOwn, checked: checks.length, lies: lies, checks: checks };
  }

  // ------------------------------------------------------------ permissions
  async function permissionsProbe() {
    var names = ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read', 'clipboard-write', 'persistent-storage', 'midi', 'push', 'accelerometer', 'gyroscope', 'magnetometer',
      'background-sync', 'payment-handler', 'screen-wake-lock', 'storage-access', 'window-management', 'local-fonts', 'idle-detection', 'display-capture'];
    if (!(navigator.permissions && navigator.permissions.query)) return { supported: false };
    var out = { supported: true, states: {} };
    for (var i = 0; i < names.length; i++) {
      var n = names[i];
      var r = await withTimeout(navigator.permissions.query({ name: n }), 800, { __err: 'timeout' });
      out.states[n] = r && r.state ? r.state : (r && r.__err ? 'error:' + r.__err.split(':')[0] : 'error');
    }
    out.notificationPermission = safe(function () { return Notification.permission; });
    return out;
  }

  // ------------------------------------------------------------------ media
  async function mediaProbe() {
    var out = {};
    var v = document.createElement('video'); var a = document.createElement('audio');
    out.canPlayType = {
      h264: safe(function () { return v.canPlayType('video/mp4; codecs="avc1.42E01E"'); }), h265: safe(function () { return v.canPlayType('video/mp4; codecs="hvc1.1.6.L93.B0"'); }),
      vp8: safe(function () { return v.canPlayType('video/webm; codecs="vp8"'); }), vp9: safe(function () { return v.canPlayType('video/webm; codecs="vp9"'); }), av1: safe(function () { return v.canPlayType('video/mp4; codecs="av01.0.08M.08"'); }),
      ogg: safe(function () { return v.canPlayType('video/ogg; codecs="theora"'); }), mp3: safe(function () { return a.canPlayType('audio/mpeg'); }), aac: safe(function () { return a.canPlayType('audio/mp4; codecs="mp4a.40.2"'); }),
      opus: safe(function () { return a.canPlayType('audio/ogg; codecs="opus"'); }), flac: safe(function () { return a.canPlayType('audio/flac'); }), wav: safe(function () { return a.canPlayType('audio/wav'); })
    };
    out.mediaSource = safe(function () { return { h264: MediaSource.isTypeSupported('video/mp4; codecs="avc1.42E01E"'), vp9: MediaSource.isTypeSupported('video/webm; codecs="vp9"'), av1: MediaSource.isTypeSupported('video/mp4; codecs="av01.0.08M.08"'), opus: MediaSource.isTypeSupported('audio/webm; codecs="opus"') }; });
    out.recorder = safe(function () { return { webm: MediaRecorder.isTypeSupported('video/webm'), webmVp9: MediaRecorder.isTypeSupported('video/webm;codecs=vp9'), mp4: MediaRecorder.isTypeSupported('video/mp4') }; });
    out.devices = await (async function () {
      if (!(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices)) return { err: 'unsupported' };
      var r = await withTimeout(navigator.mediaDevices.enumerateDevices(), 2000, { __err: 'timeout' });
      if (!r || r.__err) return { err: r ? r.__err : 'timeout' };
      var c = { audioinput: 0, audiooutput: 0, videoinput: 0 }; r.forEach(function (d) { c[d.kind] = (c[d.kind] || 0) + 1; }); c.labelsVisible = r.some(function (d) { return !!d.label; }); return c;
    })();
    out.voices = await (async function () {
      if (!window.speechSynthesis) return null;
      var vs = speechSynthesis.getVoices(); if (vs.length) return vs.length;
      return await new Promise(function (res) { var done = false; var t = setTimeout(function () { if (!done) { done = true; res(speechSynthesis.getVoices().length); } }, 800); try { speechSynthesis.onvoiceschanged = function () { if (!done) { done = true; clearTimeout(t); res(speechSynthesis.getVoices().length); } }; } catch (e) {} });
    })();
    out.voiceSample = safe(function () { return speechSynthesis.getVoices().slice(0, 3).map(function (v) { return v.name + '/' + v.lang; }); });
    out.webrtc = await (async function () {
      var PC = window.RTCPeerConnection || window.webkitRTCPeerConnection; if (!PC) return { supported: false };
      var out = { supported: true, candidates: [], ips: [], mdns: false };
      try {
        var pc = new PC({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] }); pc.createDataChannel('probe');
        var p = new Promise(function (res) { var t = setTimeout(res, 2500); pc.onicecandidate = function (e) { if (!e.candidate) { clearTimeout(t); res(); return; } var c = e.candidate.candidate || ''; var m = c.match(/typ (\w+)/); out.candidates.push(m ? m[1] : '?'); var ip = c.split(' ')[4]; if (ip) { if (/\.local$/.test(ip)) out.mdns = true; else if (out.ips.indexOf(ip) < 0) out.ips.push(ip); } }; });
        var r = await withTimeout((async function () { var offer = await pc.createOffer(); await pc.setLocalDescription(offer); await p; return true; })(), 4000, { __err: 'timeout' });
        if (r && r.__err) out.err = 'createOffer/ICE gathering did not complete within 4 s';
        out.sdpLines = (pc.localDescription && pc.localDescription.sdp || '').split('\n').length; try { pc.close(); } catch (e) {}
      } catch (e) { out.err = errStr(e); }
      return out;
    })();
    out.mediaCapabilities = await (async function () { if (!(navigator.mediaCapabilities && navigator.mediaCapabilities.decodingInfo)) return null; var r = await withTimeout(navigator.mediaCapabilities.decodingInfo({ type: 'file', video: { contentType: 'video/mp4; codecs="avc1.42E01E"', width: 1920, height: 1080, bitrate: 3000000, framerate: 30 } }), 1500, null); return r && !r.__err ? { supported: r.supported, smooth: r.smooth, powerEfficient: r.powerEfficient } : null; })();
    return out;
  }

  // ------------------------------------------------------------------ worker
  function workerProbe() {
    return new Promise(function (resolve) {
      if (!window.Worker) { resolve({ ok: false, err: 'Worker unsupported' }); return; }
      var w; var done = false;
      var t = setTimeout(function () { if (!done) { done = true; resolve({ ok: false, err: 'timeout' }); try { w.terminate(); } catch (e) {} } }, 4000);
      try {
        w = new Worker('/static/worker.js?r=' + T0);
        w.onmessage = function (e) { if (!done) { done = true; clearTimeout(t); var d = e.data || {}; d.ok = true; resolve(d); try { w.terminate(); } catch (x) {} } };
        w.onerror = function (e) { if (!done) { done = true; clearTimeout(t); resolve({ ok: false, err: (e && e.message) || 'worker error' }); } };
      } catch (e) { if (!done) { done = true; clearTimeout(t); resolve({ ok: false, err: errStr(e) }); } }
    });
  }

  // ------------------------------------------------------------------ iframe
  function iframeProbe() {
    var f = document.createElement('iframe'); f.style.cssText = 'position:absolute;left:-9999px;width:10px;height:10px;'; f.src = 'about:blank';
    document.body.appendChild(f);
    try {
      var w = f.contentWindow; var n = w.navigator;
      var out = { ok: true, userAgent: n.userAgent, platform: n.platform, webdriver: n.webdriver, hardwareConcurrency: n.hardwareConcurrency, deviceMemory: n.deviceMemory, languages: safe(function () { return Array.prototype.slice.call(n.languages); }), vendor: n.vendor };
      out.protoHash = hashStr(Object.getOwnPropertyNames(Object.getPrototypeOf(n)).join(','));
      out.uaGetterNative = safe(function () { return isNative(Object.getOwnPropertyDescriptor(w.Navigator.prototype, 'userAgent').get); });
      out.webdriverGetterNative = safe(function () { var d = Object.getOwnPropertyDescriptor(w.Navigator.prototype, 'webdriver'); return d && d.get ? isNative(d.get) : null; });
      out.toStringSame = safe(function () { return w.Function.prototype.toString === Function.prototype.toString; });
      out.toStringNativeInFrame = safe(function () { return NATIVE_RE.test(w.Function.prototype.toString.call(w.Function.prototype.toString)); });
      out.defaultFontFamily = safe(function () { return w.getComputedStyle(w.document.body || w.document.documentElement).fontFamily; });
      out.screenWidth = safe(function () { return w.screen.width; }); out.innerWidth = safe(function () { return w.innerWidth; });
      out.timezone = safe(function () { return w.Intl.DateTimeFormat().resolvedOptions().timeZone; });
      out.chrome = safe(function () { return !!w.chrome; });
      out.contentWindowNull = false;
      return out;
    } catch (e) { return { ok: false, err: errStr(e) }; }
    finally { try { document.body.removeChild(f); } catch (e) {} }
  }

  // ---------------------------------------------------------------- storage
  async function storageProbe() {
    var out = {};
    out.localStorage = safe(function () { localStorage.setItem('__dacty', '1'); var v = localStorage.getItem('__dacty') === '1'; localStorage.removeItem('__dacty'); return v; }, false);
    out.sessionStorage = safe(function () { sessionStorage.setItem('__dacty', '1'); var v = sessionStorage.getItem('__dacty') === '1'; sessionStorage.removeItem('__dacty'); return v; }, false);
    out.cookies = safe(function () { document.cookie = '__dacty=1; path=/; SameSite=Lax'; var v = document.cookie.indexOf('__dacty=1') >= 0; document.cookie = '__dacty=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'; return v; }, false);
    out.indexedDB = await withTimeout(new Promise(function (res) { try { var r = indexedDB.open('__dacty', 1); r.onsuccess = function () { try { r.result.close(); indexedDB.deleteDatabase('__dacty'); } catch (e) {} res(true); }; r.onerror = function () { res(false); }; r.onblocked = function () { res(false); }; } catch (e) { res(false); } }), 2000, null);
    var est = await withTimeout(safe(function () { return navigator.storage.estimate(); }) || Promise.resolve(null), 2000, null);
    out.quota = est && !est.__err ? est.quota : null; out.usage = est && !est.__err ? est.usage : null;
    out.persisted = await withTimeout(safe(function () { return navigator.storage.persisted(); }) || Promise.resolve(null), 1000, null);
    out.caches = typeof window.caches; out.openDatabase = typeof window.openDatabase;
    return out;
  }

  // ----------------------------------------------------------------- timing
  function timingProbe() {
    var out = {};
    out.perfMemory = safe(function () { var m = performance.memory; return m ? { jsHeapSizeLimit: m.jsHeapSizeLimit, totalJSHeapSize: m.totalJSHeapSize, usedJSHeapSize: m.usedJSHeapSize } : null; });
    out.timeOrigin = safe(function () { return performance.timeOrigin; });
    out.dateNowDrift = safe(function () { return Date.now() - (performance.timeOrigin + performance.now()); });
    out.loopMs = safe(function () { var t = performance.now(); var x = 0; for (var i = 0; i < 2e6; i++) x += i % 7; return performance.now() - t; });
    out.nowResolution = safe(function () { var ds = []; var last = performance.now(); for (var i = 0; i < 500; i++) { var n = performance.now(); if (n !== last) { ds.push(n - last); last = n; } } ds.sort(function (a, b) { return a - b; }); return ds.length ? ds[0] : null; });
    out.navigationEntry = safe(function () { var e = performance.getEntriesByType('navigation')[0]; return e ? { type: e.type, protocol: e.nextHopProtocol, transferSize: e.transferSize, domInteractive: Math.round(e.domInteractive), responseEnd: Math.round(e.responseEnd) } : null; });
    out.eventCounts = safe(function () { return performance.eventCounts ? performance.eventCounts.size : null; });
    out.probeStartedMs = Date.now() - T0;
    return out;
  }

  // ------------------------------------------------------------- document
  function documentProbe() {
    return {
      referrer: document.referrer, url: location.href, title: document.title, readyState: document.readyState, compatMode: document.compatMode, characterSet: document.characterSet,
      designMode: document.designMode, hasFocus: safe(function () { return document.hasFocus(); }), visibility: document.visibilityState, hidden: document.hidden,
      historyLength: safe(function () { return history.length; }), scrollRestoration: safe(function () { return history.scrollRestoration; }),
      opener: safe(function () { return !!window.opener; }), top: safe(function () { return window.top === window; }), isSecureContext: window.isSecureContext,
      origin: location.origin, protocol: location.protocol, onLine: navigator.onLine,
      cookieEnabled: navigator.cookieEnabled, doNotTrack: safe(function () { return navigator.doNotTrack; }),
      userActivation: safe(function () { return navigator.userActivation ? { hasBeenActive: navigator.userActivation.hasBeenActive, isActive: navigator.userActivation.isActive } : null; }),
      elementFromPoint: safe(function () { var e = document.elementFromPoint(10, 10); return e ? e.tagName : null; })
    };
  }

  // ------------------------------------------------------------------- main
  async function main() {
    progress('__start__', 'running');
    await section('navigator', async function () { return navigatorProbe(); });
    await section('uadata', uaDataProbe);
    await section('screen', async function () { return screenProbe(); });
    await section('timezone', async function () { return timezoneProbe(); });
    await section('document', async function () { return documentProbe(); });
    await section('engine', async function () { return engineProbe(); });
    await section('apis', async function () { return apisProbe(); });
    await section('automation', automationProbe);
    await section('integrity', async function () { return integrityProbe(); });
    await section('canvas', async function () { return canvasProbe(); });
    await section('webgl', async function () { return webglProbe(); });
    await section('audio', audioProbe);
    await section('fonts', async function () { return fontsProbe(); });
    await section('permissions', permissionsProbe);
    await section('media', mediaProbe);
    await section('worker', workerProbe);
    await section('iframe', async function () { return iframeProbe(); });
    await section('storage', storageProbe);
    await section('timing', async function () { return timingProbe(); });
    var r = null;
    var body = { created: SEED.created, label: SEED.label, client: SEED.client, network: SEED.network,
      probes: RESULTS, probe_errors: ERRORS, elapsed_ms: Date.now() - T0, order: ORDER };
    try { r = await post('/analyze', body); r = await r.json(); } catch (e) { r = { error: errStr(e) }; }
    window.__DACTY_REPORT__ = r;
    progress('__done__', 'done', r);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { main(); }); else main();
})();
