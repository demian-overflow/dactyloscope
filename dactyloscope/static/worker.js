/* Dactyloscope — dedicated worker probe: what does the worker scope say about itself? */
(function () {
  function safe(fn) { try { var v = fn(); return v === undefined ? null : v; } catch (e) { return null; } }
  var n = self.navigator || {};
  var out = {
    userAgent: safe(function () { return n.userAgent; }), platform: safe(function () { return n.platform; }),
    hardwareConcurrency: safe(function () { return n.hardwareConcurrency; }), deviceMemory: safe(function () { return n.deviceMemory; }),
    language: safe(function () { return n.language; }), languages: safe(function () { return Array.prototype.slice.call(n.languages || []); }),
    appVersion: safe(function () { return n.appVersion; }), vendor: safe(function () { return n.vendor; }), product: safe(function () { return n.product; }),
    uaData: safe(function () { return n.userAgentData ? { brands: n.userAgentData.brands, mobile: n.userAgentData.mobile, platform: n.userAgentData.platform } : null; }),
    timezone: safe(function () { return Intl.DateTimeFormat().resolvedOptions().timeZone; }),
    offset: safe(function () { return new Date().getTimezoneOffset(); }),
    locale: safe(function () { return Intl.DateTimeFormat().resolvedOptions().locale; }),
    scope: safe(function () { return Object.prototype.toString.call(self); }),
    webdriver: safe(function () { return 'webdriver' in n ? n.webdriver : undefined; }),
    offscreenCanvas: typeof OffscreenCanvas !== 'undefined',
    webgl: safe(function () { if (typeof OffscreenCanvas === 'undefined') return null; var c = new OffscreenCanvas(8, 8); var g = c.getContext('webgl'); if (!g) return false; var d = g.getExtension('WEBGL_debug_renderer_info'); return d ? g.getParameter(d.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER); }),
    stackFirst: safe(function () { return (new Error('x').stack || '').split('\n').slice(0, 2).join('\n'); }),
    globals: safe(function () { return Object.getOwnPropertyNames(self).length; }),
    perfMemory: safe(function () { return !!(self.performance && performance.memory); })
  };
  self.postMessage(out);
})();
