/* Scanner-brain visualization for the Contract Auditor overview page.
 *
 * Standalone: no dependencies, no network beyond the dashboard's own
 * read-only APIs. Every number shown comes from those APIs; when nothing is
 * being scanned the case header shows IDLE and only the ambient particle
 * flow keeps moving.
 *
 * Data sources (polled; paused while the tab is hidden):
 *   /api/monitor/live      counters, running scans, recent scans, alerts (1.5 s)
 *   /api/monitor/scans/ID  stage timeline + finding categories for a case (on demand)
 *   /api/hunt/live?top=1   hunted value today (6 s)
 *   /api/simulate/live     fork-simulation runs (6 s)
 *   /api/exploitable       confirmed EXPLOITABLE_REAL_MONEY items (6 s, optional)
 */
(function () {
  'use strict';

  var root = document.getElementById('scanviz');
  if (!root || root.dataset.svInit) return;
  root.dataset.svInit = '1';

  var API = root.dataset.api || '';
  var REDUCED = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var COL = {
    cyan: '#22e5ff', yellow: '#ffd23f', orange: '#ff8a1f', magenta: '#ff2bd6',
    purple: '#a46bff', red: '#ff1f3d', grey: '#7d8796', pale: '#cfd8e6', white: '#e8f6ff',
    live: '#9fefff'
  };
  var SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
  var SEV_COL = { CRITICAL: COL.orange, HIGH: COL.orange, MEDIUM: COL.yellow, LOW: '#e8c45a', INFORMATIONAL: '#5c6b80' };
  var HONEYPOT_SLUGS = ['quiz-honeypot', 'payout-lure', 'hidden-owner-drain', 'transfer-blocking-token', 'unlimited-owner-mint', 'external-log-gate'];

  // ---------------------------------------------------------------- graph
  // Pipeline stages: 'fetching' / 'compiling' / 'analyzing' / 'done' are the
  // real monitor_stage_events names; the post-analysis nodes are the steps
  // monitor.process_one runs before 'done' (analyzers, triage, value at risk).
  var NODES = [
    { id: 'fetch', label: 'fetch source', stage: 'fetching', x: -0.92, y: -0.05, z: 0.15 },
    { id: 'compile', label: 'compile · solc', stage: 'compiling', x: -0.66, y: -0.32, z: -0.35 },
    { id: 'analyze', label: 'slither + analyzers', stage: 'analyzing', x: -0.40, y: 0.02, z: 0.30 },
    { id: 'honeypot', label: 'honeypot check', x: -0.18, y: -0.40, z: -0.15 },
    { id: 'priv', label: 'privileged auth', x: -0.02, y: 0.30, z: 0.45 },
    { id: 'triage', label: 'triage · fp filter', x: 0.18, y: -0.18, z: -0.40 },
    { id: 'value', label: 'value at risk', x: 0.36, y: 0.12, z: 0.10 },
    { id: 'sim', label: 'fork simulation', x: 0.48, y: -0.44, z: 0.35 },
    { id: 'o_clean', label: 'clean', outcome: true, x: 0.80, y: -0.42, z: 0.0 },
    { id: 'o_find', label: 'findings', outcome: true, x: 0.86, y: -0.16, z: -0.30 },
    { id: 'o_honey', label: 'honeypot · scam', outcome: true, x: 0.82, y: 0.10, z: 0.35 },
    { id: 'o_skip', label: 'no source · skipped', outcome: true, x: -0.70, y: 0.40, z: -0.10 },
    { id: 'o_inc', label: 'incomplete', outcome: true, x: -0.18, y: 0.48, z: -0.45 },
    { id: 'alert', label: 'alert', outcome: true, x: 0.70, y: 0.36, z: -0.05 },
    { id: 'o_exploit', label: 'EXPLOITABLE', outcome: true, x: 0.94, y: 0.30, z: 0.20 },
    // components the stages talk to (labels only, never metrics)
    { id: 'x_scan', label: 'etherscan', aux: true, x: -0.98, y: -0.46, z: -0.55 },
    { id: 'x_srcfy', label: 'sourcify', aux: true, x: -0.86, y: 0.30, z: 0.60 },
    { id: 'x_solc', label: 'solc-select', aux: true, x: -0.50, y: -0.58, z: 0.10 },
    { id: 'x_play', label: 'risk playbook', aux: true, x: 0.06, y: -0.58, z: 0.20 },
    { id: 'x_price', label: 'price feed', aux: true, x: 0.30, y: 0.46, z: -0.50 },
    { id: 'x_anvil', label: 'anvil fork', aux: true, x: 0.62, y: -0.60, z: -0.25 },
    { id: 'x_hist', label: 'scan history', aux: true, x: 0.56, y: 0.56, z: 0.40 }
  ];
  var NODE = {};
  NODES.forEach(function (n, i) { n.i = i; NODE[n.id] = n; n.hit = 0; n.hitCol = null; n.metric = ''; });
  var EDGES = [
    ['fetch', 'compile'], ['compile', 'analyze'], ['analyze', 'honeypot'], ['honeypot', 'priv'],
    ['priv', 'triage'], ['triage', 'value'], ['value', 'sim'], ['value', 'o_clean'], ['value', 'o_find'],
    ['value', 'o_honey'], ['sim', 'o_clean'], ['sim', 'o_find'], ['o_find', 'alert'], ['o_honey', 'alert'],
    ['o_find', 'o_exploit'], ['alert', 'o_exploit'], ['fetch', 'o_skip'], ['compile', 'o_inc'], ['analyze', 'o_inc'],
    ['x_scan', 'fetch'], ['x_srcfy', 'fetch'], ['x_solc', 'compile'], ['x_play', 'triage'], ['x_price', 'value'],
    ['x_anvil', 'sim'], ['x_hist', 'alert'], ['x_play', 'honeypot'], ['x_hist', 'value']
  ].map(function (e) { return [NODE[e[0]], NODE[e[1]]]; });
  var PILLARS = [-0.84, -0.52, -0.20, 0.12, 0.44, 0.76].map(function (x, i) {
    return { x: x, z: (i % 2 ? -0.55 : 0.5) * (i % 3 === 0 ? 0.6 : 1) };
  });
  // web lines: every node to its nearest pillar and two nearest neighbours
  var WEB = [];
  NODES.forEach(function (n) {
    var best = null, bd = 9;
    PILLARS.forEach(function (p) { var d = Math.abs(p.x - n.x) + Math.abs(p.z - n.z) * 0.5; if (d < bd) { bd = d; best = p; } });
    WEB.push({ a: n, p: best });
    var near = NODES.filter(function (m) { return m !== n; }).sort(function (a, b) {
      return dist3(a, n) - dist3(b, n);
    }).slice(0, 2);
    near.forEach(function (m) { if (n.i < m.i) WEB.push({ a: n, b: m }); });
  });
  function dist3(a, b) { var dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z; return dx * dx + dy * dy + dz * dz; }

  // ---------------------------------------------------------------- DOM
  root.classList.add('sv');
  root.innerHTML = [
    '<div class="sv-hud-top">',
    ' <div class="sv-cell sv-cell-count"><div class="sv-k">contracts scanned today</div>',
    '  <div class="sv-big" data-f="scanned">—</div><canvas class="sv-wave"></canvas>',
    '  <div class="sv-sub" data-f="scanned_sub"></div></div>',
    ' <div class="sv-cell"><div class="sv-k">vulnerabilities today</div><div class="sv-mid" data-f="vulns">—</div>',
    '  <div class="sv-sub" data-f="vulns_sub"></div></div>',
    ' <div class="sv-cell"><div class="sv-k">confirmed outsider value at risk today <span class="sv-est">est.</span></div>',
    '  <div class="sv-mid sv-money" data-f="var">—</div><div class="sv-sub" data-f="var_sub"></div></div>',
    ' <div class="sv-cell sv-score"><div class="sv-k">scan step</div><div class="sv-scorebox" data-f="step">—</div>',
    '  <div class="sv-sub" data-f="step_sub"></div></div>',
    '</div>',
    '<div class="sv-stage">',
    ' <canvas class="sv-main" aria-hidden="true"></canvas>',
    ' <div class="sv-case" data-f="case"><div class="sv-case-top"><span data-f="case_no">IDLE</span><span data-f="case_type"></span></div>',
    '  <div class="sv-case-name" data-f="case_name">waiting for next scan</div><div class="sv-case-params" data-f="case_params"></div></div>',
    ' <div class="sv-legend">',
    '  <span style="--c:' + COL.cyan + '">clean</span><span style="--c:' + COL.yellow + '">low/med</span>',
    '  <span style="--c:' + COL.orange + '">high</span><span style="--c:' + COL.magenta + '">honeypot</span>',
    '  <span style="--c:' + COL.purple + '">simulation</span><span style="--c:' + COL.red + '">exploitable</span></div>',
    ' <div class="sv-status" data-f="status"></div>',
    '</div>',
    '<div class="sv-hud-bot">',
    ' <div class="sv-cell"><div class="sv-k">scans / min <span data-f="rate"></span></div><canvas class="sv-rate"></canvas></div>',
    ' <div class="sv-cell sv-cell-wide"><div class="sv-k">severity stream · per scan</div><canvas class="sv-stream"></canvas></div>',
    ' <div class="sv-cell"><div class="sv-k">today · severity mix</div><div class="sv-bars" data-f="bars"></div></div>',
    ' <div class="sv-cell sv-cell-log"><div class="sv-k">scan log</div><ol class="sv-log" data-f="log"></ol></div>',
    '</div>'
  ].join('');
  function F(name) { return root.querySelector('[data-f="' + name + '"]'); }
  var cv = root.querySelector('.sv-main'), ctx = cv.getContext('2d');
  var waveCv = root.querySelector('.sv-wave'), waveCtx = waveCv.getContext('2d');
  var rateCv = root.querySelector('.sv-rate'), rateCtx = rateCv.getContext('2d');
  var strCv = root.querySelector('.sv-stream'), strCtx = strCv.getContext('2d');

  // ---------------------------------------------------------------- state
  var S = {
    live: null, hunt: null, sim: null, exploit: null, apiOk: null, lastOk: 0,
    seenMax: null, seenSim: null, rows: {},       // id -> finished_at (for scans/min)
    queue: [], active: null, logLines: [], stream: [], streamLastT: 0,
    alertsByScan: {}, exploitAddr: {}, simByAddr: {}, staleNoted: {}
  };

  // ---------------------------------------------------------------- utils
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function shortAddr(a) { return a ? a.slice(0, 6) + '…' + a.slice(-4) : ''; }
  function money(v) {
    if (v == null || isNaN(v)) return '—';
    v = Number(v);
    if (v >= 1e9) return '$' + (v / 1e9).toFixed(2) + 'B';
    if (v >= 1e6) return '$' + (v / 1e6).toFixed(2) + 'M';
    if (v >= 1e3) return '$' + (v / 1e3).toFixed(1) + 'K';
    return '$' + v.toFixed(0);
  }
  function fmtInt(v) { return v == null ? '—' : Math.round(v).toLocaleString('en-US'); }
  function hms(ts) {
    try { return new Date(ts * 1000).toLocaleTimeString('en-US', { hour12: false, timeZone: 'America/Detroit' }); }
    catch (e) { return new Date(ts * 1000).toTimeString().slice(0, 8); }
  }
  function dur(s) {
    if (s == null) return '—';
    s = Math.max(0, Math.round(s));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm' + ('0' + (s % 60)).slice(-2) + 's';
    return Math.floor(s / 3600) + 'h' + ('0' + Math.floor((s % 3600) / 60)).slice(-2) + 'm';
  }
  function getJSON(path) {
    return fetch(API + path, { cache: 'no-store', headers: { Accept: 'application/json' } }).then(function (r) {
      if (!r.ok) { var e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return r.json();
    });
  }
  function hexA(hex, a) {
    var n = parseInt(hex.slice(1), 16);
    return 'rgba(' + (n >> 16 & 255) + ',' + (n >> 8 & 255) + ',' + (n & 255) + ',' + a.toFixed(3) + ')';
  }
  function topSev(sc) {
    for (var i = 0; i < SEV_ORDER.length; i++) if (sc && sc[SEV_ORDER[i]] > 0) return SEV_ORDER[i];
    return null;
  }

  // ---------------------------------------------------------------- cases
  // A case is one real scan (or one fork-simulation run) replayed as a trace.
  function caseFromRow(r, detail, live) {
    var c = {
      key: 'm' + r.id, row: r, live: !!live, kind: (r.origin || 'monitor'), path: [], metrics: {},
      color: COL.live, outcome: null, label: '', t0: 0, revealed: 0, doneAt: 0, fade: 1
    };
    var st = r.status, path = ['fetch'];
    var stages = {};
    ((detail && detail.stages) || []).forEach(function (e) { stages[e.stage] = e.at; });
    if (live) {
      if (r.stage === 'compiling' || r.stage === 'analyzing') path.push('compile');
      if (r.stage === 'analyzing') path.push('analyze');
      c.path = path; c.label = 'SCANNING · ' + String(r.stage || '').toUpperCase();
      c.metrics.fetch = r.line_count ? fmtInt(r.line_count) + ' lines' : '';
      return c;
    }
    if (st === 'deferred' || st === 'unverified' || st === 'duplicate') {
      path.push('o_skip'); c.color = COL.grey; c.outcome = st;
      c.metrics.o_skip = st === 'duplicate' ? 'duplicate code' : 'source not verified';
      c.label = st.toUpperCase();
    } else if (st === 'incomplete' || st === 'failed') {
      if (stages.compiling || r.solc_version) path.push('compile');
      if (stages.analyzing) path.push('analyze');
      path.push('o_inc'); c.color = COL.pale; c.outcome = st; c.label = st.toUpperCase();
      c.metrics.o_inc = 'not fully analyzed';
    } else {
      path.push('compile', 'analyze', 'honeypot', 'priv', 'triage', 'value');
      var kept = ((detail && detail.findings_detail) || []).filter(function (f) { return !f.suppressed; });
      var nHoney = 0, nPriv = 0;
      kept.forEach(function (f) {
        var t = String(f.title || '').toLowerCase();
        if (HONEYPOT_SLUGS.some(function (s) { return t.indexOf(s) === 0; })) nHoney++;
        if (t.indexOf('privileged-auth-unprotected') === 0 || t.indexOf('privileged-auth-weak') === 0) nPriv++;
      });
      var haveDetail = !!(detail && detail.findings_detail);
      c.metrics.fetch = r.line_count ? fmtInt(r.line_count) + ' lines' : '';
      c.metrics.compile = r.solc_version ? 'solc ' + r.solc_version : '';
      c.metrics.analyze = (r.findings || 0) + ' kept';
      c.metrics.honeypot = haveDetail || !r.findings ? (nHoney ? nHoney + ' scam flags' : 'none') : '';
      c.metrics.priv = haveDetail || !r.findings ? (nPriv ? nPriv + ' weak/unprot.' : 'ok') : '';
      c.metrics.triage = (r.suppressed_count || 0) + ' suppressed';
      c.metrics.value = r.tvl_usd != null ? 'tvl ' + money(r.tvl_usd) : 'n/a';
      var sim = S.simByAddr[(r.address || '').toLowerCase()];
      if (sim && sim.finished_at && r.finished_at && Math.abs(sim.finished_at - r.finished_at) < 3600) {
        path.push('sim');
        c.metrics.sim = (sim.summary.invariant_pass || 0) + ' pass / ' + (sim.summary.invariant_fail || 0) + ' fail';
      }
      var sev = topSev(r.severity_counts);
      if (S.exploitAddr[(r.address || '').toLowerCase()]) {
        path.push('o_find', 'o_exploit'); c.color = COL.red; c.outcome = 'EXPLOITABLE';
        c.metrics.o_exploit = money(S.exploitAddr[r.address.toLowerCase()].takeable_usd) + ' confirmed';
      } else if (nHoney) {
        path.push('o_honey'); c.color = COL.magenta; c.outcome = 'honeypot';
        c.metrics.o_honey = nHoney + ' flag' + (nHoney > 1 ? 's' : '');
      } else if (r.findings > 0) {
        path.push('o_find'); c.outcome = sev || 'findings';
        c.color = (sev === 'HIGH' || sev === 'CRITICAL') ? COL.orange : (sev === 'INFORMATIONAL' ? COL.cyan : COL.yellow);
        c.metrics.o_find = SEV_ORDER.filter(function (k) { return r.severity_counts[k]; })
          .map(function (k) { return r.severity_counts[k] + k[0]; }).join(' ');
      } else {
        path.push('o_clean'); c.color = COL.cyan; c.outcome = 'clean'; c.metrics.o_clean = '0 findings';
      }
      if (r.scan_id && S.alertsByScan[r.scan_id]) {
        if (path.indexOf('alert') < 0) path.splice(path.length - (c.outcome === 'EXPLOITABLE' ? 1 : 0), 0, 'alert');
        c.metrics.alert = S.alertsByScan[r.scan_id] + ' raised';
      }
      if (r.est_max_loss_usd != null && c.outcome !== 'clean') c.metrics.value += ' · potential impact est. ' + money(r.est_max_loss_usd);
      c.label = c.outcome === 'EXPLOITABLE' ? 'EXPLOITABLE · REAL MONEY' : String(c.outcome).toUpperCase();
    }
    c.path = path;
    return c;
  }
  function caseFromSim(run) {
    var s = run.summary || {};
    var c = {
      key: 's' + run.id, sim: run, kind: 'simulation', live: run.status === 'running', metrics: {},
      path: ['value', 'sim'], color: COL.purple, outcome: run.status, label: 'FORK SIMULATION · ' + String(run.status || '').toUpperCase(),
      t0: 0, revealed: 0, doneAt: 0, fade: 1
    };
    c.metrics.value = run.holder_value_usd != null ? 'holds ' + money(run.holder_value_usd) : '';
    c.metrics.sim = (s.invariant_pass || 0) + ' pass / ' + (s.invariant_fail || 0) + ' fail';
    if (run.status === 'done') {
      if (s.invariant_fail > 0) { c.path.push('o_find'); c.metrics.o_find = s.invariant_fail + ' invariant fail'; }
      else { c.path.push('o_clean'); c.metrics.o_clean = 'invariants hold'; }
    }
    return c;
  }
  function enqueue(c) {
    S.queue.push(c);
    if (S.queue.length > 6) {
      var dropped = S.queue.splice(0, S.queue.length - 6);
      pushLog({ t: Date.now() / 1000, text: '+' + dropped.length + ' scans not animated (backlog)', col: COL.grey });
    }
  }
  function startCase(c, now) {
    c.t0 = now; c.revealed = 0; c.doneAt = 0; c.fade = 1;
    S.active = c;
    renderCaseHeader();
  }
  function upgradeLive(c, finished) {
    // a running scan finished: keep the already-drawn trace, extend it.
    finished.t0 = c.t0; finished.revealed = Math.min(c.revealed, finished.path.length - 1);
    finished.segT0 = performance.now() / 1000;
    S.active = finished; renderCaseHeader();
  }

  // ---------------------------------------------------------------- polling
  var timers = [];
  function poll(fn, ms) { var t = { fn: fn, ms: ms, h: null }; timers.push(t); return t; }
  function runTimer(t) {
    if (document.hidden) { t.h = null; return; }
    Promise.resolve().then(t.fn).catch(function () {}).then(function () {
      if (!document.hidden) t.h = setTimeout(function () { runTimer(t); }, t.ms);
      else t.h = null;
    });
  }
  function startPolling() { timers.forEach(function (t) { if (!t.h) runTimer(t); }); }
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) { startPolling(); kick(); }
  });

  function isStale(r, counters) {
    var est = (r.eta && r.eta.estimated_total_s) || (counters && counters.avg_scan_s) || 60;
    return r.elapsed_s > Math.max(900, est * 10);
  }

  poll(function pollLive() {
    return getJSON('/api/monitor/live?recent=80&sort=recent').then(function (d) {
      S.live = d; S.apiOk = true; S.lastOk = Date.now();
      (d.recent_alerts || []).forEach(function (a) { if (a.scan_id) S.alertsByScan[a.scan_id] = (S.alertsByScan[a.scan_id] || 0); });
      var counted = {};
      (d.recent_alerts || []).forEach(function (a) { if (a.scan_id) counted[a.scan_id] = (counted[a.scan_id] || 0) + 1; });
      Object.keys(counted).forEach(function (k) { S.alertsByScan[k] = counted[k]; });
      var rows = (d.recent_scans || []).slice().sort(function (a, b) { return a.id - b.id; });
      rows.forEach(function (r) { if (r.finished_at) S.rows[r.id] = r.finished_at; });
      var first = S.seenMax === null;
      var fresh = rows.filter(function (r) { return first || r.id > S.seenMax; });
      if (rows.length) S.seenMax = Math.max(S.seenMax || 0, rows[rows.length - 1].id);
      if (first) {
        S.seedLeft = fresh.length;
        fresh.forEach(function (r) { pushStream(r, true); });
        fresh.slice(-9).forEach(function (r) { pushLog(logOf(r)); });
        fresh = fresh.slice(-1); // replay only the most recent finished scan
      } else {
        fresh.forEach(function (r) { pushLog(logOf(r)); pushStream(r, false); });
      }
      var running = (d.current || []).filter(function (r) { return !isStale(r, d.counters); });
      (d.current || []).forEach(function (r) {
        if (isStale(r, d.counters) && !S.staleNoted[r.id]) {
          S.staleNoted[r.id] = 1;
          pushLog({ t: r.started_at, text: (r.contract_name || 'contract') + ' ' + shortAddr(r.address) +
            ' · stuck in ' + r.stage + ' ' + dur(r.elapsed_s) + ' (not animated)', col: COL.grey });
        }
      });
      S.running = running;
      return chain(fresh.map(function (r) {
        return function () {
          var needDetail = (r.findings || 0) > 0 || r.status === 'incomplete' || r.status === 'failed';
          var p = needDetail ? getJSON('/api/monitor/scans/' + r.id).catch(function () { return null; }) : Promise.resolve(null);
          return p.then(function (det) {
            var c = caseFromRow(r, det, false);
            S.queue = S.queue.filter(function (q) { return q.key !== c.key; });
            if (S.active && S.active.live && S.active.key === c.key) upgradeLive(S.active, c);
            else enqueue(c);
          });
        };
      })).then(function () {
        running.forEach(function (r) {
          var key = 'm' + r.id;
          var known = (S.active && S.active.key === key) || S.queue.some(function (q) { return q.key === key; });
          var c = caseFromRow(r, null, true);
          if (!known) enqueue(c);
          else if (S.active && S.active.key === key && S.active.live) {
            c.t0 = S.active.t0; c.revealed = S.active.revealed; c.segT0 = S.active.segT0; S.active = c; renderCaseHeader();
          }
        });
        renderHud();
      });
    }).catch(function () { S.apiOk = false; renderHud(); });
  }, 1500);

  poll(function pollSlow() {
    var a = getJSON('/api/hunt/live?top=1').then(function (d) { S.hunt = d; }).catch(function () {});
    var b = getJSON('/api/simulate/live?limit=10').then(function (d) {
      S.sim = d;
      var runs = (d.runs || []).slice().sort(function (x, y) { return x.id - y.id; });
      runs.forEach(function (run) {
        var addr = (run.address || '').toLowerCase();
        if (addr && run.status === 'done') S.simByAddr[addr] = run;
      });
      var first = S.seenSim === null;
      var fresh = runs.filter(function (r) { return !first && r.id > S.seenSim && r.status === 'done'; });
      if (runs.length) S.seenSim = Math.max(S.seenSim || 0, runs[runs.length - 1].id);
      fresh.forEach(function (run) {
        enqueue(caseFromSim(run));
        var s = run.summary || {};
        pushLog({ t: run.finished_at || Date.now() / 1000, text: 'sim ' + (run.protocol || shortAddr(run.address)) +
          ' · ' + (s.invariant_pass || 0) + ' pass / ' + (s.invariant_fail || 0) + ' fail', col: COL.purple });
      });
    }).catch(function () {});
    var c = getJSON('/api/exploitable').then(function (d) {
      S.exploit = d; S.exploitAddr = {};
      ((d && d.items) || []).forEach(function (i) { if (i.address) S.exploitAddr[i.address.toLowerCase()] = i; });
    }).catch(function () { S.exploit = null; });
    return Promise.all([a, b, c]).then(renderHud);
  }, 6000);

  function chain(fns) { return fns.reduce(function (p, f) { return p.then(f); }, Promise.resolve()); }

  // ---------------------------------------------------------------- HUD (DOM)
  var counterAnim = { from: 0, to: null, t0: 0, shown: null };
  function logOf(r) {
    var res, col;
    var c = caseFromRow(r, null, false);
    res = c.outcome === 'clean' ? 'clean' : (c.outcome || r.status);
    if (r.findings > 0) res = r.findings + ' findings · top ' + (topSev(r.severity_counts) || '?');
    col = c.color;
    return { t: r.finished_at || r.started_at, text: (r.contract_name || 'unnamed') + ' ' + shortAddr(r.address) + ' · ' + res, col: col, origin: r.origin };
  }
  function pushLog(l) {
    S.logLines.unshift(l); if (S.logLines.length > 40) S.logLines.length = 40;
    var ol = F('log');
    ol.innerHTML = S.logLines.slice(0, 9).map(function (x, i) {
      return '<li' + (i === 0 ? ' class="sv-new"' : '') + ' style="--c:' + x.col + '"><span class="sv-t">' + hms(x.t) + '</span>' +
        (x.origin ? '<span class="sv-o">' + esc(x.origin) + '</span>' : '') + esc(x.text) + '</li>';
    }).join('');
  }
  function pushStream(r, seed) {
    var now = performance.now() / 1000;
    // seeded history is spaced evenly to the left of 'now'; live scans enter at the right edge
    var t = seed ? now - (S.seedLeft--) * 0.9 : Math.max(now, S.streamLastT + 0.6);
    S.streamLastT = Math.max(S.streamLastT, t);
    var segs = [];
    var sc = r.severity_counts || {};
    if (r.status === 'done' && r.findings > 0) SEV_ORDER.forEach(function (k) { if (sc[k]) segs.push({ n: sc[k], c: SEV_COL[k] }); });
    else if (r.status === 'done') segs.push({ n: 1, c: COL.cyan, thin: true });
    else segs.push({ n: 1, c: r.status === 'incomplete' ? COL.pale : COL.grey, dot: true });
    if (S.exploitAddr[(r.address || '').toLowerCase()]) segs = [{ n: 6, c: COL.red }];
    S.stream.push({ t: t, segs: segs });
    if (S.stream.length > 400) S.stream.splice(0, S.stream.length - 400);
  }
  function renderHud() {
    var d = S.live, c = (d && d.counters) || {};
    if (d) {
      if (counterAnim.to !== c.audited_today) {
        counterAnim.from = counterAnim.shown == null ? Math.max(0, (c.audited_today || 0) - 40) : counterAnim.shown;
        counterAnim.to = c.audited_today || 0; counterAnim.t0 = performance.now();
      }
      F('scanned_sub').textContent = 'all-time ' + fmtInt(c.audited_all_time) + ' · queue ' + fmtInt(c.queue_pending) +
        ' · could not analyze ' + fmtInt(c.could_not_analyze_today);
      F('vulns').textContent = fmtInt(c.findings_today_total);
      var ft = c.findings_today || {};
      F('vulns_sub').innerHTML = SEV_ORDER.filter(function (k) { return ft[k]; }).map(function (k) {
        return '<b style="color:' + SEV_COL[k] + '">' + (k === 'INFORMATIONAL' ? 'INFO' : k) + ' ' + fmtInt(ft[k]) + '</b>';
      }).join(' ') + ' · <span>' + fmtInt(c.suppressed_today) + ' suppressed</span>';
      F('var').textContent = money(c.value_at_risk_found_today_usd);
      var hc = (S.hunt && S.hunt.counters) || {};
      var exN = (S.exploit && S.exploit.items && S.exploit.items.length) || 0;
      var unver = c.unverified_exposure_today_usd;
      F('var_sub').innerHTML = 'unverified exposure ' + esc(money(unver)) +
        ' · hunted holdings scanned today ' + esc(money(hc.hunted_value_scanned_today_usd)) +
        (exN ? ' · <b class="sv-redtxt">' + exN + ' EXPLOITABLE</b>' : ' · 0 confirmed exploitable');
      renderBars(ft);
    }
    var st = F('status');
    if (S.apiOk === false) { st.textContent = 'OFFLINE · dashboard API unreachable · last ok ' + (S.lastOk ? hms(S.lastOk / 1000) : 'never'); st.className = 'sv-status sv-bad'; }
    else if (d) { st.textContent = 'live · block ' + fmtInt(c.last_block) + ' · ' + fmtInt(c.polls_last_hour) + ' polls/h · avg scan ' + (c.avg_scan_s != null ? c.avg_scan_s + 's' : '—'); st.className = 'sv-status'; }
    renderCaseHeader();
  }
  function renderBars(ft) {
    var keys = ['HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
    var tot = keys.reduce(function (a, k) { return a + (ft[k] || 0); }, 0) + (ft.CRITICAL || 0);
    var html = keys.map(function (k) {
      var n = (ft[k] || 0) + (k === 'HIGH' ? (ft.CRITICAL || 0) : 0);
      var on = tot ? Math.round(20 * n / tot) : 0;
      if (n && !on) on = 1;
      var segs = '';
      for (var i = 0; i < 20; i++) segs += '<i' + (i < on ? ' class="on"' : '') + '></i>';
      return '<div class="sv-bar" style="--c:' + SEV_COL[k] + '"><span>' + (k === 'INFORMATIONAL' ? 'INFO' : k) + '</span><div>' + segs + '</div><em>' + fmtInt(n) + '</em></div>';
    }).join('');
    var a = S.active && !(S.active.doneAt && !S.queue.length && S.active.fade <= 0.02) ? S.active : null;
    var steps = a ? a.path.length : 0, done = a ? Math.min(Math.floor(a.revealed) + 1, steps) : 0;
    var segs2 = '';
    for (var j = 0; j < 20; j++) segs2 += '<i' + (steps && j < Math.round(20 * done / steps) ? ' class="on"' : '') + '></i>';
    html += '<div class="sv-bar" style="--c:' + (a ? a.color : COL.grey) + '"><span>STEP</span><div>' + segs2 + '</div><em>' + (a ? done + '/' + steps : '—') + '</em></div>';
    F('bars').innerHTML = html;
  }
  var lastHeaderKey = '';
  function renderCaseHeader() {
    var a = S.active, box = F('case');
    var idle = !a || (a.doneAt && !S.queue.length && a.fade <= 0.02);
    if (idle) {
      var hk = 'idle' + (S.apiOk === false);
      box.style.setProperty('--c', COL.grey);
      F('case_no').textContent = S.apiOk === false ? 'OFFLINE' : 'IDLE';
      F('case_type').textContent = S.live ? 'queue ' + fmtInt(S.live.counters.queue_pending) : '';
      F('case_name').textContent = 'waiting for next scan';
      var last = S.logLines[0];
      F('case_params').textContent = last ? 'last: ' + last.text : '';
      F('step').textContent = 'IDLE'; F('step').style.setProperty('--c', COL.grey);
      F('step_sub').textContent = 'no scan running';
      lastHeaderKey = hk; return;
    }
    box.style.setProperty('--c', a.color);
    var r = a.row, sim = a.sim;
    var today = S.live && S.live.counters ? S.live.counters.audited_today : null;
    F('case_no').textContent = sim ? 'SIM ' + ('000' + sim.id).slice(-3) : 'SCAN #' + r.id + (today != null ? ' / ' + fmtInt(today) + ' today' : '');
    F('case_type').textContent = (a.kind || '').toUpperCase() + ' · ' + a.label;
    if (sim) {
      F('case_name').textContent = (sim.protocol || 'fork simulation') + ' ' + shortAddr(sim.address);
      F('case_params').textContent = 'duration ' + dur(sim.duration_s) + ' · oracle ' + (((sim.summary || {}).oracle_kinds || []).join(',') || '—') +
        ' · trust nodes ' + ((sim.summary || {}).trust_nodes != null ? sim.summary.trust_nodes : '—');
    } else {
      F('case_name').textContent = (r.contract_name || 'unnamed contract') + ' ' + shortAddr(r.address);
      var p = [];
      if (r.line_count) p.push(fmtInt(r.line_count) + ' lines');
      if (r.file_count) p.push(r.file_count + ' files');
      if (r.solc_version) p.push('solc ' + r.solc_version);
      if (a.live) {
        p.push('elapsed ' + dur(r.elapsed_s));
        var rem = r.eta && r.eta.estimated_remaining_s;
        p.push(rem == null ? 'time left —' : (r.eta.overrun ? 'over estimate' : 'time left ~' + dur(rem)));
      } else if (r.duration_s != null) p.push('took ' + dur(r.duration_s));
      if (r.tvl_usd) p.push('tvl ' + money(r.tvl_usd));
      F('case_params').textContent = p.join(' · ');
    }
    var steps = a.path.length, done = Math.min(Math.floor(a.revealed) + 1, steps);
    F('step').textContent = done + '/' + steps; F('step').style.setProperty('--c', a.color);
    F('step_sub').textContent = (NODE[a.path[Math.min(done, steps) - 1]] || {}).label || '';
  }

  // ---------------------------------------------------------------- render
  var W = 0, H = 0, DPR = 1, gridCv = document.createElement('canvas');
  var particles = [], pTarget = REDUCED ? 300 : 1800, P_MAX = 5000, P_MIN = 300;
  var spr = makeSprite();
  function makeSprite() {
    var s = document.createElement('canvas'); s.width = s.height = 16;
    var g = s.getContext('2d'), gr = g.createRadialGradient(8, 8, 0, 8, 8, 8);
    gr.addColorStop(0, 'rgba(255,255,255,1)'); gr.addColorStop(0.25, 'rgba(210,245,255,0.75)'); gr.addColorStop(1, 'rgba(120,220,255,0)');
    g.fillStyle = gr; g.fillRect(0, 0, 16, 16); return s;
  }
  function sizeCanvas(c, g) {
    var r = c.getBoundingClientRect();
    var w = Math.max(1, Math.round(r.width * DPR)), h = Math.max(1, Math.round(r.height * DPR));
    if (c.width !== w || c.height !== h) { c.width = w; c.height = h; }
    g.setTransform(DPR, 0, 0, DPR, 0, 0);
    return { w: r.width, h: r.height };
  }
  function resize() {
    DPR = Math.min(window.devicePixelRatio || 1, 2);
    var s = sizeCanvas(cv, ctx); W = s.w; H = s.h;
    sizeCanvas(waveCv, waveCtx); sizeCanvas(rateCv, rateCtx); sizeCanvas(strCv, strCtx);
    gridCv.width = cv.width; gridCv.height = cv.height;
    var g = gridCv.getContext('2d'); g.setTransform(DPR, 0, 0, DPR, 0, 0);
    g.clearRect(0, 0, W, H);
    g.strokeStyle = 'rgba(120,170,220,0.045)'; g.lineWidth = 1; g.beginPath();
    for (var x = 0; x < W; x += 28) { g.moveTo(x + 0.5, 0); g.lineTo(x + 0.5, H); }
    for (var y = 0; y < H; y += 28) { g.moveTo(0, y + 0.5); g.lineTo(W, y + 0.5); }
    g.stroke();
    var vg = g.createRadialGradient(W / 2, H / 2, Math.min(W, H) * 0.2, W / 2, H / 2, Math.max(W, H) * 0.7);
    vg.addColorStop(0, 'rgba(8,11,16,0)'); vg.addColorStop(1, 'rgba(8,11,16,0.85)');
    g.fillStyle = vg; g.fillRect(0, 0, W, H);
  }
  if (window.ResizeObserver) new ResizeObserver(function () { resize(); kick(); }).observe(root);
  window.addEventListener('resize', resize);

  // camera
  var cam = { yaw: 0, zoom: 1, panX: 0, panY: 0 };
  function project(x, y, z, out) {
    var cy = Math.cos(cam.yaw), sy = Math.sin(cam.yaw);
    var rx = x * cy - z * sy, rz = x * sy + z * cy;
    var D = 3.2, s = D / (D + rz) * cam.zoom;
    out.x = W / 2 + (rx + cam.panX) * s * W * 0.43;
    out.y = H * 0.5 + (y + cam.panY) * s * H * 0.66;
    out.s = s; out.d = Math.min(1, Math.max(0, (rz + 1.1) / 2.2)); // 0 front .. 1 back
    return out;
  }
  NODES.forEach(function (n) { n.p = { x: 0, y: 0, s: 1, d: 0 }; });
  PILLARS.forEach(function (p) { p.top = { x: 0, y: 0, s: 1, d: 0 }; p.bot = { x: 0, y: 0, s: 1, d: 0 }; });

  function spawn(p) {
    var r = Math.random();
    if (r < 0.45) { p.k = 0; p.a = PILLARS[(Math.random() * PILLARS.length) | 0]; p.u = Math.random(); p.v = 0.05 + Math.random() * 0.12; p.off = (Math.random() - 0.5) * 0.02; }
    else { p.k = 1; p.e = EDGES[(Math.random() * EDGES.length) | 0]; p.u = Math.random(); p.v = 0.08 + Math.random() * 0.25; p.off = (Math.random() - 0.5) * 0.015; }
    p.b = 0.35 + Math.random() * 0.65; p.r = Math.random() < 0.08 ? 2.2 : 1.1;
    return p;
  }
  function setParticleCount(n) {
    while (particles.length < n) particles.push(spawn({}));
    if (particles.length > n) particles.length = n;
  }

  var last = 0, frameEma = 16, adaptT = 0, raf = 0, t = 0, tmp = { x: 0, y: 0, s: 1, d: 0 };
  var reducedLast = 0;
  function kick() { if (!raf && !document.hidden) raf = requestAnimationFrame(frame); }
  document.addEventListener('visibilitychange', function () { if (document.hidden && raf) { cancelAnimationFrame(raf); raf = 0; } });

  function frame(ts) {
    raf = 0;
    if (document.hidden) return;
    var now = ts / 1000, dt = last ? Math.min(0.1, now - last) : 0.016;
    if (REDUCED && now - reducedLast < 0.5) { raf = requestAnimationFrame(frame); return; }
    reducedLast = now;
    var t0 = performance.now();
    last = now; t += REDUCED ? 0 : dt;
    update(now, dt);
    draw(now, dt);
    drawWave(now); drawRate(); drawStream(now);
    // adaptive particle cap: hold ~60 fps
    var cost = performance.now() - t0;
    frameEma = frameEma * 0.92 + cost * 0.08;
    adaptT += dt;
    if (!REDUCED && adaptT > 0.5) {
      adaptT = 0;
      if (frameEma > 9 && pTarget > P_MIN) pTarget = Math.max(P_MIN, Math.round(pTarget * 0.85));
      else if (frameEma < 5 && pTarget < P_MAX) pTarget = Math.min(P_MAX, Math.round(pTarget * 1.08));
    }
    setParticleCount(pTarget);
    raf = requestAnimationFrame(frame);
  }

  var TRACE_TIME = 1.25, HOLD = 1.8, FADE = 0.7;
  function update(now, dt) {
    // camera: slow pan / zoom / yaw
    if (!REDUCED) {
      cam.yaw = 0.32 * Math.sin(t * 0.06) + 0.06 * Math.sin(t * 0.17);
      cam.zoom = 1 + 0.06 * Math.sin(t * 0.045 + 1);
      cam.panX = 0.03 * Math.sin(t * 0.05); cam.panY = 0.02 * Math.cos(t * 0.04);
    }
    NODES.forEach(function (n) { project(n.x, n.y, n.z, n.p); });
    PILLARS.forEach(function (p) { project(p.x, -0.95, p.z, p.top); project(p.x, 0.95, p.z, p.bot); });

    // counter tween
    if (counterAnim.to != null) {
      var k = Math.min(1, (performance.now() - counterAnim.t0) / 1400);
      k = 1 - Math.pow(1 - k, 3);
      var v = Math.round(counterAnim.from + (counterAnim.to - counterAnim.from) * k);
      if (v !== counterAnim.shown) { counterAnim.shown = v; F('scanned').textContent = fmtInt(v); }
    }

    // case lifecycle
    var a = S.active;
    // a running case yields if other finished scans are waiting (monitor + hunt can run in parallel)
    var liveYield = a && a.live && S.queue.length && now - a.t0 > 4 && S.queue.some(function (q) { return !q.live; });
    if (!a || liveYield || (a.doneAt && (S.queue.length ? now - a.doneAt > HOLD : false))) {
      if (S.queue.length) { clearHits(); startCase(S.queue.shift(), now); a = S.active; a.segT0 = now; }
    }
    if (a) {
      var segs = a.path.length - 1, segDur = Math.max(0.12, TRACE_TIME / Math.max(1, segs));
      var target = a.live ? Math.max(0, a.path.length - 1) : segs;
      if (REDUCED) a.revealed = target;
      else if (a.revealed < target) {
        a.revealed = Math.min(target, a.revealed + dt / segDur);
      }
      // mark hit nodes
      for (var i = 0; i <= Math.floor(a.revealed + 1e-6) && i < a.path.length; i++) {
        var n = NODE[a.path[i]];
        if (n.hitKey !== a.key) { n.hitKey = a.key; n.hit = now; n.hitCol = a.color; }
        n.metric = a.metrics[n.id] || '';
      }
      if (!a.live && a.revealed >= segs && !a.doneAt) { a.doneAt = now; renderCaseHeader(); }
      if (a.doneAt && !S.queue.length) {
        var since = now - a.doneAt;
        a.fade = since < HOLD + 4 ? 1 : Math.max(0.0, 1 - (since - HOLD - 4) / 3);
        if (a.fade <= 0.02 && !a.idleShown) { a.idleShown = true; renderCaseHeader(); }
      } else if (a.doneAt) {
        var s2 = now - a.doneAt; a.fade = Math.max(0, 1 - Math.max(0, s2 - HOLD + FADE) / FADE);
      }
      if (Math.floor(now * 4) !== a._hb) { a._hb = Math.floor(now * 4); renderBars((S.live && S.live.counters.findings_today) || {}); renderCaseHeader(); }
    }

    // particles
    for (var j = 0; j < particles.length; j++) {
      var p = particles[j];
      p.u += p.v * dt * (REDUCED ? 0 : 1);
      if (p.u > 1) spawn(p), p.u = 0;
    }
  }
  function clearHits() { NODES.forEach(function (n) { n.hitKey = null; n.metric = ''; }); }

  function draw(now) {
    ctx.globalCompositeOperation = 'source-over';
    ctx.fillStyle = '#080b10'; ctx.fillRect(0, 0, W, H);
    ctx.drawImage(gridCv, 0, 0, W, H);
    var a = S.active, fade = a ? a.fade : 0;
    var exploitOn = S.exploit && S.exploit.visible;

    // pillars
    ctx.globalCompositeOperation = 'lighter';
    PILLARS.forEach(function (p) {
      var al = 0.10 + 0.10 * (1 - p.top.d);
      var g = ctx.createLinearGradient(0, p.top.y, 0, p.bot.y);
      g.addColorStop(0, 'rgba(140,220,255,0)'); g.addColorStop(0.5, 'rgba(140,220,255,' + al + ')'); g.addColorStop(1, 'rgba(140,220,255,0)');
      ctx.strokeStyle = g; ctx.lineWidth = 6 * p.top.s; ctx.beginPath(); ctx.moveTo(p.top.x, p.top.y); ctx.lineTo(p.bot.x, p.bot.y); ctx.stroke();
      ctx.lineWidth = 1; ctx.stroke();
    });
    // web + edges
    ctx.lineWidth = 0.6;
    WEB.forEach(function (w) {
      var A = w.a.p, B;
      if (w.p) { project(w.p.x, w.a.y, w.p.z, tmp); B = tmp; } else B = w.b.p;
      ctx.strokeStyle = 'rgba(150,200,255,' + (0.05 + 0.05 * (1 - (A.d + B.d) / 2)).toFixed(3) + ')';
      ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.lineTo(B.x, B.y); ctx.stroke();
    });
    EDGES.forEach(function (e) {
      var A = e[0].p, B = e[1].p, aux = e[0].aux || e[1].aux;
      ctx.strokeStyle = 'rgba(160,230,255,' + ((aux ? 0.07 : 0.16) * (1.2 - (A.d + B.d) / 2)).toFixed(3) + ')';
      ctx.lineWidth = aux ? 0.6 : 1;
      ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.lineTo(B.x, B.y); ctx.stroke();
    });

    // particles (additive sprites)
    for (var j = 0; j < particles.length; j++) {
      var p = particles[j], x, y, d, s;
      if (p.k === 0) {
        var yy = -0.95 + p.u * 1.9;
        project(p.a.x + p.off, yy, p.a.z, tmp);
      } else {
        var A2 = p.e[0], B2 = p.e[1];
        project(A2.x + (B2.x - A2.x) * p.u, A2.y + (B2.y - A2.y) * p.u + p.off, A2.z + (B2.z - A2.z) * p.u, tmp);
      }
      x = tmp.x; y = tmp.y; d = tmp.d; s = tmp.s;
      var edgeFade = p.k === 0 ? Math.sin(p.u * Math.PI) : 1;
      ctx.globalAlpha = p.b * (1 - 0.65 * d) * edgeFade;
      var sz = p.r * s * (1 + 2.5 * d) * 2; // back particles: larger + dimmer = blurred
      ctx.drawImage(spr, x - sz / 2, y - sz / 2, sz, sz);
    }
    ctx.globalAlpha = 1;

    // trace
    if (a && a.path.length && fade > 0) {
      var col = a.color, rv = a.revealed;
      ctx.lineCap = 'round'; ctx.lineJoin = 'round';
      for (var pass = 0; pass < 2; pass++) {
        ctx.strokeStyle = hexA(col, (pass ? 0.95 : 0.22) * fade);
        ctx.lineWidth = pass ? 2.6 : 9;
        ctx.shadowColor = col; ctx.shadowBlur = pass ? 14 : 0;
        ctx.beginPath();
        var P0 = NODE[a.path[0]].p; ctx.moveTo(P0.x, P0.y);
        for (var i = 1; i < a.path.length; i++) {
          var segp = Math.min(1, Math.max(0, rv - (i - 1)));
          if (segp <= 0) break;
          var Pa = NODE[a.path[i - 1]].p, Pb = NODE[a.path[i]].p;
          ctx.lineTo(Pa.x + (Pb.x - Pa.x) * segp, Pa.y + (Pb.y - Pa.y) * segp);
        }
        ctx.stroke();
      }
      ctx.shadowBlur = 0;
      // head
      var hi = Math.min(a.path.length - 1, Math.floor(rv)), hf = rv - hi;
      var H1 = NODE[a.path[hi]].p, H2 = NODE[a.path[Math.min(hi + 1, a.path.length - 1)]].p;
      var hx = H1.x + (H2.x - H1.x) * hf, hy = H1.y + (H2.y - H1.y) * hf;
      var pulse = a.live ? 0.6 + 0.4 * Math.sin(now * 6) : 1;
      ctx.globalAlpha = fade * pulse;
      ctx.drawImage(spr, hx - 14, hy - 14, 28, 28);
      ctx.fillStyle = col; ctx.beginPath(); ctx.arc(hx, hy, 3, 0, 6.283); ctx.fill();
      ctx.globalAlpha = 1;
    }
    ctx.globalCompositeOperation = 'source-over';

    // nodes, back to front
    var order = NODES.slice().sort(function (x, y) { return y.p.d - x.p.d; });
    order.forEach(function (n) { drawNode(n, now, a, fade, exploitOn); });
  }

  function drawNode(n, now, a, fade, exploitOn) {
    var P = n.p, d = P.d, isHit = a && n.hitKey === a.key && fade > 0;
    var alpha = (n.aux ? 0.38 : 0.85) * (1 - 0.55 * d);
    var fs = Math.max(9, (n.outcome ? 12 : 11.5) * P.s * (1 - 0.15 * d));
    ctx.font = (n.id === 'o_exploit' ? '700 ' : '500 ') + fs.toFixed(1) + 'px "JetBrains Mono", ui-monospace, Menlo, monospace';
    var label = n.id === 'o_exploit' ? n.label : n.label.toLowerCase();
    var tw = ctx.measureText(label).width;
    var x = P.x, y = P.y;
    // node core
    ctx.globalCompositeOperation = 'lighter';
    ctx.globalAlpha = alpha;
    ctx.fillStyle = n.aux ? '#5d7590' : '#bfefff';
    ctx.fillRect(x - 2, y - 2, 4, 4);
    if (exploitOn && n.id === 'o_exploit') {
      var pr = 0.5 + 0.5 * Math.sin(now * 5);
      ctx.globalAlpha = 0.5 + 0.5 * pr; ctx.shadowColor = COL.red; ctx.shadowBlur = 20;
      ctx.strokeStyle = COL.red; ctx.lineWidth = 2; ctx.strokeRect(x + 8 - 5, y - fs - 4, tw + 10, fs + 10); ctx.shadowBlur = 0;
    }
    ctx.globalCompositeOperation = 'source-over';
    // label (back nodes: blurred via shadow + dim)
    ctx.globalAlpha = isHit ? Math.max(alpha, fade) : alpha;
    ctx.fillStyle = isHit ? '#ffffff' : (n.id === 'o_exploit' ? hexA(COL.red, 0.8) : (n.aux ? '#7f93ab' : '#cfe6f5'));
    if (d > 0.55 && !isHit) { ctx.shadowColor = 'rgba(190,230,255,0.9)'; ctx.shadowBlur = 6 * d; }
    ctx.fillText(label, x + 8, y + fs * 0.35);
    ctx.shadowBlur = 0;
    if (isHit) {
      var col = n.hitCol || a.color, age = now - n.hit;
      ctx.globalAlpha = fade;
      ctx.strokeStyle = col; ctx.lineWidth = 1.5; ctx.shadowColor = col; ctx.shadowBlur = 16;
      var bx = x + 3, by = y - fs * 0.85, bw = tw + 12, bh = fs * 1.7;
      ctx.strokeRect(bx, by, bw, bh);
      // corner ticks
      ctx.lineWidth = 2.5; ctx.beginPath();
      ctx.moveTo(bx, by + 5); ctx.lineTo(bx, by); ctx.lineTo(bx + 5, by);
      ctx.moveTo(bx + bw - 5, by + bh); ctx.lineTo(bx + bw, by + bh); ctx.lineTo(bx + bw, by + bh - 5); ctx.stroke();
      ctx.shadowBlur = 0;
      if (age < 0.7 && !REDUCED) { // pulse ring
        var k = age / 0.7;
        ctx.globalAlpha = (1 - k) * fade; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, 4 + k * 26, 0, 6.283); ctx.stroke();
        ctx.globalAlpha = (1 - k) * 0.35 * fade; ctx.fillStyle = col;
        ctx.fillRect(bx, by, bw, bh);
      }
      if (n.metric) {
        ctx.globalAlpha = fade;
        ctx.font = '500 ' + Math.max(9, fs * 0.82).toFixed(1) + 'px "JetBrains Mono", ui-monospace, Menlo, monospace';
        ctx.fillStyle = col;
        ctx.fillText(n.metric.toUpperCase(), bx + 2, by + bh + fs * 0.95);
      }
    }
    ctx.globalAlpha = 1;
  }

  // ---------------------------------------------------------------- small charts
  function scansPerMinSeries() {
    var nowS = Date.now() / 1000, buckets = new Array(30).fill(0), keys = Object.keys(S.rows), minT = Infinity;
    for (var i = 0; i < keys.length; i++) {
      var f = S.rows[keys[i]], age = nowS - f;
      if (age > 1800) { delete S.rows[keys[i]]; continue; }
      if (f < minT) minT = f;
      buckets[29 - Math.min(29, Math.floor(age / 60))]++;
    }
    // minutes older than the oldest row we have seen are unknown, not zero
    var known = isFinite(minT) ? Math.min(30, Math.ceil((nowS - minT) / 60)) : 0;
    return { b: buckets, known: known };
  }
  var rateCache = { at: 0, v: null };
  function drawRate() {
    var r = rateCv.getBoundingClientRect(), w = r.width, h = r.height, g = rateCtx;
    g.clearRect(0, 0, w, h);
    var nowMs = Date.now();
    if (!rateCache.v || nowMs - rateCache.at > 1000) { rateCache = { at: nowMs, v: scansPerMinSeries() }; F('rate').textContent = rateCache.v.known ? '· now ' + rateCache.v.b[29] : ''; }
    var sr = rateCache.v, max = Math.max(4, Math.max.apply(null, sr.b));
    g.strokeStyle = 'rgba(120,170,220,0.12)'; g.lineWidth = 1;
    for (var q = 1; q < 4; q++) { g.beginPath(); g.moveTo(0, h * q / 4); g.lineTo(w, h * q / 4); g.stroke(); }
    var start = 30 - sr.known;
    g.beginPath();
    for (var i = start; i < 30; i++) {
      var x = (i / 29) * w, y = h - 3 - (sr.b[i] / max) * (h - 8);
      if (i === start) g.moveTo(x, y); else g.lineTo(x, y);
    }
    g.strokeStyle = COL.cyan; g.lineWidth = 1.5; g.shadowColor = COL.cyan; g.shadowBlur = 8; g.stroke(); g.shadowBlur = 0;
    g.lineTo(w, h); g.lineTo((start / 29) * w, h); g.closePath(); g.fillStyle = 'rgba(34,229,255,0.08)'; g.fill();
    g.fillStyle = '#5d6f86'; g.font = '9px "JetBrains Mono", monospace'; g.fillText('MAX ' + max, 2, 10); g.fillText('-30m', 2, h - 2);
  }
  function drawStream(now) {
    var r = strCv.getBoundingClientRect(), w = r.width, h = r.height, g = strCtx;
    g.clearRect(0, 0, w, h);
    g.strokeStyle = 'rgba(120,170,220,0.10)'; g.beginPath(); g.moveTo(0, h / 2); g.lineTo(w, h / 2); g.stroke();
    var speed = 9, colW = 4;
    g.globalCompositeOperation = 'lighter';
    for (var i = S.stream.length - 1; i >= 0; i--) {
      var c = S.stream[i], x = w - 8 - (now - c.t) * speed;
      if (x < -colW) { S.stream.splice(0, i + 1); break; }
      if (x > w) continue;
      var tot = c.segs.reduce(function (a2, s) { return a2 + s.n; }, 0), y = h / 2;
      var hgt = Math.min(h - 6, 6 + Math.log2(1 + tot) * 9);
      var y0 = y - hgt / 2;
      c.segs.forEach(function (s) {
        var sh = s.dot ? 3 : (s.thin ? 4 : hgt * s.n / tot);
        g.fillStyle = s.c; g.shadowColor = s.c; g.shadowBlur = 6;
        g.fillRect(x, s.dot || s.thin ? y - sh / 2 : y0, s.dot ? 3 : colW, sh);
        y0 += sh;
      });
    }
    g.shadowBlur = 0; g.globalCompositeOperation = 'source-over';
  }
  function drawWave(now) {
    var r = waveCv.getBoundingClientRect(), w = r.width, h = r.height, g = waveCtx;
    g.clearRect(0, 0, w, h);
    var rate = rateCache.v ? rateCache.v.b[29] : 0;
    var busy = (S.running && S.running.length) || (S.active && !S.active.doneAt);
    var amp = Math.min(1, 0.12 + rate / 30 + (busy ? 0.35 : 0)) * (h / 2 - 2);
    var col = S.active && S.active.fade > 0.05 ? S.active.color : COL.cyan;
    for (var k = 0; k < 2; k++) {
      g.beginPath();
      for (var x = 0; x <= w; x += 2) {
        var y = h / 2 + Math.sin(x * 0.06 + (REDUCED ? 0 : now * (3 + k * 1.7)) + k) * amp * (k ? 0.5 : 1) * Math.sin(Math.PI * x / w);
        if (x === 0) g.moveTo(x, y); else g.lineTo(x, y);
      }
      g.strokeStyle = hexA(col, k ? 0.35 : 0.9); g.lineWidth = k ? 1 : 1.5; g.shadowColor = col; g.shadowBlur = k ? 0 : 8; g.stroke();
    }
    g.shadowBlur = 0;
  }

  // ---------------------------------------------------------------- go
  resize();
  setParticleCount(pTarget);
  renderCaseHeader();
  startPolling();
  kick();
  window.__scanviz = { state: S, stats: function () { return { particles: particles.length, frameMs: +frameEma.toFixed(2), reduced: REDUCED }; } };
})();
