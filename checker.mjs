// checker.mjs v2 — runs inside GitHub Actions (Node 20+, no dependencies)
//
// Per run:
//  1. get sources + remembered winners + recently-published keys from the Worker
//  2. re-test previous winners first (cheap, most likely to still work)
//  3. wide funnel: scrape every source -> TCP-test ALL from the runner (free) -> group by /24 network
//  4. spend the limited Check-Host budget smartly (one per network first, then dig into networks that pass)
//  5. if nothing passes, run a control test to tell "proxies are dead" from "Iran is cut off"
//  6. POST the verified proxies (best first) to the Worker /api/stage

import net from 'node:net';
import dns from 'node:dns/promises';

const WORKER_URL = (process.env.WORKER_URL || '').replace(/\/$/, '');
const WORKER_KEY = process.env.WORKER_KEY || '';
if (!WORKER_URL || !WORKER_KEY) {
  console.error('Missing WORKER_URL / WORKER_KEY secrets');
  process.exit(1);
}

// ---------------- tuning ----------------
const WANT = 8;                  // stop once this many proxies passed the Iran check
const MAX_CH_CHECKS = 12;        // Iran checks per run once at least one proxy has passed
const MAX_CH_CHECKS_HARD = 30;   // keep trying up to this many while NOTHING has passed yet
const RETEST_MAX = 3;            // previous winners re-tested first
const PER_SOURCE_CAP = 100;      // proxies taken from each source for the (free) runner TCP test
const TCP_CONCURRENCY = 50;
const GAP_MS = 15000;            // pause between Check-Host checks (avoids HTTP 429)
const DIAG_AFTER = 4;            // run the control test if nothing passed after this many checks
const GLOBAL_TARGET = '1.1.1.1:443';       // control: a well-known host OUTSIDE Iran
const DOMESTIC_TARGET = 'digikala.com:443'; // control: a well-known host INSIDE Iran
const SCALE = Number(process.env.SLEEP_SCALE || 1); // tests set this tiny to run fast

const CH = 'https://check-host.net';
const CH_HEADERS = { Accept: 'application/json' };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms * SCALE));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---------------- parsing ----------------
function parseProxies(text) {
  const out = [];
  const seen = new Set();
  const decoded = text.replace(/&amp;/g, '&');
  const matches = decoded.match(/(?:tg:\/\/proxy|https?:\/\/t\.me\/proxy)\?[^\s"'<>)]+/g) || [];
  for (const m of matches) {
    try {
      const u = new URL(m.replace('tg://proxy', 'https://t.me/proxy'));
      const server = (u.searchParams.get('server') || '').trim();
      const port = Number(u.searchParams.get('port'));
      const secret = (u.searchParams.get('secret') || '').trim();
      if (!server || !secret || !(port > 0 && port <= 65535)) continue;
      const k = `${server.toLowerCase()}:${port}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({
        server,
        port,
        secret,
        rawUrl: `https://t.me/proxy?server=${encodeURIComponent(server)}&port=${port}&secret=${encodeURIComponent(secret)}`,
      });
    } catch (_) {}
  }
  return out;
}

function pick(list, n) {
  if (list.length <= n) return list;
  const step = list.length / n;
  return Array.from({ length: n }, (_, i) => list[Math.floor(i * step)]);
}

async function mapPool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const idx = next++;
      out[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}

// ---------------- network helpers ----------------
function tcpPing(host, port, timeout = 2500) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const s = net.connect({ host, port });
    const done = (v) => { s.destroy(); resolve(v); };
    s.setTimeout(timeout, () => done(null));
    s.once('connect', () => done(Date.now() - t0));
    s.once('error', () => done(null));
  });
}

async function resolveIp(host) {
  if (net.isIP(host)) return host;
  try { return (await dns.lookup(host, { family: 4 })).address; } catch (_) {}
  try { return (await dns.lookup(host)).address; } catch (_) { return null; }
}

// Proxies in the same /24 usually behave alike from Iran -> used for ordering, never for rejecting
function clusterKey(ip, fallback) {
  if (ip && net.isIPv4(ip)) return ip.split('.').slice(0, 3).join('.');
  return ip || fallback;
}

function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return '🌐';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
}

const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });

async function geoLookup(ip) {
  try {
    const r = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    if (j.success) {
      return { ip, country: j.country, country_code: j.country_code, city: j.city || '', flag: flagEmoji(j.country_code) };
    }
  } catch (_) {}
  try { // fallback: country only
    const r = await fetch(`https://api.country.is/${ip}`, { signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    if (j.country) {
      return { ip, country: regionNames.of(j.country) || j.country, country_code: j.country, city: '', flag: flagEmoji(j.country) };
    }
  } catch (_) {}
  return null;
}

const geoCache = new Map(); // /24 key -> geo (keeps us well under the free GeoIP quota)
async function geoFor(ip, key) {
  if (geoCache.has(key)) return geoCache.get(key);
  const g = await geoLookup(ip);
  if (g) geoCache.set(key, g);
  return g;
}

// ---------------- Check-Host ----------------
async function chGet(path) {
  for (let i = 0; i < 3; i++) {
    const r = await fetch(CH + path, { headers: CH_HEADERS, signal: AbortSignal.timeout(20000) });
    if (r.status === 429) {
      log('   ⚠️ Check-Host 429 — backing off 30s');
      await sleep(30000);
      continue;
    }
    if (!r.ok) throw new Error(`Check-Host HTTP ${r.status}`);
    return r.json();
  }
  const e = new Error('Check-Host rate limited (429)');
  e.rateLimited = true;
  throw e;
}

async function getIranNodes() {
  try {
    const j = await chGet('/nodes/hosts');
    const ir = Object.keys(j.nodes || {}).filter((k) => k.toLowerCase().startsWith('ir'));
    if (ir.length) return ir;
  } catch (_) {}
  return ['ir1.node.check-host.net', 'ir3.node.check-host.net'];
}

// TCP connect test of "host:port" from every Iranian node. Always returns the raw measurement.
async function measureFromIran(target, nodes, fallbackIp) {
  const q = nodes.map((n) => 'node=' + encodeURIComponent(n)).join('&');
  const init = await chGet(`/check-tcp?host=${encodeURIComponent(target)}&${q}`);
  if (!init.ok || !init.request_id) {
    throw new Error('Check-Host init failed: ' + JSON.stringify(init).slice(0, 120));
  }
  const keys = Object.keys(init.nodes || {});
  let result = {};
  await sleep(3000);
  for (let i = 0; i < 6; i++) {
    result = await chGet(`/check-result/${init.request_id}`);
    if (keys.every((k) => result[k] !== null && result[k] !== undefined)) break;
    await sleep(2000);
  }

  const reports = keys.map((k) => {
    const city = (init.nodes[k] || [])[2] || 'Iran';
    const r = Array.isArray(result[k]) ? result[k][0] : null;
    if (r && typeof r.time === 'number') {
      const ms = Number((r.time * 1000).toFixed(1));
      return {
        node: k, location: `Iran, ${city}`, ok: 4, total: 4,
        min: ms, avg: ms, max: ms, rttText: `${ms} ms (TCP)`, ip: r.address || fallbackIp || target.split(':')[0],
      };
    }
    return {
      node: k, location: `Iran, ${city}`, ok: 0, total: 4,
      rttText: r && r.error ? String(r.error) : 'Timeout', ip: fallbackIp || target.split(':')[0],
    };
  });
  const good = reports.filter((n) => n.ok > 0);
  return {
    reports,
    good: good.length,
    total: keys.length,
    permalink: init.permanent_link || `${CH}/check-tcp?host=${encodeURIComponent(target)}`,
    address: good.length ? good[0].ip : null,
  };
}

// How many Iranian nodes must connect for a proxy to count as "working from Iran"
function needFor(total, mode) {
  if (mode === 'international-cut') return 1; // outage: any success is valuable
  return total >= 3 ? 2 : 1;
}

// Split-DNS guard: Iran may resolve the domain to a different (domestic) IP
async function splitDnsToIran(meas, ip) {
  const addr = meas.address;
  if (!addr || !net.isIP(addr) || addr === ip) return null;
  const g = await geoLookup(addr);
  return g && g.country_code === 'IR' ? addr : null;
}

// Control test: tells "these proxies are dead" apart from "Iran's international link is cut / nodes are blind"
async function diagnose(nodes) {
  log('🩺 Nothing passed yet — running control checks from the Iran nodes');
  await sleep(GAP_MS);
  const g = await measureFromIran(GLOBAL_TARGET, nodes);
  await sleep(GAP_MS);
  const d = await measureFromIran(DOMESTIC_TARGET, nodes);
  log(`   global ${GLOBAL_TARGET}: ${g.good}/${g.total} OK | domestic ${DOMESTIC_TARGET}: ${d.good}/${d.total} OK`);
  if (g.good === 0 && d.good === 0) return 'nodes-blind';
  if (g.good === 0 && d.good > 0) return 'international-cut';
  return 'normal';
}

function toRecord(c, g, meas, source) {
  const good = meas.reports.filter((n) => n.ok > 0);
  const avg = good.reduce((a, n) => a + n.avg, 0) / good.length;
  return {
    server: c.server,
    port: c.port,
    secret: c.secret,
    rawUrl: c.rawUrl,
    source,
    geo: { ip: g.ip, country: g.country, country_code: g.country_code, city: g.city, flag: g.flag },
    iranPing: Math.round(avg),
    iranNodes: meas.reports,
    checkHostSummary: good.map((n) => `${n.location.replace('Iran, ', '')}: ${n.avg}ms (TCP)`).join(' | '),
    checkHostReportUrl: meas.permalink,
    nodesOk: meas.good,
    nodesTotal: meas.total,
  };
}

// ---------------- worker API ----------------
async function workerGet(path) {
  const sep = path.includes('?') ? '&' : '?';
  const r = await fetch(`${WORKER_URL}${path}${sep}key=${encodeURIComponent(WORKER_KEY)}`, {
    signal: AbortSignal.timeout(20000),
  });
  if (!r.ok) throw new Error(`Worker ${path} HTTP ${r.status}`);
  return r.json();
}

// ---------------- main ----------------
async function main() {
  const sources = ((await workerGet('/api/get-sources')).sources || [])
    .filter((s) => s.enabled !== false)
    .sort((a, b) => (a.priority || 1) - (b.priority || 1));
  log(`📋 ${sources.length} active source(s)`);

  let winners = [];
  let seen = new Set();
  try {
    const st = await workerGet('/api/winners');
    winners = st.winners || [];
    seen = new Set(st.seen || []);
    log(`🧠 ${winners.length} remembered winner(s), ${seen.size} proxy(ies) published recently`);
  } catch (e) {
    log(`ℹ️ winners/seen unavailable (${e.message}) — continuing without them`);
  }
  const isSeen = (server, port) => seen.has(`seen_proxy_${server}_${port}`);

  const irNodes = await getIranNodes();
  log(`🇮🇷 Iran nodes: ${irNodes.join(', ')}`);

  const verified = [];
  const measured = [];   // failed the current threshold but had >=1 node OK (re-judged if the mode changes)
  const hot = new Set(); // /24 networks where a proxy passed
  let mode = 'normal';
  let diagnosed = false;
  let abort = false;
  let blind = false;
  let chChecks = 0;

  const budget = () => (verified.length ? MAX_CH_CHECKS : MAX_CH_CHECKS_HARD);

  function accept(item, g, meas) {
    const rec = toRecord(item.c, g, meas, item.source);
    verified.push(rec);
    hot.add(item.key);
    log(`   ✅ PASSED ${meas.good}/${meas.total} Iran nodes — ${rec.checkHostSummary}`);
  }

  async function tryItem(item) {
    let g = item.geo;
    if (!g) g = await geoFor(item.ip, item.key);
    if (!g) { log(`   ⏭  ${item.c.server}: GeoIP failed`); return; }
    if (g.country_code === 'IR') { log(`   ⏭  ${item.c.server}: hosted in Iran`); return; }

    if (chChecks > 0) await sleep(GAP_MS);
    chChecks++;
    log(`📡 [${chChecks}] ${item.retest ? '♻️ ' : ''}${item.c.server}:${item.c.port} (${g.city || g.country})`);

    let meas;
    try {
      meas = await measureFromIran(`${item.c.server}:${item.c.port}`, irNodes, item.ip || g.ip);
    } catch (e) {
      log(`   ⚠️ ${e.message}`);
      if (e.rateLimited) abort = true;
      return;
    }
    if (meas.good >= needFor(meas.total, mode)) {
      const bad = await splitDnsToIran(meas, g.ip || item.ip);
      if (bad) { log(`   ❌ split-DNS: Iran resolves it to ${bad}`); return; }
      accept(item, g, meas);
    } else {
      log(`   ❌ failed from Iran (${meas.good}/${meas.total} nodes OK)`);
      if (meas.good > 0) measured.push({ item, g, meas });
    }
  }

  async function maybeDiagnose() {
    if (diagnosed || verified.length > 0 || chChecks < DIAG_AFTER) return;
    diagnosed = true;
    try {
      mode = await diagnose(irNodes);
    } catch (e) {
      log(`   ⚠️ control test failed: ${e.message}`);
      if (e.rateLimited) abort = true;
      return;
    }
    if (mode === 'nodes-blind') {
      log('🚫 Both control targets are unreachable from every Iran node — Check-Host results are not trustworthy right now');
      blind = true;
      abort = true;
    } else if (mode === 'international-cut') {
      log('🌐✂️ Outage mode: international link looks cut — accepting proxies that connect from just 1 Iran node');
      for (const m of measured) {
        if (m.meas.good >= needFor(m.meas.total, mode)) accept(m.item, m.g, m.meas);
      }
      measured.length = 0;
    } else {
      log('✅ Control targets look normal — the proxies themselves are failing');
    }
  }

  // ---- step 2: re-test previous winners ----
  const winnerPool = winners.filter((w) => w && w.server && w.port && !isSeen(w.server, w.port)).slice(0, 8);
  const winnerTcp = await mapPool(winnerPool, 8, async (w) => ({ w, ping: await tcpPing(w.server, w.port) }));
  const retest = [];
  for (const { w, ping } of winnerTcp) {
    if (ping === null) { log(`♻️ winner ${w.server}:${w.port} unreachable from runner — skipped`); continue; }
    if (retest.length >= RETEST_MAX) break;
    const ip = w.geo && w.geo.ip;
    retest.push({ c: w, source: w.source || 'winner', geo: w.geo, ip, key: clusterKey(ip, w.server), retest: true });
  }
  const retestKeys = new Set(retest.map((r) => `${r.c.server.toLowerCase()}:${r.c.port}`));
  for (const it of retest) {
    if (abort || chChecks >= budget() || verified.length >= WANT) break;
    await tryItem(it);
    await maybeDiagnose();
  }

  // ---- step 3: wide funnel ----
  const pool = new Map();
  for (const src of sources) {
    log(`🔍 ${src.name || src.id}`);
    let text;
    try {
      const r = await fetch(src.url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(20000) });
      if (!r.ok) { log(`   HTTP ${r.status} — skipped`); continue; }
      text = await r.text();
    } catch (e) {
      log(`   fetch error: ${e.message}`);
      continue;
    }
    let list = parseProxies(text);
    const isTelegram = src.type === 'telegram' || (src.url || '').includes('t.me/');
    if (isTelegram) list = list.reverse().slice(0, PER_SOURCE_CAP); // newest first
    else list = pick(list, PER_SOURCE_CAP);
    let added = 0;
    for (const p of list) {
      const k = `${p.server.toLowerCase()}:${p.port}`;
      if (pool.has(k) || retestKeys.has(k) || isSeen(p.server, p.port)) continue;
      pool.set(k, { c: p, source: src.name || src.id });
      added++;
    }
    log(`   parsed ${list.length}, ${added} new candidate(s)`);
  }

  const entries = [...pool.values()];
  const tested = await mapPool(entries, TCP_CONCURRENCY, async (e) => ({ ...e, ping: await tcpPing(e.c.server, e.c.port) }));
  const live = tested.filter((x) => x.ping !== null);
  const resolved = (await mapPool(live, 20, async (x) => {
    const ip = await resolveIp(x.c.server);
    return ip ? { ...x, ip, key: clusterKey(ip, x.c.server) } : null;
  })).filter(Boolean);

  const clusters = new Map();
  for (const it of resolved.sort((a, b) => a.ping - b.ping)) {
    if (!clusters.has(it.key)) clusters.set(it.key, { items: [], tried: 0 });
    clusters.get(it.key).items.push(it);
  }
  log(`🌐 ${entries.length} candidates → ${live.length} reachable from runner → ${clusters.size} network cluster(s) (/24)`);

  // ---- step 4: spend the Check-Host budget ----
  // normal: one per network first (diversity), then dig into networks that passed
  // outage: dig into networks that passed first (they are rare and valuable)
  function nextItem() {
    let bestKey = null;
    let bestScore = null;
    for (const [key, cl] of clusters) {
      if (!cl.items.length) continue;
      const isHot = hot.has(key);
      const tier = mode === 'normal'
        ? (cl.tried === 0 ? 0 : isHot ? 1 : 2)
        : (isHot ? 0 : cl.tried === 0 ? 1 : 2);
      const score = [tier, cl.tried, cl.items[0].ping];
      if (!bestScore || score[0] < bestScore[0] ||
          (score[0] === bestScore[0] && (score[1] < bestScore[1] ||
          (score[1] === bestScore[1] && score[2] < bestScore[2])))) {
        bestKey = key;
        bestScore = score;
      }
    }
    if (bestKey === null) return null;
    const cl = clusters.get(bestKey);
    cl.tried++;
    return cl.items.shift();
  }

  while (!abort && chChecks < budget() && verified.length < WANT) {
    const it = nextItem();
    if (!it) break;
    await tryItem(it);
    await maybeDiagnose();
  }

  log(`📊 mode=${mode} | Iran checks used: ${chChecks} | verified: ${verified.length}`);

  if (blind) {
    process.exitCode = 1; // red run -> GitHub e-mails you
    log('❌ Nodes are blind — nothing staged');
    return;
  }
  if (!verified.length) {
    log('❌ No proxy passed the Iran check this run — nothing staged');
    return;
  }

  // best first: more Iran nodes OK, then lower ping
  verified.sort((a, b) => (b.nodesOk / b.nodesTotal - a.nodesOk / a.nodesTotal) || (a.iranPing - b.iranPing));

  const res = await fetch(`${WORKER_URL}/api/stage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: WORKER_KEY, candidates: verified, scarce: mode === 'international-cut', mode }),
  });
  log(`📤 Worker /api/stage → HTTP ${res.status}`, (await res.text()).slice(0, 300));
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
