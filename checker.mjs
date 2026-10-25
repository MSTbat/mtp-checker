// checker.mjs — runs inside GitHub Actions (Node 20+, no dependencies)
// 1) reads the sources list from your Worker  2) scrapes MTProto links
// 3) TCP pre-filter from the runner          4) GeoIP (drop Iranian hosts)
// 5) Check-Host.net check-tcp from Iranian nodes  6) POSTs verified proxies to Worker /api/stage

import net from 'node:net';
import dns from 'node:dns/promises';

const WORKER_URL = (process.env.WORKER_URL || '').replace(/\/$/, '');
const WORKER_KEY = process.env.WORKER_KEY || '';
if (!WORKER_URL || !WORKER_KEY) {
  console.error('Missing WORKER_URL / WORKER_KEY secrets');
  process.exit(1);
}

const CH = 'https://check-host.net';
const CH_HEADERS = { Accept: 'application/json' };
const WANT = 3;               // verified proxies to send (Worker picks the first unseen one)
const MAX_CH_CHECKS = 6;      // hard cap on Check-Host checks per run (rate limit!)
const SAMPLE_PER_SOURCE = 12; // candidates tested from the runner per source
const GAP_MS = 15000;         // pause between Check-Host checks

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---------- parsing ----------
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

// ---------- network helpers ----------
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

function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return '🌐';
  return String.fromCodePoint(...cc.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
}

async function geo(host) {
  let ip = host;
  if (!net.isIP(host)) {
    try { ip = (await dns.lookup(host)).address; } catch (_) { return null; }
  }
  try {
    const r = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    if (!j.success) return null;
    return {
      ip,
      country: j.country,
      country_code: j.country_code,
      city: j.city || '',
      flag: flagEmoji(j.country_code),
    };
  } catch (_) {
    return null;
  }
}

// ---------- Check-Host ----------
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

// Real-world MTProto criterion: is the TCP port reachable from inside Iran?
async function checkFromIran(server, port, nodes, foreignIp) {
  const q = nodes.map((n) => 'node=' + encodeURIComponent(n)).join('&');
  const init = await chGet(`/check-tcp?host=${encodeURIComponent(server + ':' + port)}&${q}`);
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

  const reports = [];
  for (const k of keys) {
    const city = (init.nodes[k] || [])[2] || 'Iran';
    const r = Array.isArray(result[k]) ? result[k][0] : null;
    if (r && typeof r.time === 'number') {
      const ms = Number((r.time * 1000).toFixed(1));
      reports.push({
        node: k, location: `Iran, ${city}`, ok: 4, total: 4,
        min: ms, avg: ms, max: ms, rttText: `${ms} ms (TCP)`, ip: r.address || server,
      });
    } else {
      reports.push({
        node: k, location: `Iran, ${city}`, ok: 0, total: 4,
        rttText: r && r.error ? String(r.error) : 'Timeout', ip: server,
      });
    }
  }

  const good = reports.filter((n) => n.ok > 0);
  const need = keys.length >= 3 ? 2 : 1;
  if (good.length < need) return { passed: false, reports, good: good.length, total: keys.length };

  // Split-DNS guard: if Iran resolves the domain to a different IP, make sure it is not an Iranian one
  const seenAddr = good[0].ip;
  if (seenAddr && seenAddr !== foreignIp && net.isIP(seenAddr)) {
    const g = await geo(seenAddr);
    if (g && g.country_code === 'IR') {
      return { passed: false, reports, good: good.length, total: keys.length, splitDns: seenAddr };
    }
  }

  return {
    passed: true,
    iranPing: Math.round(good.reduce((a, n) => a + n.avg, 0) / good.length),
    iranNodes: reports,
    summary: good.map((n) => `${n.location.replace('Iran, ', '')}: ${n.avg}ms (TCP)`).join(' | '),
    reportUrl: init.permanent_link || `${CH}/check-tcp?host=${encodeURIComponent(server + ':' + port)}`,
    good: good.length,
    total: keys.length,
  };
}

// ---------- main ----------
async function main() {
  const srcRes = await fetch(`${WORKER_URL}/api/get-sources?key=${encodeURIComponent(WORKER_KEY)}`);
  if (!srcRes.ok) throw new Error(`Worker /api/get-sources HTTP ${srcRes.status}`);
  const sources = ((await srcRes.json()).sources || [])
    .filter((s) => s.enabled !== false)
    .sort((a, b) => (a.priority || 1) - (b.priority || 1));
  log(`📋 ${sources.length} active source(s)`);

  const irNodes = await getIranNodes();
  log(`🇮🇷 Iran nodes: ${irNodes.join(', ')}`);

  const verified = [];
  let chChecks = 0;
  let stop = false;

  for (const src of sources) {
    if (stop || verified.length >= WANT || chChecks >= MAX_CH_CHECKS) break;
    log(`🔍 ${src.name || src.id}`);

    let text;
    try {
      const r = await fetch(src.url, {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        signal: AbortSignal.timeout(20000),
      });
      if (!r.ok) { log(`   HTTP ${r.status} — skipped`); continue; }
      text = await r.text();
    } catch (e) {
      log(`   fetch error: ${e.message}`);
      continue;
    }

    let list = parseProxies(text);
    if (src.type === 'telegram' || (src.url || '').includes('t.me/')) list = list.reverse(); // newest first
    log(`   parsed ${list.length} proxies`);
    if (!list.length) continue;

    const sample = pick(list, SAMPLE_PER_SOURCE);
    const tested = await Promise.all(sample.map(async (c) => ({ c, ping: await tcpPing(c.server, c.port) })));
    const live = tested.filter((x) => x.ping !== null).sort((a, b) => a.ping - b.ping);
    log(`   ${live.length}/${sample.length} reachable from runner`);

    for (const { c } of live) {
      if (verified.length >= WANT || chChecks >= MAX_CH_CHECKS) break;

      const g = await geo(c.server);
      if (!g) { log(`   ⏭  ${c.server}: GeoIP failed`); continue; }
      if (g.country_code === 'IR') { log(`   ⏭  ${c.server}: hosted in Iran`); continue; }

      if (chChecks > 0) await sleep(GAP_MS);
      chChecks++;
      log(`   📡 [${chChecks}/${MAX_CH_CHECKS}] ${c.server}:${c.port} (${g.city || g.country})`);

      try {
        const r = await checkFromIran(c.server, c.port, irNodes, g.ip);
        if (r.passed) {
          log(`   ✅ PASSED ${r.good}/${r.total} Iran nodes — ${r.summary}`);
          verified.push({
            server: c.server,
            port: c.port,
            secret: c.secret,
            rawUrl: c.rawUrl,
            source: src.name || src.id,
            geo: { country: g.country, country_code: g.country_code, city: g.city, flag: g.flag },
            iranPing: r.iranPing,
            iranNodes: r.iranNodes,
            checkHostSummary: r.summary,
            checkHostReportUrl: r.reportUrl,
          });
        } else {
          log(`   ❌ failed from Iran (${r.good}/${r.total} nodes OK)${r.splitDns ? ' split-DNS → ' + r.splitDns : ''}`);
        }
      } catch (e) {
        log(`   ⚠️ ${e.message}`);
        if (e.rateLimited) { stop = true; break; }
      }
    }
  }

  if (!verified.length) {
    log('❌ No proxy passed the Iran check this run — nothing staged');
    return;
  }

  const res = await fetch(`${WORKER_URL}/api/stage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key: WORKER_KEY, candidates: verified }),
  });
  log(`📤 Worker /api/stage → HTTP ${res.status}`, (await res.text()).slice(0, 300));
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
