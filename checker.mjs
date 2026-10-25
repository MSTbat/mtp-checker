// checker.mjs v3.5 — runs inside GitHub Actions (Node 20+, no dependencies)
//
// How it works with Cloudflare Worker:
//  1. Calls Worker /api/candidates -> Worker rotates sources in Round-Robin order (Source #1 -> #2 -> #3...),
//     scrapes them, and pre-tests TCP connections on Cloudflare Edge so dead proxies never even reach GitHub!
//  2. Also fetches remembered winners + seen list from /api/winners (fallback to direct source scraping if needed)
//  3. Verifies real MTProto Fake-TLS (ee...) & Obfuscated2 (dd...) handshakes so fake web servers & dead secrets are dropped
//  4. Tests live MTProto candidates from Iranian nodes via Check-Host.net
//  5. POSTs verified proxies to Worker /api/stage (which merges multi-stage runs like 5:20 and 5:45 seamlessly)

import net from 'node:net';
import crypto from 'node:crypto';
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
const RETEST_MAX = 1;            // max 1 previous winner re-tested first so fresh sources get priority
const PER_SOURCE_CAP = 100;      // fallback cap if Worker /api/candidates is not deployed yet
const TCP_CONCURRENCY = 40;
const GAP_MS = 15000;            // pause between Check-Host checks (avoids HTTP 429)
const DIAG_AFTER = 4;            // run the control test if nothing passed after this many checks
const GLOBAL_TARGET = '1.1.1.1:443';        // control: a well-known host OUTSIDE Iran
const DOMESTIC_TARGET = 'digikala.com:443'; // control: a well-known host INSIDE Iran
const SCALE = Number(process.env.SLEEP_SCALE || 1);

const CH = 'https://check-host.net';
const CH_HEADERS = { Accept: 'application/json' };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms * SCALE));
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// ---------------- secret & protocol helpers ----------------
function parseSecret(secretStr) {
  if (!secretStr || typeof secretStr !== 'string') return null;
  let s = secretStr.trim();
  if (!/^[0-9a-fA-F]+$/.test(s)) {
    try {
      const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
      const hex = Buffer.from(b64 + pad, 'base64').toString('hex');
      if (hex.length >= 32) s = hex;
    } catch (_) {
      return null;
    }
  }
  s = s.toLowerCase();
  if (!/^[0-9a-f]+$/.test(s)) return null;

  if (s.length === 32) {
    return { type: 'raw', key: Buffer.from(s, 'hex'), tier: 2 };
  }
  if (s.length === 34 && s.startsWith('dd')) {
    return { type: 'dd', key: Buffer.from(s.slice(2), 'hex'), tier: 1 };
  }
  if (s.length >= 36 && s.startsWith('ee')) {
    const key = Buffer.from(s.slice(2, 34), 'hex');
    let domain = 'www.google.com';
    try {
      const d = Buffer.from(s.slice(34), 'hex').toString('utf8').replace(/[^\x20-\x7E]/g, '');
      if (d.length >= 3) domain = d;
    } catch (_) {}
    return { type: 'ee', key, domain, tier: 0 };
  }
  return null;
}

function buildFakeTlsClientHello(secretKey, domain = 'www.google.com') {
  const sniBuf = Buffer.from(domain, 'utf8');
  const sniListLen = sniBuf.length + 3;
  const sniExtLen = sniListLen + 2;
  const sniExt = Buffer.alloc(4 + sniExtLen);
  sniExt.writeUInt16BE(0x0000, 0);
  sniExt.writeUInt16BE(sniExtLen, 2);
  sniExt.writeUInt16BE(sniListLen, 4);
  sniExt.writeUInt8(0x00, 6);
  sniExt.writeUInt16BE(sniBuf.length, 7);
  sniBuf.copy(sniExt, 9);

  const otherExts = Buffer.from(
    '002b00050403040303' +
    '000a00080006001d00170018' +
    '000d00080006040308040401' +
    '003300260024001d0020' + crypto.randomBytes(32).toString('hex'),
    'hex'
  );
  const extensions = Buffer.concat([sniExt, otherExts]);
  const extLenBuf = Buffer.alloc(2);
  extLenBuf.writeUInt16BE(extensions.length, 0);

  const clientRandom = Buffer.alloc(32, 0);
  const sessionId = crypto.randomBytes(32);
  const cipherSuites = Buffer.from('0008130113021303c02b0100', 'hex');

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    clientRandom,
    Buffer.from([0x20]),
    sessionId,
    cipherSuites,
    extLenBuf,
    extensions,
  ]);

  const handshake = Buffer.alloc(4 + body.length);
  handshake[0] = 0x01;
  handshake.writeUIntBE(body.length, 1, 3);
  body.copy(handshake, 4);

  const record = Buffer.alloc(5 + handshake.length);
  record[0] = 0x16;
  record[1] = 0x03;
  record[2] = 0x01;
  record.writeUInt16BE(handshake.length, 3);
  handshake.copy(record, 5);

  const hmac = crypto.createHmac('sha256', secretKey).update(record).digest();
  const ts = Math.floor(Date.now() / 1000);
  hmac[28] ^= ts & 0xff;
  hmac[29] ^= (ts >> 8) & 0xff;
  hmac[30] ^= (ts >> 16) & 0xff;
  hmac[31] ^= (ts >> 24) & 0xff;
  hmac.copy(record, 11);

  return { packet: record, clientRandom: hmac };
}

function buildObfuscated2Probe(secretKey, isDd = false) {
  let init;
  while (true) {
    init = crypto.randomBytes(64);
    if (init[0] === 0xef) continue;
    const v1 = init.readUInt32LE(0);
    if ([0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0xeeeeeeee, 0xdddddddd, 0x16030102].includes(v1)) continue;
    if (init.readUInt32LE(4) === 0x00000000) continue;
    break;
  }
  const tag = isDd ? 0xdd : 0xee;
  init[56] = tag; init[57] = tag; init[58] = tag; init[59] = tag;

  const rawKey = init.subarray(8, 40);
  const encIv = Buffer.from(init.subarray(40, 56));
  const encKey = crypto.createHash('sha256').update(Buffer.concat([rawKey, secretKey])).digest();

  const cipher = crypto.createCipheriv('aes-256-ctr', encKey, encIv);
  const encInit = cipher.update(init);
  const outFrame = Buffer.from(init);
  encInit.subarray(56, 64).copy(outFrame, 56);

  const probePayload = cipher.update(crypto.randomBytes(16));
  return Buffer.concat([outFrame, probePayload]);
}

function verifyMtprotoProxy(host, port, secretStr, timeout = 3000) {
  const parsed = parseSecret(secretStr);
  if (!parsed) return Promise.resolve(null);

  return new Promise((resolve) => {
    const t0 = Date.now();
    let connectRtt = null;
    let settled = false;
    const s = net.connect({ host, port });

    const done = (val) => {
      if (settled) return;
      settled = true;
      s.destroy();
      resolve(val);
    };

    const timer = setTimeout(() => {
      if (connectRtt !== null && parsed.type !== 'ee') {
        done(connectRtt);
      } else {
        done(null);
      }
    }, timeout);

    s.once('error', () => {
      clearTimeout(timer);
      done(null);
    });

    s.once('close', () => {
      clearTimeout(timer);
      done(null);
    });

    if (parsed.type === 'ee') {
      const { packet, clientRandom } = buildFakeTlsClientHello(parsed.key, parsed.domain);
      let rx = Buffer.alloc(0);

      s.once('connect', () => {
        connectRtt = Date.now() - t0;
        s.write(packet);
      });

      s.on('data', (chunk) => {
        rx = Buffer.concat([rx, chunk]);
        if (rx.length < 11) return;
        if (rx[0] !== 0x16 || rx[1] !== 0x03 || rx[5] !== 0x02) {
          clearTimeout(timer);
          done(null);
          return;
        }
        if (rx.length < 43) return;
        const firstRecLen = rx.readUInt16BE(3);
        const totalExpected = 5 + firstRecLen;
        if (rx.length < Math.min(totalExpected, 90)) return;

        const serverRandom = Buffer.from(rx.subarray(11, 43));
        const candidatesToVerify = [rx];
        if (rx.length >= totalExpected) candidatesToVerify.push(rx.subarray(0, totalExpected));

        for (const buf of candidatesToVerify) {
          const copy = Buffer.from(buf);
          copy.fill(0, 11, 43);
          const expectedHmac = crypto.createHmac('sha256', parsed.key)
            .update(Buffer.concat([clientRandom, copy]))
            .digest();
          if (expectedHmac.equals(serverRandom)) {
            clearTimeout(timer);
            done(connectRtt);
            return;
          }
        }

        if (rx.length >= totalExpected) {
          clearTimeout(timer);
          done(null);
        }
      });
    } else {
      const probe = buildObfuscated2Probe(parsed.key, parsed.type === 'dd');
      s.once('connect', () => {
        connectRtt = Date.now() - t0;
        s.write(probe);
      });
      s.on('data', (chunk) => {
        const text = chunk.toString('utf8', 0, Math.min(chunk.length, 32));
        if (/^(HTTP\/|<!DOC|<html|SSH-|\x15\x03)/i.test(text)) {
          clearTimeout(timer);
          done(null);
          return;
        }
        clearTimeout(timer);
        done(connectRtt);
      });
    }
  });
}

// ---------------- parsing ----------------
function parseProxies(text) {
  const out = [];
  const seen = new Set();
  const decoded = text
    .replace(/&amp;/gi, '&')
    .replace(/&#38;/gi, '&')
    .replace(/%26/gi, '&')
    .replace(/%3D/gi, '=')
    .replace(/%3F/gi, '?');
  const matches = decoded.match(/(?:tg:\/\/proxy|https?:\/\/t\.me\/proxy)\?[^\s"'<>)]+/g) || [];
  for (const m of matches) {
    try {
      const u = new URL(m.replace('tg://proxy', 'https://t.me/proxy'));
      const server = (u.searchParams.get('server') || '').trim().replace(/\.$/, '');
      const port = Number(u.searchParams.get('port'));
      const secret = (u.searchParams.get('secret') || '').trim();
      if (!server || !secret || !(port > 0 && port <= 65535)) continue;
      const secretMeta = parseSecret(secret);
      if (!secretMeta) continue;
      const k = `${server.toLowerCase()}:${port}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({
        server,
        port,
        secret,
        secretType: secretMeta.type,
        secretTier: secretMeta.tier,
        rawUrl: `https://t.me/proxy?server=${encodeURIComponent(server)}&port=${port}&secret=${encodeURIComponent(secret)}`,
      });
    } catch (_) {}
  }
  return out;
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function pickRandom(list, n) {
  if (list.length <= n) return shuffle(list);
  return shuffle(list).slice(0, n);
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
async function resolveIp(host) {
  if (net.isIP(host)) return host;
  try { return (await dns.lookup(host, { family: 4 })).address; } catch (_) {}
  try { return (await dns.lookup(host)).address; } catch (_) { return null; }
}

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
  try {
    const r = await fetch(`https://api.country.is/${ip}`, { signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    if (j.country) {
      return { ip, country: regionNames.of(j.country) || j.country, country_code: j.country, city: '', flag: flagEmoji(j.country) };
    }
  } catch (_) {}
  return null;
}

const geoCache = new Map();
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

function needFor(total, mode) {
  if (mode === 'international-cut') return 1;
  return total >= 3 ? 2 : 1;
}

async function splitDnsToIran(meas, ip) {
  const addr = meas.address;
  if (!addr || !net.isIP(addr) || addr === ip) return null;
  const g = await geoLookup(addr);
  return g && g.country_code === 'IR' ? addr : null;
}

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
  const times = good.map((n) => n.avg).sort((a, b) => a - b);
  const mid = Math.floor(times.length / 2);
  const avg = times.length % 2 ? times[mid] : (times[mid - 1] + times[mid]) / 2;
  const parsed = parseSecret(c.secret);
  return {
    server: c.server,
    port: c.port,
    secret: c.secret,
    secretType: c.secretType || (parsed ? parsed.type : 'raw'),
    secretTier: c.secretTier ?? (parsed ? parsed.tier : 2),
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
    signal: AbortSignal.timeout(25000),
  });
  if (!r.ok) throw new Error(`Worker ${path} HTTP ${r.status}`);
  return r.json();
}

// ---------------- main ----------------
async function main() {
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
  const measured = [];
  const hot = new Set();
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
    log(`   ✅ PASSED ${meas.good}/${meas.total} Iran nodes [${rec.secretType.toUpperCase()} | ${item.source}] — ${rec.checkHostSummary}`);
  }

  async function tryItem(item) {
    let g = item.geo;
    if (!g) g = await geoFor(item.ip, item.key);
    if (!g) { log(`   ⏭  ${item.c.server}: GeoIP failed`); return; }
    if (g.country_code === 'IR') { log(`   ⏭  ${item.c.server}: hosted in Iran`); return; }

    if (chChecks > 0) await sleep(GAP_MS);
    chChecks++;
    const sType = (item.c.secretType || 'raw').toUpperCase();
    log(`📡 [${chChecks}] ${item.retest ? '♻️ ' : ''}${item.c.server}:${item.c.port} [${sType} | ${item.source}] (${g.city || g.country})`);

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

  // ---- step 2: re-test at most RETEST_MAX shuffled previous winner ----
  const unseenWinners = shuffle(
    winners.filter((w) => w && w.server && w.port && w.secret && !isSeen(w.server, w.port))
  ).slice(0, 6);

  const winnerChecked = await mapPool(unseenWinners, 6, async (w) => {
    const parsed = parseSecret(w.secret);
    if (!parsed) return { w, ping: null };
    const ping = await verifyMtprotoProxy(w.server, w.port, w.secret);
    return { w: { ...w, secretType: parsed.type, secretTier: parsed.tier }, ping };
  });

  const retest = [];
  for (const { w, ping } of winnerChecked) {
    if (ping === null) { log(`♻️ winner ${w.server}:${w.port} failed MTProto handshake — skipped`); continue; }
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

  // ---- step 3: Ask Worker /api/candidates for Round-Robin rotated & Edge TCP pre-tested proxies ----
  const pool = new Map();
  let usedEdgePreFilter = false;
  try {
    const pre = await workerGet('/api/candidates');
    if (pre && Array.isArray(pre.candidates) && pre.candidates.length > 0) {
      usedEdgePreFilter = true;
      log(`🔄 Worker Round-Robin Turn: Primary Source = "${pre.primary_source}" (next cursor: #${pre.next_source_index + 1})`);
      log(`⚡ Worker Edge TCP Pre-Filter: ${pre.total_checked_on_edge} checked on Cloudflare → ${pre.live_count} alive sent to GitHub`);
      for (const item of pre.candidates) {
        const parsed = parseSecret(item.secret);
        if (!parsed) continue;
        const k = `${item.server.toLowerCase()}:${item.port}`;
        if (pool.has(k) || retestKeys.has(k) || isSeen(item.server, item.port)) continue;
        pool.set(k, {
          c: {
            server: item.server,
            port: Number(item.port),
            secret: item.secret,
            secretType: parsed.type,
            secretTier: parsed.tier,
            rawUrl: item.rawUrl,
          },
          source: item.source,
          sourcePriority: item.sourcePriority || 1,
        });
      }
    }
  } catch (e) {
    log(`ℹ️ Worker /api/candidates not available (${e.message}) — falling back to direct source scraping`);
  }

  // Fallback if Worker wasn't updated with /api/candidates yet or returned 0
  if (!usedEdgePreFilter || pool.size === 0) {
    const sources = ((await workerGet('/api/get-sources')).sources || [])
      .filter((s) => s.enabled !== false)
      .sort((a, b) => (a.priority || 1) - (b.priority || 1));
    log(`📋 ${sources.length} active source(s) (direct fallback)`);

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
      if (isTelegram) list = shuffle(list.reverse().slice(0, PER_SOURCE_CAP));
      else list = pickRandom(list, PER_SOURCE_CAP);
      let added = 0;
      for (const p of list) {
        const k = `${p.server.toLowerCase()}:${p.port}`;
        if (pool.has(k) || retestKeys.has(k) || isSeen(p.server, p.port)) continue;
        pool.set(k, { c: p, source: src.name || src.id, sourcePriority: src.priority || 1 });
        added++;
      }
      log(`   parsed ${list.length}, ${added} new candidate(s)`);
    }
  }

  // Verify full MTProto Fake-TLS / Obfuscated2 Handshake on the candidates
  const entries = [...pool.values()];
  const tested = await mapPool(entries, TCP_CONCURRENCY, async (e) => ({
    ...e,
    ping: await verifyMtprotoProxy(e.c.server, e.c.port, e.c.secret),
  }));
  const live = tested.filter((x) => x.ping !== null);
  const resolved = (await mapPool(live, 20, async (x) => {
    const ip = await resolveIp(x.c.server);
    return ip ? { ...x, ip, key: clusterKey(ip, x.c.server) } : null;
  })).filter(Boolean);

  // Order by: 1) Turn's primary source priority, 2) Secret Tier (Fake-TLS first), 3) Ping + jitter
  const clusters = new Map();
  const sortedResolved = resolved
    .map((x) => ({
      ...x,
      sortScore: (x.sourcePriority === 1 ? 0 : 120) + x.c.secretTier * 200 + x.ping + Math.random() * 25,
    }))
    .sort((a, b) => a.sortScore - b.sortScore);

  for (const it of sortedResolved) {
    if (!clusters.has(it.key)) clusters.set(it.key, { items: [], tried: 0 });
    clusters.get(it.key).items.push(it);
  }
  log(`🌐 ${entries.length} candidates → ${live.length} passed MTProto Handshake → ${clusters.size} network cluster(s) (/24)`);

  // ---- step 4: spend the Check-Host budget ----
  function nextItem() {
    let bestKey = null;
    let bestScore = null;
    for (const [key, cl] of clusters) {
      if (!cl.items.length) continue;
      const isHot = hot.has(key);
      const top = cl.items[0];
      const tier = mode === 'normal'
        ? (cl.tried === 0 ? 0 : isHot ? 2 : 1)
        : (isHot ? 0 : cl.tried === 0 ? 1 : 2);
      const score = [tier, top.c.secretTier, cl.tried, top.sortScore];
      if (!bestScore ||
          score[0] < bestScore[0] ||
          (score[0] === bestScore[0] && score[1] < bestScore[1]) ||
          (score[0] === bestScore[0] && score[1] === bestScore[1] && score[2] < bestScore[2]) ||
          (score[0] === bestScore[0] && score[1] === bestScore[1] && score[2] === bestScore[2] && score[3] < bestScore[3])) {
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
    process.exitCode = 1;
    log('❌ Nodes are blind — nothing staged');
    return;
  }
  if (!verified.length) {
    log('❌ No proxy passed the Iran check this run — nothing staged');
    return;
  }

  verified.sort((a, b) =>
    (a.secretTier - b.secretTier) ||
    (b.nodesOk / b.nodesTotal - a.nodesOk / a.nodesTotal) ||
    (a.iranPing - b.iranPing)
  );

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
