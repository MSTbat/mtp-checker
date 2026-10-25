// Cloudflare Worker - MTProto Proxy Scraper & Automated Publisher (v3.5 Check-Host Iran & Pre-Stage Edition)
import { connect } from 'cloudflare:sockets';

const CONFIG = {
  AUTH_KEY: "",   // set as a Cloudflare secret named AUTH_KEY (never hardcode)
  BOT_TOKEN: "",  // set as a Cloudflare secret named BOT_TOKEN (never hardcode)
  CHANNEL_ID: "@MSTProxy",
  CHANNEL_SIGNATURE: '🔥 <a href="https://t.me/MSTProxy">𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬</a>',
  KV_TTL_SECONDS: 43200,         // a published proxy may be re-published after 12 hours (higher diversity)
  KV_TTL_SCARCE_SECONDS: 1800,   // shorter repeat window when healthy proxies are scarce (outage mode)
  DEFAULT_TEMPLATE: {
    messageTemplate: `📍 <b>Location:</b> {location}
⚡️ <b>Ping:</b> {ping}ms {status_dot}
🕒 <b>Updated:</b> <tg-time unix="{unix}" format="r">{time}</tg-time>
━━━━━━━━━━━━━━━━━━
{signature}`,
    signature: '🔥 <a href="https://t.me/MSTProxy">𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬</a>',
    buttonText: '🚀 CONNECT TO PROXY 🚀',
    secondButtonEnabled: false,
    secondButtonText: '📢 Join @MSTProxy',
    secondButtonUrl: 'https://t.me/MSTProxy',
    disableWebPagePreview: true
  },
  DEFAULT_SOURCES: [
    {
      id: "Ela_Proxy",
      name: "Ela Proxy (Telegram Channel)",
      type: "telegram",
      url: "https://t.me/s/Ela_Proxy",
      enabled: true,
      priority: 1
    },
    {
      id: "GitHub",
      name: "GitHub Master List (SoliSpirit)",
      type: "text",
      url: "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
      enabled: true,
      priority: 2
    },
    {
      id: "iMTProto",
      name: "iMTProto (Telegram Channel)",
      type: "telegram",
      url: "https://t.me/s/iMTProto",
      enabled: true,
      priority: 3
    },
    {
      id: "ProxyMTProto",
      name: "ProxyMTProto (Telegram Channel)",
      type: "telegram",
      url: "https://t.me/s/ProxyMTProto",
      enabled: true,
      priority: 4
    },
    {
      id: "TelMTProto",
      name: "TelMTProto (Telegram Channel)",
      type: "telegram",
      url: "https://t.me/s/TelMTProto",
      enabled: true,
      priority: 5
    },
    {
      id: "MTP_roto",
      name: "MTP_roto (Telegram Channel)",
      type: "telegram",
      url: "https://t.me/s/MTP_roto",
      enabled: true,
      priority: 6
    }
  ]
};

// In-isolate fallback memory when KV is not bound
const MEMORY_STATE = {
  sources: null,
  template: null,
  lastRun: null,
  stagedProxy: null,
  channelInfo: null,
  iranNodesCache: null,
  seenProxies: new Map()
};

// Secrets live in Cloudflare (Settings -> Variables and Secrets), never in the code.
// Returns false when either secret is missing so callers can fail closed.
function applyEnvSecrets(env) {
  CONFIG.AUTH_KEY = (env && typeof env.AUTH_KEY === 'string') ? env.AUTH_KEY : '';
  CONFIG.BOT_TOKEN = (env && typeof env.BOT_TOKEN === 'string') ? env.BOT_TOKEN : '';
  return Boolean(CONFIG.AUTH_KEY && CONFIG.BOT_TOKEN);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Ignore browser favicon requests
    if (url.pathname === '/favicon.ico') {
      return new Response(null, { status: 404 });
    }

    // Fail closed: an empty key must never be accepted as valid
    if (!applyEnvSecrets(env)) {
      return jsonResponse({
        status: "error",
        message: "Server misconfigured: add AUTH_KEY and BOT_TOKEN as secrets in Cloudflare (Settings -> Variables and Secrets) and redeploy."
      }, 500);
    }

    // Cron trigger endpoint via query key (supports ?mode=prepare, ?mode=publish, or ?mode=auto)
    const queryKey = url.searchParams.get('key');
    if (url.pathname === '/cron' || (url.pathname === '/' && queryKey === CONFIG.AUTH_KEY)) {
      if (queryKey !== CONFIG.AUTH_KEY) {
        return jsonResponse({ status: "error", message: "Unauthorized: Invalid key" }, 401);
      }
      const modeParam = url.searchParams.get('mode') || 'auto';
      return await handleCronExecution(env, false, null, modeParam);
    }

    // API: Manual dispatch or Pre-Stage from UI
    if (url.pathname === '/api/send' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (body.key !== CONFIG.AUTH_KEY) {
          return jsonResponse({ status: "error", message: "Unauthorized: Invalid key" }, 401);
        }
        if (Array.isArray(body.sourcesOverride) && body.sourcesOverride.length > 0) {
          await saveSourcesConfig(env, body.sourcesOverride);
        }
        if (body.templateOverride && typeof body.templateOverride === 'object') {
          await saveTemplateConfig(env, body.templateOverride);
        }
        const execMode = body.mode || 'immediate';
        return await handleCronExecution(env, body.ignoreKv === true, body.templateOverride || null, execMode);
      } catch (err) {
        return jsonResponse({ status: "error", message: err.message }, 400);
      }
    }

    // API: receive Iran-verified proxies from GitHub Actions, remember them, and stage the best unseen one
    if (url.pathname === '/api/stage' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (body.key !== CONFIG.AUTH_KEY) {
          return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
        }
        const kv = getKv(env);
        const list = Array.isArray(body.candidates) ? body.candidates.slice(0, 20) : [];
        const valid = list.filter(c =>
          c && c.server && c.port && c.geo && c.geo.country_code !== 'IR' &&
          typeof c.rawUrl === 'string' && c.rawUrl.startsWith('https://t.me/proxy?'));

        // Remember every verified proxy (the checker re-tests these first next time)
        let remembered = 0;
        if (kv && valid.length) {
          try {
            const winners = await loadWinners(kv);
            for (const c of valid) {
              winners[`${c.server}:${c.port}`] = {
                server: c.server, port: c.port, secret: c.secret, rawUrl: c.rawUrl,
                source: c.source || 'GitHub Actions', geo: c.geo,
                lastOk: Date.now(), lastPing: c.iranPing
              };
            }
            await saveWinners(kv, winners);
            remembered = valid.length;
          } catch (_) { /* memory is best-effort; staging must still work */ }
        }

        // Stage the best candidate that maximizes diversity (different /24 subnet & country from last published proxy when possible)
        const seenSet = kv ? await loadSeenSet(kv) : {};
        let lastRun = MEMORY_STATE.lastRun;
        if (kv && !lastRun) {
          try {
            const rawLast = await kv.get('mtp_last_run_meta');
            if (rawLast) lastRun = JSON.parse(rawLast);
          } catch (_) {}
        }
        const lastSubnet = lastRun && lastRun.server ? lastRun.server.split('.').slice(0, 3).join('.') : '';
        const lastCountry = lastRun && lastRun.country ? lastRun.country : '';

        const unseenCandidates = valid.filter(c => {
          const cacheKey = `seen_proxy_${c.server}_${c.port}`;
          const subnetKey = `seen_subnet_${(c.geo?.ip || c.server).split('.').slice(0, 3).join('.')}`;
          return !seenSet[cacheKey] && !seenSet[subnetKey];
        });

        // Sort unseen candidates: prefer Fake-TLS (ee...) / dd..., then prefer different country/subnet from last post
        unseenCandidates.sort((a, b) => {
          const aSecretTier = String(a.secret || '').toLowerCase().startsWith('ee') ? 0 : String(a.secret || '').toLowerCase().startsWith('dd') ? 1 : 2;
          const bSecretTier = String(b.secret || '').toLowerCase().startsWith('ee') ? 0 : String(b.secret || '').toLowerCase().startsWith('dd') ? 1 : 2;
          if (aSecretTier !== bSecretTier) return aSecretTier - bSecretTier;
          const aDiffCountry = (a.geo?.country && a.geo.country !== lastCountry) ? 0 : 1;
          const bDiffCountry = (b.geo?.country && b.geo.country !== lastCountry) ? 0 : 1;
          if (aDiffCountry !== bDiffCountry) return aDiffCountry - bDiffCountry;
          return (a.iranPing || 999) - (b.iranPing || 999);
        });

        if (unseenCandidates.length > 0) {
          // Multi-stage merge: if an earlier run this hour (e.g. 5:20) already staged a proxy,
          // merge its candidates with this run (e.g. 5:45) and pick the best diverse winner!
          const existingStaged = await getStagedProxy(env);
          const mergedPool = [...unseenCandidates];
          if (existingStaged && existingStaged.server) {
            const existingItems = [existingStaged, ...(Array.isArray(existingStaged.backupQueue) ? existingStaged.backupQueue : [])];
            for (const ex of existingItems) {
              if (ex && ex.server && !mergedPool.some(m => m.server === ex.server && m.port === ex.port)) {
                mergedPool.push(ex);
              }
            }
          }
          const c = mergedPool[0];
          const staged = await saveStagedProxy(env, {
            server: c.server, port: c.port, secret: c.secret, rawUrl: c.rawUrl,
            source: c.source || 'GitHub Actions', geo: c.geo, iranPing: c.iranPing,
            iranNodes: c.iranNodes || [], checkHostSummary: c.checkHostSummary,
            checkHostReportUrl: c.checkHostReportUrl,
            scarce: body.scarce === true,
            backupQueue: mergedPool.slice(1, 8)
          });
          return jsonResponse({
            status: "staged", remembered, scarce: body.scarce === true,
            source: staged.source,
            queued_backups: mergedPool.length - 1,
            proxy: { server: staged.server, port: staged.port, ping: staged.iranPing, country: staged.geo?.country, source: staged.source }
          });
        }
        return jsonResponse({ status: "skipped", remembered, reason: "all candidates already published or invalid" });
      } catch (err) {
        return jsonResponse({ status: "error", message: err.message }, 400);
      }
    }

    // API: remembered winners + currently "seen" proxy keys (used by the GitHub checker)
    if (url.pathname === '/api/winners' && request.method === 'GET') {
      if (url.searchParams.get('key') !== CONFIG.AUTH_KEY) {
        return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
      }
      const kv = getKv(env);
      const winners = kv ? await loadWinners(kv) : {};
      const seenSet = kv ? await loadSeenSet(kv) : {};
      const list = Object.values(winners).sort((x, y) => (y.lastOk || 0) - (x.lastOk || 0));
      return jsonResponse({ status: "success", winners: list, seen: Object.keys(seenSet) });
    }


    // API: Round-Robin Source Rotation + Cloudflare Edge TCP Pre-Filter for GitHub Actions
    // Scrapes the current turn's source (then rotates cursor to next source for the next call),
    // tests TCP sockets directly on Cloudflare Edge, and returns only LIVE unseen candidates to GitHub Actions!
    if (url.pathname === '/api/candidates' && request.method === 'GET') {
      if (url.searchParams.get('key') !== CONFIG.AUTH_KEY) {
        return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
      }
      const kv = getKv(env);
      const allSources = (await getSourcesConfig(env)).filter(s => s.enabled !== false);
      if (allSources.length === 0) {
        return jsonResponse({ status: "error", message: "No enabled sources" }, 400);
      }

      // Read & increment Round-Robin cursor in KV so every call starts from the NEXT source
      let cursor = 0;
      if (kv) {
        try {
          const rawCursor = await kv.get('mtp_source_cursor');
          if (rawCursor !== null) cursor = parseInt(rawCursor, 10) || 0;
        } catch (_) {}
      }
      const startIndex = cursor % allSources.length;
      const nextCursor = (startIndex + 1) % allSources.length;
      if (kv) {
        try { await kv.put('mtp_source_cursor', String(nextCursor)); } catch (_) {}
      }

      // Rotate sources list starting from startIndex
      const rotatedSources = [
        ...allSources.slice(startIndex),
        ...allSources.slice(0, startIndex)
      ];

      const seenSet = kv ? await loadSeenSet(kv) : {};
      const rawPool = [];
      const seenInBatch = new Set();
      const sourceStats = [];

      // Scrape rotated sources (prioritizing the current turn's primary source, plus secondary sources for diversity)
      for (let sIdx = 0; sIdx < rotatedSources.length; sIdx++) {
        const src = rotatedSources[sIdx];
        // Take more from the primary turn source, fewer from secondary sources so we stay within Cloudflare subrequest limits
        const cap = sIdx === 0 ? 25 : 10;
        let fetchedCount = 0;
        let freshCount = 0;
        try {
          const res = await fetch(src.url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0" }
          });
          if (res.ok) {
            const text = await res.text();
            let links = extractProxyLinks(text);
            fetchedCount = links.length;
            if (src.type === 'telegram' || (src.url && src.url.includes('t.me/'))) {
              links = links.reverse();
            } else {
              links = links.sort(() => Math.random() - 0.5);
            }
            for (const item of links) {
              if (freshCount >= cap || rawPool.length >= 42) break;
              if (isLikelyIranian(item.server)) continue;
              const k = `${item.server.toLowerCase()}:${item.port}`;
              const cacheKey = `seen_proxy_${item.server}_${item.port}`;
              if (seenInBatch.has(k) || seenSet[cacheKey]) continue;
              seenInBatch.add(k);
              rawPool.push({ ...item, source: src.name || src.id, sourcePriority: sIdx + 1 });
              freshCount++;
            }
          }
        } catch (_) {}
        sourceStats.push({ id: src.id, name: src.name, turnOrder: sIdx + 1, parsed: fetchedCount, selected: freshCount });
        if (rawPool.length >= 42) break;
      }

      // Pre-test TCP sockets on Cloudflare Edge in parallel batches so dead proxies never go to GitHub!
      const liveCandidates = [];
      const batchSize = 14;
      for (let i = 0; i < rawPool.length; i += batchSize) {
        const batch = rawPool.slice(i, i + batchSize);
        const results = await Promise.allSettled(batch.map(async (c) => {
          const edgePing = await testTcpSocketLatency(c.server, c.port, 1600, c.secret);
          return edgePing !== null ? { ...c, edgePing } : null;
        }));
        for (const r of results) {
          if (r.status === 'fulfilled' && r.value) {
            liveCandidates.push(r.value);
          }
        }
      }

      return jsonResponse({
        status: "success",
        primary_source: rotatedSources[0].name || rotatedSources[0].id,
        next_source_index: nextCursor,
        source_stats: sourceStats,
        total_checked_on_edge: rawPool.length,
        live_count: liveCandidates.length,
        candidates: liveCandidates
      });
    }

    // API: Get sources configuration
    if (url.pathname === '/api/get-sources' && request.method === 'GET') {
      const auth = url.searchParams.get('key');
      if (auth !== CONFIG.AUTH_KEY) {
        return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
      }
      const sources = await getSourcesConfig(env);
      return jsonResponse({ status: "success", sources });
    }

    // API: Save sources configuration
    if (url.pathname === '/api/save-sources' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (body.key !== CONFIG.AUTH_KEY) {
          return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
        }
        if (!Array.isArray(body.sources)) {
          return jsonResponse({ status: "error", message: "Invalid sources payload" }, 400);
        }
        const savedSources = await saveSourcesConfig(env, body.sources);
        const kvInfo = getKvInfo(env);
        return jsonResponse({
          status: "success",
          kv_connected: !!kvInfo.kv,
          kv_binding: kvInfo.name,
          message: kvInfo.kv
            ? `Saved to KV (${kvInfo.name})`
            : "Saved to Worker Memory (Warning: KV binding not detected)",
          sources: savedSources
        });
      } catch (err) {
        return jsonResponse({ status: "error", message: err.message }, 400);
      }
    }

    // API: Get Telegram post template configuration
    if (url.pathname === '/api/get-template' && request.method === 'GET') {
      const auth = url.searchParams.get('key');
      if (auth !== CONFIG.AUTH_KEY) {
        return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
      }
      const template = await getTemplateConfig(env);
      return jsonResponse({ status: "success", template });
    }

    // API: Save Telegram post template configuration
    if (url.pathname === '/api/save-template' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (body.key !== CONFIG.AUTH_KEY) {
          return jsonResponse({ status: "error", message: "Unauthorized" }, 401);
        }
        if (!body.template || typeof body.template !== 'object') {
          return jsonResponse({ status: "error", message: "Invalid template payload" }, 400);
        }
        const saved = await saveTemplateConfig(env, body.template);
        return jsonResponse({
          status: "success",
          message: "Post template saved successfully",
          template: saved
        });
      } catch (err) {
        return jsonResponse({ status: "error", message: err.message }, 400);
      }
    }

    // API: Get Channel Profile Info (Avatar, Subscribers, Title)
    if (url.pathname === '/api/channel-info' && request.method === 'GET') {
      const channelInfo = await getChannelInfo(env);
      return jsonResponse({ status: "success", channel_info: channelInfo });
    }

    // API: System status
    if (url.pathname === '/api/status' && request.method === 'GET') {
      const kvInfo = getKvInfo(env);
      const kv = kvInfo.kv;
      const sources = await getSourcesConfig(env);
      const template = await getTemplateConfig(env);
      let lastRun = MEMORY_STATE.lastRun;
      let stagedProxy = MEMORY_STATE.stagedProxy;
      if (kv) {
        try {
          const rawLast = await kv.get('mtp_last_run_meta');
          if (rawLast) lastRun = JSON.parse(rawLast);
        } catch (_) {}
        try {
          const rawStaged = await kv.get('mtp_staged_proxy');
          if (rawStaged) stagedProxy = JSON.parse(rawStaged);
        } catch (_) {}
      }
      // Expire staged proxy if older than 55 minutes
      if (stagedProxy && (Date.now() - (stagedProxy.staged_at || 0) > 3300000)) {
        stagedProxy = null;
      }
      const channelInfo = await getChannelInfo(env);
      return jsonResponse({
        status: "success",
        kv_connected: !!kv,
        kv_binding: kvInfo.name,
        auth_configured: true,
        channel: CONFIG.CHANNEL_ID,
        active_sources_count: sources.filter(s => s.enabled).length,
        total_sources_count: sources.length,
        last_run: lastRun,
        staged_proxy: stagedProxy,
        channel_info: channelInfo,
        sources,
        template
      });
    }

    // Default: Serve Web UI Dashboard
    return new Response(renderDashboardHtml(), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  },

  async scheduled(event, env, ctx) {
    if (!applyEnvSecrets(env)) return;
    // Two-Stage Cron Architecture:
    // - Cron "55 * * * *" (or minutes 50..58): Pre-tests proxies via Check-Host Iran nodes 5 mins early and stages the winner in KV.
    // - Cron "0 * * * *" (or top of the hour): Instantly dispatches the pre-tested staged proxy at :00:00 sharp (or falls back to live test).
    const cronExpr = String((event && event.cron) || '');
    const nowMin = new Date(event && event.scheduledTime ? event.scheduledTime : Date.now()).getUTCMinutes();
    let mode = 'auto';
    if (cronExpr.startsWith('55 ') || (nowMin >= 50 && nowMin <= 58)) {
      mode = 'prepare';
    } else if (cronExpr.startsWith('0 ') || nowMin <= 5) {
      mode = 'publish';
    }
    ctx.waitUntil(handleCronExecution(env, false, null, mode));
  }
};

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

// Dynamically fetch and cache Telegram Channel Profile Photo and Subscriber Count
async function getChannelInfo(env) {
  const kv = getKv(env);
  const now = Date.now();

  // 1. Check in-memory cache (TTL 30 minutes)
  if (MEMORY_STATE.channelInfo && (now - (MEMORY_STATE.channelInfo.cached_at || 0) < 1800000)) {
    return MEMORY_STATE.channelInfo;
  }

  // 2. Check KV cache
  if (kv) {
    try {
      const raw = await kv.get('mtp_channel_info_cache');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && (now - (parsed.cached_at || 0) < 1800000)) {
          MEMORY_STATE.channelInfo = parsed;
          return parsed;
        }
      }
    } catch (_) {}
  }

  let memberCount = null;
  let photoUrl = null;
  let subscribersText = null;
  let title = '𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬';

  // 3. Query Telegram Bot API for real member count
  try {
    const memberRes = await fetch(`https://api.telegram.org/bot${CONFIG.BOT_TOKEN}/getChatMemberCount?chat_id=${encodeURIComponent(CONFIG.CHANNEL_ID)}`);
    if (memberRes.ok) {
      const mData = await memberRes.json();
      if (mData.ok && typeof mData.result === 'number') {
        memberCount = mData.result;
        subscribersText = `${memberCount.toLocaleString('en-US')} subscribers`;
      }
    }
  } catch (_) {}

  // 4. Scrape Telegram Web Public Page for Avatar Photo URL & Metadata
  try {
    const cleanChannel = CONFIG.CHANNEL_ID.replace('@', '');
    const webRes = await fetch(`https://t.me/s/${cleanChannel}`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
      }
    });
    if (webRes.ok) {
      const html = await webRes.text();
      const imgMatch = html.match(/<meta property="og:image" content="([^"]+)"/i) ||
                       html.match(/class="tgme_page_photo_image" src="([^"]+)"/i);
      if (imgMatch && imgMatch[1]) {
        photoUrl = imgMatch[1];
      }

      if (!subscribersText) {
        const extraMatch = html.match(/class="tgme_page_extra"[^>]*>([^<]+)<\/div>/i);
        if (extraMatch && extraMatch[1]) {
          subscribersText = extraMatch[1].trim();
        }
      }

      const titleMatch = html.match(/class="tgme_page_title"[^>]*><span[^>]*>([^<]+)<\/span>/i) ||
                         html.match(/<meta property="og:title" content="([^"]+)"/i);
      if (titleMatch && titleMatch[1]) {
        title = titleMatch[1].trim();
      }
    }
  } catch (_) {}

  const result = {
    title: title || '𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬',
    username: CONFIG.CHANNEL_ID.replace('@', ''),
    avatar: photoUrl || null,
    subscribers: subscribersText || (memberCount ? `${memberCount.toLocaleString('en-US')} subscribers` : '2,148 subscribers'),
    member_count: memberCount || null,
    cached_at: now
  };

  MEMORY_STATE.channelInfo = result;

  if (kv) {
    try {
      await kv.put('mtp_channel_info_cache', JSON.stringify(result), { expirationTtl: 1800 });
    } catch (_) {}
  }

  return result;
}

// Safe KV retrieval helper supporting PROXIES_KV and any bound KV namespace
function getKvInfo(env) {
  if (!env || typeof env !== 'object') return { kv: null, name: null };
  const preferredNames = ['PROXIES_KV', 'PROXY_KV', 'KV', 'SETTINGS_KV', 'mst_proxies_db'];
  for (const name of preferredNames) {
    if (env[name] && typeof env[name].get === 'function' && typeof env[name].put === 'function') {
      return { kv: env[name], name };
    }
  }
  // Fallback: auto-detect any bound KV namespace on env
  for (const [key, val] of Object.entries(env)) {
    if (val && typeof val === 'object' && typeof val.get === 'function' && typeof val.put === 'function') {
      return { kv: val, name: key };
    }
  }
  return { kv: null, name: null };
}

function getKv(env) {
  return getKvInfo(env).kv;
}

function normalizeSourcesList(sources) {
  if (!Array.isArray(sources) || sources.length === 0) {
    return CONFIG.DEFAULT_SOURCES.map((s, idx) => ({ ...s, enabled: Boolean(s.enabled), priority: idx + 1 }));
  }
  return sources.map((s, idx) => ({
    id: String(s.id || `src_${idx + 1}`),
    name: String(s.name || s.id || `Source ${idx + 1}`),
    type: s.type === 'text' || (s.url && !String(s.url).includes('t.me/')) ? 'text' : 'telegram',
    url: String(s.url || '').trim(),
    enabled: s.enabled !== false && s.enabled !== 'false',
    priority: idx + 1
  }));
}

// Get sources configuration from PROXIES_KV or defaults
async function getSourcesConfig(env) {
  const kv = getKv(env);
  if (kv) {
    try {
      const raw = await kv.get('mtp_sources_config');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const sorted = [...parsed].sort((a, b) => (Number(a.priority) || 99) - (Number(b.priority) || 99));
          const normalized = normalizeSourcesList(sorted);
          MEMORY_STATE.sources = normalized;
          return normalized;
        }
      }
    } catch (e) {}
  }
  if (Array.isArray(MEMORY_STATE.sources) && MEMORY_STATE.sources.length > 0) {
    return normalizeSourcesList(MEMORY_STATE.sources);
  }
  return normalizeSourcesList(CONFIG.DEFAULT_SOURCES);
}

// Save sources configuration to PROXIES_KV & memory in exact order
async function saveSourcesConfig(env, sources) {
  const normalized = normalizeSourcesList(sources);
  MEMORY_STATE.sources = normalized;
  const kv = getKv(env);
  if (kv) {
    await kv.put('mtp_sources_config', JSON.stringify(normalized));
  }
  return normalized;
}

// Get Telegram template configuration from PROXIES_KV or defaults
async function getTemplateConfig(env) {
  const kv = getKv(env);
  if (kv) {
    try {
      const raw = await kv.get('mtp_template_config');
      if (raw) {
        const saved = JSON.parse(raw);
        if (saved && typeof saved === 'object') {
          return { ...CONFIG.DEFAULT_TEMPLATE, ...saved };
        }
      }
    } catch (e) {}
  }
  if (MEMORY_STATE.template) {
    return { ...CONFIG.DEFAULT_TEMPLATE, ...MEMORY_STATE.template };
  }
  return { ...CONFIG.DEFAULT_TEMPLATE };
}

// Save Telegram template configuration to KV & memory
async function saveTemplateConfig(env, templateInput) {
  const merged = {
    ...CONFIG.DEFAULT_TEMPLATE,
    messageTemplate: String(templateInput.messageTemplate || CONFIG.DEFAULT_TEMPLATE.messageTemplate),
    signature: String(templateInput.signature ?? CONFIG.DEFAULT_TEMPLATE.signature),
    buttonText: String(templateInput.buttonText || CONFIG.DEFAULT_TEMPLATE.buttonText),
    secondButtonEnabled: Boolean(templateInput.secondButtonEnabled),
    secondButtonText: String(templateInput.secondButtonText || CONFIG.DEFAULT_TEMPLATE.secondButtonText),
    secondButtonUrl: String(templateInput.secondButtonUrl || CONFIG.DEFAULT_TEMPLATE.secondButtonUrl),
    disableWebPagePreview: templateInput.disableWebPagePreview !== false
  };
  MEMORY_STATE.template = merged;
  const kv = getKv(env);
  if (kv) {
    await kv.put('mtp_template_config', JSON.stringify(merged));
  }
  return merged;
}

// Helper: Retrieve or clear pre-tested staged proxy from KV / Memory
async function getStagedProxy(env) {
  const kv = getKv(env);
  if (kv) {
    try {
      const raw = await kv.get('mtp_staged_proxy');
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && parsed.server && (Date.now() - (parsed.staged_at || 0) < 3300000)) {
          MEMORY_STATE.stagedProxy = parsed;
          return parsed;
        }
      }
    } catch (_) {}
  }
  if (MEMORY_STATE.stagedProxy && (Date.now() - (MEMORY_STATE.stagedProxy.staged_at || 0) < 3300000)) {
    return MEMORY_STATE.stagedProxy;
  }
  return null;
}

async function saveStagedProxy(env, proxyData) {
  const stagedObj = {
    ...proxyData,
    staged_at: Date.now()
  };
  MEMORY_STATE.stagedProxy = stagedObj;
  const kv = getKv(env);
  if (kv) {
    try {
      await kv.put('mtp_staged_proxy', JSON.stringify(stagedObj), { expirationTtl: 3300 });
    } catch (_) {}
  }
  return stagedObj;
}

async function clearStagedProxy(env) {
  MEMORY_STATE.stagedProxy = null;
  const kv = getKv(env);
  if (kv) {
    try {
      await kv.delete('mtp_staged_proxy');
    } catch (_) {}
  }
}

// Core execution engine: Supports 3 modes:
// - 'prepare': Runs at :55 (5 minutes before the hour), tests proxies via Check-Host Iran datacenters, and stages the winner in KV for :00.
// - 'publish': Runs at :00 sharp, immediately sends the staged proxy to Telegram (<0.3s) or falls back to live scrape+test if none is staged.
// - 'immediate' / 'auto': Auto-detects or runs full scrape + Check-Host Iran test + immediate Telegram dispatch.
async function handleCronExecution(env, ignoreKv = false, templateOverride = null, mode = 'immediate') {
  const kvInfo = getKvInfo(env);
  const kv = kvInfo.kv;
  const sources = await getSourcesConfig(env);
  const executionLogs = [];
  function addLog(msg) {
    const ts = new Date().toLocaleTimeString('en-GB', { timeZone: 'Asia/Tehran', hour12: false });
    executionLogs.push(`[${ts}] ${msg}`);
  }

  // Resolve 'auto' mode based on current minute if invoked via generic /cron
  let effectiveMode = mode;
  if (effectiveMode === 'auto') {
    const currentMin = new Date().getUTCMinutes();
    if (currentMin >= 50 && currentMin <= 58) {
      effectiveMode = 'prepare';
    } else {
      effectiveMode = 'publish';
    }
  }

  const templateConfig = templateOverride
    ? { ...(await getTemplateConfig(env)), ...templateOverride }
    : await getTemplateConfig(env);

  addLog(`🚀 [PIPELINE] Mode: ${effectiveMode.toUpperCase()} | Deduplication: ${ignoreKv ? 'FORCE BYPASS' : 'ACTIVE'}`);
  addLog(`📦 [STORAGE] KV Engine: ${kvInfo.name ? `${kvInfo.name} (Connected)` : 'Worker In-Memory (No KV bound)'}`);

  // FAST-PATH: If mode is 'publish' (e.g. at :00 top-of-hour Cron or "Publish Staged" button), check if a pre-tested proxy from :55 is ready!
  if (effectiveMode === 'publish' && !ignoreKv) {
    const staged = await getStagedProxy(env);
    if (staged && staged.server && staged.geo && staged.geo.country_code !== 'IR') {
      const ageSec = Math.round((Date.now() - (staged.staged_at || Date.now())) / 1000);
      addLog(`⚡ [FAST-PUBLISH] Found pre-tested proxy in queue (verified ${ageSec}s ago via Check-Host Iran)!`);
      addLog(`   ├─ Staged Winner: ${staged.server}:${staged.port} (${staged.geo.city ? staged.geo.city + ', ' : ''}${staged.geo.country} ${staged.geo.flag})`);
      addLog(`   ├─ Iran Datacenter Ping: ${staged.iranPing}ms (${staged.checkHostSummary || 'Verified'})`);
      if (staged.checkHostReportUrl) {
        addLog(`   ├─ Check-Host Report: ${staged.checkHostReportUrl}`);
      }
      addLog(`📤 [TELEGRAM] Instant top-of-the-hour dispatch to ${CONFIG.CHANNEL_ID}...`);

      const postResult = await postToTelegram(staged, templateConfig);
      if (postResult.ok) {
        const cacheKey = `seen_proxy_${staged.server}_${staged.port}`;
        const lastRunMeta = {
          timestamp: Date.now(),
          server: staged.server,
          port: staged.port,
          country: staged.geo.country,
          city: staged.geo.city || '',
          flag: staged.geo.flag || '🌐',
          ping: staged.iranPing,
          source: staged.source,
          check_host_url: staged.checkHostReportUrl || null,
          iran_nodes: staged.iranNodes || []
        };
        MEMORY_STATE.lastRun = lastRunMeta;
        MEMORY_STATE.seenProxies.set(cacheKey, Date.now() + CONFIG.KV_TTL_SECONDS * 1000);

        if (kv) {
          await markSeen(kv, cacheKey, staged.scarce ? CONFIG.KV_TTL_SCARCE_SECONDS : undefined);
          const ipPrefix = (staged.geo?.ip || staged.server).split('.').slice(0, 3).join('.');
          if (ipPrefix && ipPrefix.split('.').length === 3 && !staged.scarce) {
            await markSeen(kv, `seen_subnet_${ipPrefix}`, 7200); // 2h cooldown on same /24 subnet for diversity
          }
          await kv.put('mtp_last_run_meta', JSON.stringify(lastRunMeta));
        }
        // Promote next backup candidate in queue (from a different subnet) if available so next run has an instant fallback
        if (Array.isArray(staged.backupQueue) && staged.backupQueue.length > 0) {
          const usedPrefix = (staged.geo?.ip || staged.server).split('.').slice(0, 3).join('.');
          const nextInLine = staged.backupQueue.find(b => (b.geo?.ip || b.server).split('.').slice(0, 3).join('.') !== usedPrefix);
          if (nextInLine) {
            await saveStagedProxy(env, { ...nextInLine, backupQueue: staged.backupQueue.filter(x => x !== nextInLine) });
          } else {
            await clearStagedProxy(env);
          }
        } else {
          await clearStagedProxy(env);
        }
        addLog(`   ├─ Telegram API: Success 200 (Message ID #${postResult.result?.message_id})`);
        addLog(`🎉 [SUCCESS] Pre-staged proxy published right on time to @MSTProxy!`);

        return jsonResponse({
          status: "success",
          mode: "publish_from_staged",
          proxy: {
            server: staged.server,
            port: staged.port,
            location: `${staged.geo.city ? staged.geo.city + ', ' : ''}${staged.geo.country} ${staged.geo.flag}`,
            ping: staged.iranPing,
            source: staged.source,
            check_host_url: staged.checkHostReportUrl || null,
            iran_nodes: staged.iranNodes || []
          },
          telegram_response: postResult,
          logs: executionLogs
        }, 200);
      } else {
        addLog(`   └─ ⚠️ Telegram send error on staged proxy (${postResult.description || 'Unknown'}). Falling back to fresh scan...`);
      }
    } else if (effectiveMode === 'publish') {
      addLog(`ℹ️ [QUEUE] No pre-staged proxy found in KV (or expired). Running live Check-Host Iran scan & publish...`);
    }
  }

  const activeSources = sources.filter(s => s.enabled);
  addLog(`📋 [PIPELINE] ${activeSources.length} active sources in queue: ${activeSources.map(s => `#${s.priority} ${s.name}`).join(' ➔ ')}`);

  const debugReport = {
    _pipeline_meta: {
      mode: effectiveMode,
      kv_binding: kvInfo.name || "NONE (In-Memory)",
      execution_order: sources.map(s => `#${s.priority} ${s.name} [${s.enabled ? 'ENABLED' : 'DISABLED'}]`)
    }
  };

  let selectedProxy = null;

  // Rotate enabled sources using KV Round-Robin cursor so every run checks the next source in line!
  const enabledList = sources.filter(s => s.enabled);
  let rrCursor = 0;
  if (kv && enabledList.length > 0) {
    try {
      const rawCur = await kv.get('mtp_source_cursor');
      if (rawCur !== null) rrCursor = parseInt(rawCur, 10) || 0;
      await kv.put('mtp_source_cursor', String((rrCursor + 1) % enabledList.length));
    } catch (_) {}
  }
  const rotIdx = enabledList.length > 0 ? (rrCursor % enabledList.length) : 0;
  const orderedSources = [
    ...enabledList.slice(rotIdx),
    ...enabledList.slice(0, rotIdx),
    ...sources.filter(s => !s.enabled)
  ];
  if (enabledList.length > 0) {
    addLog(`🔄 [ROUND-ROBIN] Turn Primary Source: #${orderedSources[0].priority} ${orderedSources[0].name}`);
  }
  for (const src of orderedSources) {
    if (!src.enabled) {
      debugReport[src.name || src.id] = { status: "disabled_by_user" };
      continue;
    }

    addLog(`────────────────────────────────────────────────────────────`);
    addLog(`🔍 [SOURCE #${src.priority}] Checking ${src.name} (${src.type.toUpperCase()})`);
    addLog(`   ├─ Target URL: ${src.url}`);

    const report = {
      source: src.id,
      http_status: null,
      raw_matches: 0,
      fresh_links: 0,
      outcome: ""
    };

    try {
      const cacheBuster = `_nocache=${Date.now()}`;
      const fetchUrl = src.url.includes('?') ? `${src.url}&${cacheBuster}` : `${src.url}?${cacheBuster}`;

      const res = await fetch(fetchUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache"
        }
      });
      report.http_status = res.status;

      if (!res.ok) {
        report.outcome = `HTTP Error ${res.status}`;
        debugReport[src.name || src.id] = report;
        addLog(`   └─ ❌ HTTP ${res.status} Error fetching source content`);
        continue;
      }

      const text = await res.text();
      report.text_length = text.length;
      addLog(`   ├─ HTTP 200 OK (${(text.length / 1024).toFixed(1)} KB received)`);

      let rawLinks = extractProxyLinks(text);

      if (src.type === 'telegram' || (src.url && src.url.includes('t.me/'))) {
        rawLinks = rawLinks.reverse();
      }
      report.raw_matches = rawLinks.length;
      addLog(`   ├─ Parsed: ${rawLinks.length} total proxy link(s) matched in source`);

      if (rawLinks.length === 0) {
        report.outcome = "No proxy links found in source";
        debugReport[src.name || src.id] = report;
        addLog(`   └─ ⚠️ No MTProto proxy links found in this source`);
        continue;
      }

      const seenSet = (!ignoreKv && kv) ? await loadSeenSet(kv) : {};

      const freshCandidates = [];
      for (const item of rawLinks) {
        const cacheKey = `seen_proxy_${item.server}_${item.port}`;
        if (!ignoreKv) {
          if (kv) {
            if (seenSet[cacheKey]) continue;
          } else if (MEMORY_STATE.seenProxies.has(cacheKey)) {
            const exp = MEMORY_STATE.seenProxies.get(cacheKey);
            if (Date.now() < exp) continue;
          }
        }
        freshCandidates.push(item);
      }
      report.fresh_links = freshCandidates.length;
      const seenCount = rawLinks.length - freshCandidates.length;
      addLog(`   ├─ Deduplication Filter: ${freshCandidates.length} fresh / ${seenCount} recently seen in KV`);

      if (freshCandidates.length === 0) {
        report.outcome = "All proxies from this source already processed recently";
        debugReport[src.name || src.id] = report;
        addLog(`   └─ ⚠️ Skipped: All ${rawLinks.length} proxies were already posted recently (within ${CONFIG.KV_TTL_SECONDS}s TTL)`);
        continue;
      }

      addLog(`   ├─ Testing candidates via Edge Socket + GeoIP + Check-Host.net (Iran Datacenters)...`);
      const testedWinner = await findBestForeignProxy(freshCandidates, addLog);
      if (testedWinner) {
        selectedProxy = {
          ...testedWinner,
          source: src.name || src.id
        };
        report.outcome = `Selected proxy: ${testedWinner.server}:${testedWinner.port} (${testedWinner.geo.country_code}) with Iran ping ${testedWinner.iranPing}ms`;
        debugReport[src.name || src.id] = report;
        addLog(`   └─ 🏆 Winner Confirmed from ${src.name}: ${testedWinner.server}:${testedWinner.port} (${testedWinner.geo.city ? testedWinner.geo.city + ', ' : ''}${testedWinner.geo.country} ${testedWinner.geo.flag}) [Iran Avg Ping: ${testedWinner.iranPing}ms]`);
        break;
      } else {
        report.outcome = "No foreign proxy passed Check-Host Iran datacenter verification";
        debugReport[src.name || src.id] = report;
        addLog(`   └─ ⚠️ No candidate from ${src.name} passed Check-Host Iran ping/TCP verification`);
      }
    } catch (err) {
      report.outcome = `Error: ${err.message}`;
      debugReport[src.name || src.id] = report;
      addLog(`   └─ ❌ Error processing source: ${err.message}`);
    }
  }

  if (!selectedProxy || (selectedProxy.geo && selectedProxy.geo.country_code === 'IR')) {
    addLog(`────────────────────────────────────────────────────────────`);
    addLog(`❌ [FAILED] No valid foreign proxies passed Check-Host Iran verification across active sources.`);
    return jsonResponse({
      status: "failed",
      mode: effectiveMode,
      reason: "No valid foreign proxies passed Check-Host Iran datacenter verification",
      debug_report: debugReport,
      logs: executionLogs
    }, 200);
  }

  // PRE-STAGE MODE (:55 Cron or "Pre-Test & Stage" button): Save verified proxy to KV for instant :00 publish!
  if (effectiveMode === 'prepare') {
    addLog(`────────────────────────────────────────────────────────────`);
    addLog(`🕒 [PRE-STAGE] Saving Check-Host Iran verified proxy to KV queue for exact :00 top-of-hour dispatch...`);
    const stagedObj = await saveStagedProxy(env, selectedProxy);
    addLog(`✅ [STAGED] Proxy ${selectedProxy.server}:${selectedProxy.port} (${selectedProxy.iranPing}ms from Iran) is queued and ready for :00!`);
    return jsonResponse({
      status: "staged",
      mode: "prepare",
      staged_proxy: stagedObj,
      proxy: {
        server: selectedProxy.server,
        port: selectedProxy.port,
        location: `${selectedProxy.geo.city ? selectedProxy.geo.city + ', ' : ''}${selectedProxy.geo.country} ${selectedProxy.geo.flag}`,
        ping: selectedProxy.iranPing,
        source: selectedProxy.source,
        check_host_url: selectedProxy.checkHostReportUrl || null,
        iran_nodes: selectedProxy.iranNodes || []
      },
      debug_report: debugReport,
      logs: executionLogs
    }, 200);
  }

  // IMMEDIATE OR FALLBACK PUBLISH MODE: Send directly to Telegram
  addLog(`────────────────────────────────────────────────────────────`);
  addLog(`📤 [TELEGRAM] Dispatching Iran-verified proxy to channel ${CONFIG.CHANNEL_ID}...`);
  const postResult = await postToTelegram(selectedProxy, templateConfig);

  if (postResult.ok) {
    const cacheKey = `seen_proxy_${selectedProxy.server}_${selectedProxy.port}`;
    const lastRunMeta = {
      timestamp: Date.now(),
      server: selectedProxy.server,
      port: selectedProxy.port,
      country: selectedProxy.geo.country,
      city: selectedProxy.geo.city || '',
      flag: selectedProxy.geo.flag || '🌐',
      ping: selectedProxy.iranPing,
      source: selectedProxy.source,
      check_host_url: selectedProxy.checkHostReportUrl || null,
      iran_nodes: selectedProxy.iranNodes || []
    };
    MEMORY_STATE.lastRun = lastRunMeta;
    MEMORY_STATE.seenProxies.set(cacheKey, Date.now() + CONFIG.KV_TTL_SECONDS * 1000);

    if (kv) {
      await markSeen(kv, cacheKey);
      await kv.put('mtp_last_run_meta', JSON.stringify(lastRunMeta));
    }
    await clearStagedProxy(env);
    addLog(`   ├─ Telegram API: Success 200 (Message ID #${postResult.result?.message_id})`);
    addLog(`   ├─ Cached proxy key ${cacheKey} (TTL: ${CONFIG.KV_TTL_SECONDS}s)`);
    addLog(`🎉 [SUCCESS] Live Iran-verified proxy dispatched and published to @MSTProxy!`);
  } else {
    addLog(`   └─ ❌ Telegram API Error: ${postResult.description || 'Unknown error'}`);
  }

  return jsonResponse({
    status: postResult.ok ? "success" : "telegram_send_failed",
    mode: effectiveMode,
    proxy: {
      server: selectedProxy.server,
      port: selectedProxy.port,
      location: `${selectedProxy.geo.city ? selectedProxy.geo.city + ', ' : ''}${selectedProxy.geo.country} ${selectedProxy.geo.flag}`,
      ping: selectedProxy.iranPing,
      source: selectedProxy.source,
      check_host_url: selectedProxy.checkHostReportUrl || null,
      iran_nodes: selectedProxy.iranNodes || []
    },
    telegram_response: postResult,
    debug_report: debugReport,
    logs: executionLogs
  }, 200);
}

function extractProxyLinks(content) {
  if (!content || typeof content !== 'string') return [];
  const results = [];

  // Normalize HTML entities common in Telegram web preview markup
  const decodedContent = content
    .replace(/&amp;/gi, '&')
    .replace(/&#38;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/%26/gi, '&')
    .replace(/%3D/gi, '=')
    .replace(/%3F/gi, '?');

  const regex = /(?:(?:https?:)?\/\/(?:www\.)?(?:t\.me|telegram\.me)\/|tg:\/\/?|\/)?(proxy|socks)\?([^\s\"'<>\\]+)/gi;
  let match;

  while ((match = regex.exec(decodedContent)) !== null) {
    try {
      let queryString = match[2];
      queryString = queryString.replace(/[)\]}>,;]+$/, '');
      const params = new URLSearchParams(queryString);
      const server = params.get('server');
      const port = parseInt(params.get('port'), 10);
      const secret = params.get('secret');

      if (server && port && secret && !isNaN(port) && port > 0 && port <= 65535) {
        const cleanServer = server.trim().replace(/^\/+/, '').replace(/\.$/, '');
        const cleanSecret = secret.trim();
        results.push({
          server: cleanServer,
          port,
          secret: cleanSecret,
          rawUrl: `https://t.me/proxy?server=${encodeURIComponent(cleanServer)}&port=${port}&secret=${encodeURIComponent(cleanSecret)}`
        });
      }
    } catch (e) {}
  }

  // Anchor Tag Fallback: specifically scan href attributes for hyperlinked captions
  const anchorRegex = /<a\s+[^>]*href=["']([^"']*(?:proxy|socks)\?[^"']+)["'][^>]*>/gi;
  let anchorMatch;
  while ((anchorMatch = anchorRegex.exec(decodedContent)) !== null) {
    try {
      const href = anchorMatch[1];
      const qIndex = href.indexOf('?');
      if (qIndex !== -1) {
        const queryString = href.slice(qIndex + 1).replace(/&amp;/g, '&');
        const params = new URLSearchParams(queryString);
        const server = params.get('server');
        const port = parseInt(params.get('port'), 10);
        const secret = params.get('secret');

        if (server && port && secret && !isNaN(port) && port > 0 && port <= 65535) {
          const cleanServer = server.trim().replace(/^\/+/, '').replace(/\.$/, '');
          const cleanSecret = secret.trim();
          results.push({
            server: cleanServer,
            port,
            secret: cleanSecret,
            rawUrl: `https://t.me/proxy?server=${encodeURIComponent(cleanServer)}&port=${port}&secret=${encodeURIComponent(cleanSecret)}`
          });
        }
      }
    } catch (e) {}
  }

  const uniqueMap = new Map();
  for (const item of results) {
    const key = `${item.server.toLowerCase()}:${item.port}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, item);
    }
  }
  return Array.from(uniqueMap.values());
}

// Comprehensive filter for Iranian domestic tunnel hosts, keywords and domain suffixes
function isLikelyIranian(server) {
  if (!server) return false;
  const s = server.toLowerCase();
  if (s.endsWith('.ir') || s.includes('.ir.') || s.includes('.ir/')) return true;
  const irKeywords = [
    'iran', 'tehran', 'shiraz', 'esfahan', 'tabriz', 'mashhad', 'kerman', 'qom', 'karaj',
    'mci', 'irancell', 'rightel', 'shatel', 'asiatech', 'mokhaberat', 'tct', 'tic',
    'respina', 'afranet', 'parsonline', 'hiweb', 'fanava', 'datak', 'pishgaman',
    'arvan', 'derak', 'parspack', 'mobinnet', 'hamrah',
    'golgoli', 'cipservice', 'fast--pro', 'bastani', 'mikhay', 'goooal', 'soheil',
    'tunnel', 'khodam', 'poolaki', 'filter', 'pirooz', 'azadi'
  ];
  return irKeywords.some(kw => s.includes(kw));
}

// Strict IPv4 Prefix Check for known Iranian network blocks
function isIranianIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const irPrefixes = [
    '87.248.', '87.247.', '5.160.', '5.200.', '5.22.', '5.127.',
    '31.2.', '31.56.', '37.254.', '37.156.', '78.38.', '78.39.',
    '79.127.', '79.175.', '80.191.', '80.75.', '85.185.', '89.165.',
    '89.196.', '89.144.', '91.98.', '91.99.', '91.240.', '93.110.',
    '94.182.', '94.101.', '95.38.', '151.232.', '151.242.', '176.101.',
    '178.131.', '178.252.', '185.8.172.', '185.120.', '188.158.',
    '188.245.', '188.253.', '194.225.', '212.16.', '212.33.', '212.80.',
    '213.207.', '217.218.', '217.146.'
  ];
  return irPrefixes.some(prefix => ip.startsWith(prefix));
}

// Check telemetry metadata strings (Org, ISP, AS Name) for Iranian entities
function hasIranianTelemetry(str) {
  if (!str || typeof str !== 'string') return false;
  const s = str.toLowerCase();
  const irOrgKeywords = [
    'bidgoli', 'imani', 'aria', 'iran', 'tehran', 'mci', 'irancell', 'rightel',
    'shatel', 'asiatech', 'mokhaberat', 'respina', 'afranet', 'parsonline',
    'derak', 'arvan', 'parspack', 'mobinnet', 'hamrah', "tose'eh", 'ertebatat',
    'as201309', 'as58224', 'as197207', 'as44244', 'as202468', 'as31549',
    'as43754', 'as16322', 'as49666', 'as56402', 'as25184', 'as51074'
  ];
  return irOrgKeywords.some(kw => s.includes(kw));
}


async function loadSeenSet(kv) {
  try {
    const raw = await kv.get('mtp_seen_set');
    const obj = raw ? JSON.parse(raw) : {};
    const now = Date.now();
    for (const k of Object.keys(obj)) if (obj[k] < now) delete obj[k];
    return obj;
  } catch (_) { return {}; }
}

async function markSeen(kv, cacheKey, ttlSec) {
  const obj = await loadSeenSet(kv);
  obj[cacheKey] = Date.now() + (ttlSec || CONFIG.KV_TTL_SECONDS) * 1000;
  await kv.put('mtp_seen_set', JSON.stringify(obj));
}

// ---- "Winners" memory: proxies that recently passed the Iran check (re-tested first by the checker) ----
const WINNERS_KEY = 'mtp_winners';
const WINNERS_MAX = 60;
const WINNERS_MAX_AGE_MS = 7 * 24 * 3600 * 1000;

async function loadWinners(kv) {
  try {
    const raw = await kv.get(WINNERS_KEY);
    const obj = raw ? JSON.parse(raw) : {};
    const now = Date.now();
    for (const k of Object.keys(obj)) {
      if (!obj[k] || now - (obj[k].lastOk || 0) > WINNERS_MAX_AGE_MS) delete obj[k];
    }
    return obj;
  } catch (_) { return {}; }
}

async function saveWinners(kv, obj) {
  const keys = Object.keys(obj).sort((a, b) => (obj[b].lastOk || 0) - (obj[a].lastOk || 0)).slice(0, WINNERS_MAX);
  const out = {};
  for (const k of keys) out[k] = obj[k];
  await kv.put(WINNERS_KEY, JSON.stringify(out));
}

// Discover active Iranian nodes from Check-Host.net API (Tehran, Shiraz, Isfahan, Tabriz, Mashhad, Karaj)
async function getIranCheckHostNodes() {
  const defaultIrNodes = [
    'ir1.node.check-host.net',
    'ir2.node.check-host.net',
    'ir3.node.check-host.net',
    'ir4.node.check-host.net',
    'ir5.node.check-host.net',
    'ir6.node.check-host.net'
  ];

  const now = Date.now();
  if (MEMORY_STATE.iranNodesCache && (now - MEMORY_STATE.iranNodesCache.ts < 1800000)) {
    return MEMORY_STATE.iranNodesCache.nodes;
  }

  try {
    const res = await fetch('https://check-host.net/nodes/hosts', {
      headers: {
        'Accept': 'application/json'
      }
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.nodes && typeof data.nodes === 'object') {
        const discovered = Object.entries(data.nodes)
          .filter(([nodeKey, meta]) => {
            if (nodeKey.toLowerCase().startsWith('ir')) return true;
            if (meta && Array.isArray(meta.location) && String(meta.location[0]).toLowerCase() === 'ir') return true;
            return false;
          })
          .map(([nodeKey]) => nodeKey);

        if (discovered.length > 0) {
          MEMORY_STATE.iranNodesCache = { ts: now, nodes: discovered };
          return discovered;
        }
      }
    }
  } catch (_) {}

  return defaultIrNodes;
}

function sleepMs(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Test proxy host directly from Iranian Datacenters (Tehran, Shiraz, Isfahan, etc.) via Check-Host.net API
// Performs real ICMP Ping check (check-ping) from Iran nodes (4 packets per node, min/avg/max ms)
// and falls back to Iran TCP check (check-tcp) if a server drops ICMP echo requests but has its MTProto TCP port open in Iran.
async function verifyProxyViaCheckHostIran(host, port, addLog = null) {
  const irNodes = await getIranCheckHostNodes();
  const nodeQuery = irNodes.map(n => `node=${encodeURIComponent(n)}`).join('&');
  let lastError = null;
  // 1. Initiate Check-Host Ping from Iranian nodes
  const pingInitUrl = `https://check-host.net/check-ping?host=${encodeURIComponent(host)}&${nodeQuery}`;
  try {
    const initRes = await fetch(pingInitUrl, {
      headers: {
        'Accept': 'application/json'
      }
    });

    if (!initRes.ok) {
      lastError = `ping init HTTP ${initRes.status} ${(await initRes.text()).slice(0, 150)}`;
      if (addLog) addLog(`   │  │  ├─ ⚠️ Check-Host ${lastError}`);
    }

    if (initRes.ok) {
      const initData = await initRes.json();
      if (!initData || !initData.ok) {
        lastError = 'ping init: ' + JSON.stringify(initData).slice(0, 150);
        if (addLog) addLog(`   │  │  ├─ ⚠️ Check-Host ${lastError}`);
      }
      if (initData && initData.ok && initData.request_id) {
        const requestId = initData.request_id;
        const nodesMeta = initData.nodes || {};
        const activeNodeKeys = Object.keys(nodesMeta);
        const reportUrl = `https://check-host.net/check-ping?host=${encodeURIComponent(host)}`;

        if (addLog) {
          addLog(`   │  │  ├─ 🇮🇷 Check-Host Ping initiated on ${activeNodeKeys.length} Iran node(s) [ID: ${requestId}]`);
        }

        // Poll check-result/<request_id> (up to 3 polls so all 4 ICMP packets complete across Iranian DCs)
        let resultData = null;
        for (let attempt = 1; attempt <= 3; attempt++) {
          await sleepMs(attempt === 1 ? 2300 : 1600);
          const pollRes = await fetch(`https://check-host.net/check-result/${encodeURIComponent(requestId)}`, {
            headers: {
              'Accept': 'application/json'
            }
          });
          if (pollRes.ok) {
            resultData = await pollRes.json();
            if (resultData && typeof resultData === 'object') {
              const completedCount = activeNodeKeys.filter(k => resultData[k] !== null && resultData[k] !== undefined).length;
              if (completedCount >= Math.max(1, activeNodeKeys.length - 1)) {
                break;
              }
            }
          }
        }

        if (resultData && typeof resultData === 'object') {
          const iranNodeReports = [];
          const avgRtts = [];
          let resolvedIpFromIran = null;

          for (const nodeKey of activeNodeKeys) {
            const meta = nodesMeta[nodeKey] || ['ir', 'Iran', nodeKey.split('.')[0].toUpperCase()];
            const city = meta[2] || 'Iran';
            const locationLabel = `Iran, ${city}`;
            const rawNodeRes = resultData[nodeKey];

            // Format of check-ping result: [[ ["OK", 0.0792, "185.4.115.74"], ["OK", 0.0790], ["OK", 0.0793], ["OK", 0.0791] ]]
            if (Array.isArray(rawNodeRes) && Array.isArray(rawNodeRes[0])) {
              const packets = rawNodeRes[0];
              if (packets.length === 1 && packets[0] === null) {
                iranNodeReports.push({
                  node: nodeKey,
                  location: locationLabel,
                  ok: 0,
                  total: 4,
                  status: 'DNS/Unreachable'
                });
                if (addLog) {
                  addLog(`   │  │  ├─ 🔴 ${locationLabel} (${nodeKey.split('.')[0]}): 0/4 (Unreachable)`);
                }
                continue;
              }

              const okRttsMs = [];
              for (const pkt of packets) {
                if (Array.isArray(pkt)) {
                  if (pkt[2] && !resolvedIpFromIran) {
                    resolvedIpFromIran = String(pkt[2]);
                  }
                  if (pkt[0] === 'OK' && typeof pkt[1] === 'number') {
                    okRttsMs.push(pkt[1] * 1000);
                  }
                }
              }

              const totalPkts = packets.length || 4;
              const okCount = okRttsMs.length;

              if (okCount > 0) {
                const minMs = Math.min(...okRttsMs);
                const maxMs = Math.max(...okRttsMs);
                const avgMs = okRttsMs.reduce((a, b) => a + b, 0) / okCount;
                avgRtts.push(avgMs);

                const rttFormatted = `${minMs.toFixed(1)} / ${avgMs.toFixed(1)} / ${maxMs.toFixed(1)} ms`;
                iranNodeReports.push({
                  node: nodeKey,
                  location: locationLabel,
                  ok: okCount,
                  total: totalPkts,
                  min: Number(minMs.toFixed(1)),
                  avg: Number(avgMs.toFixed(1)),
                  max: Number(maxMs.toFixed(1)),
                  rttText: rttFormatted,
                  ip: resolvedIpFromIran || host
                });
                if (addLog) {
                  addLog(`   │  │  ├─ 🟢 ${locationLabel} | ${okCount}/${totalPkts} | ${rttFormatted} | ${resolvedIpFromIran || host}`);
                }
              } else {
                iranNodeReports.push({
                  node: nodeKey,
                  location: locationLabel,
                  ok: 0,
                  total: totalPkts,
                  rttText: 'Timeout',
                  ip: resolvedIpFromIran || host
                });
                if (addLog) {
                  addLog(`   │  │  ├─ 🔴 ${locationLabel} | 0/${totalPkts} | Timeout | ${resolvedIpFromIran || host}`);
                }
              }
            }
          }

          // Require at least 1 Iranian node (or >=2 if >=3 nodes tested) with healthy packet response (>=2/4 OK)
          const healthyNodes = iranNodeReports.filter(n => n.ok >= 2);
          const minRequiredNodes = activeNodeKeys.length >= 3 ? 2 : 1;

          if (healthyNodes.length >= minRequiredNodes && avgRtts.length > 0) {
            const overallAvgPing = Math.round(avgRtts.reduce((a, b) => a + b, 0) / avgRtts.length);
            const summaryStr = healthyNodes
              .map(n => `${n.location.replace('Iran, ', '')}: ${n.ok}/${n.total} (${n.avg}ms)`)
              .join(' | ');

            return {
              passed: true,
              method: 'check-ping',
              avgPing: overallAvgPing,
              resolvedIp: resolvedIpFromIran,
              nodes: iranNodeReports,
              healthyCount: healthyNodes.length,
              totalNodes: activeNodeKeys.length,
              summary: summaryStr,
              reportUrl: initData.permanent_link || reportUrl
            };
          }
        }
      }
    }
  } catch (err) {
    if (addLog) {
      addLog(`   │  │  ├─ ⚠️ Check-Host Ping error: ${err.message}`);
    }
  }

  // 2. Fallback: Check-Host TCP Connection from Iranian nodes (in case ICMP Ping is blocked by firewall on the proxy host, but TCP port is open from Iran)
  try {
    const tcpInitUrl = `https://check-host.net/check-tcp?host=${encodeURIComponent(host + ':' + port)}&${nodeQuery}`;
    const tcpInitRes = await fetch(tcpInitUrl, {
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (!tcpInitRes.ok) {
      lastError = `tcp init HTTP ${tcpInitRes.status} ${(await tcpInitRes.text()).slice(0, 150)}`;
      if (addLog) addLog(`   │  │  ├─ ⚠️ Check-Host ${lastError}`);
    }

    if (tcpInitRes.ok) {
      const tcpInitData = await tcpInitRes.json();
      if (tcpInitData && tcpInitData.ok && tcpInitData.request_id) {
        const reqId = tcpInitData.request_id;
        lastError = null; // init OK → result is conclusive
        const nodesMeta = tcpInitData.nodes || {};
        const activeNodeKeys = Object.keys(nodesMeta);

        await sleepMs(2200);
        const pollRes = await fetch(`https://check-host.net/check-result/${encodeURIComponent(reqId)}`, {
          headers: {
            'Accept': 'application/json'
          }
        });

        if (pollRes.ok) {
          const tcpResult = await pollRes.json();
          const iranNodeReports = [];
          const tcpTimesMs = [];
          let resolvedIp = null;

          for (const nodeKey of activeNodeKeys) {
            const meta = nodesMeta[nodeKey] || ['ir', 'Iran', nodeKey.split('.')[0].toUpperCase()];
            const city = meta[2] || 'Iran';
            const locationLabel = `Iran, ${city}`;
            const rawRes = tcpResult ? tcpResult[nodeKey] : null;

            if (Array.isArray(rawRes) && rawRes[0] && typeof rawRes[0].time === 'number') {
              const ms = Number((rawRes[0].time * 1000).toFixed(1));
              if (rawRes[0].address && !resolvedIp) resolvedIp = rawRes[0].address;
              tcpTimesMs.push(ms);
              iranNodeReports.push({
                node: nodeKey,
                location: locationLabel,
                ok: 4,
                total: 4,
                min: ms,
                avg: ms,
                max: ms,
                rttText: `${ms} ms (TCP)`,
                ip: resolvedIp || host
              });
              if (addLog) {
                addLog(`   │  │  ├─ 🟢 ${locationLabel} (TCP:${port}) | Connected in ${ms} ms | ${resolvedIp || host}`);
              }
            }
          }

          const minRequired = activeNodeKeys.length >= 3 ? 2 : 1;
          if (tcpTimesMs.length >= minRequired) {
            const avgPing = Math.round(tcpTimesMs.reduce((a, b) => a + b, 0) / tcpTimesMs.length);
            const summaryStr = iranNodeReports
              .map(n => `${n.location.replace('Iran, ', '')}: ${n.avg}ms (TCP)`)
              .join(' | ');
            return {
              passed: true,
              method: 'check-tcp',
              avgPing,
              resolvedIp,
              nodes: iranNodeReports,
              healthyCount: tcpTimesMs.length,
              totalNodes: activeNodeKeys.length,
              summary: summaryStr,
              reportUrl: tcpInitData.permanent_link || `https://check-host.net/check-tcp?host=${encodeURIComponent(host + ':' + port)}`
            };
          }
        }
      }
    }
  } catch (err) {
    lastError = 'tcp error: ' + err.message;
  }

  return { passed: false, inconclusive: !!lastError, reason: lastError };
}

async function findBestForeignProxy(candidates, addLog = null) {
  if (!candidates || candidates.length === 0) return null;

  const standardPorts = [443, 8443, 2053, 2083, 80, 2096, 543];

  // 1. Filter out obvious Iranian domestic tunnels/hosts first
  const nonIrCandidates = candidates.filter(c => !isLikelyIranian(c.server));
  const removedIrCount = candidates.length - nonIrCandidates.length;
  if (removedIrCount > 0 && addLog) {
    addLog(`   │  ├─ Domestic Filter: Excluded ${removedIrCount} Iranian tunnel(s) -> ${nonIrCandidates.length} foreign candidate(s)`);
  }
  const workingPool = nonIrCandidates.length > 0 ? nonIrCandidates : candidates;

  // 2. Prefer Fake-TLS (ee...) and Padded (dd...) secrets over raw 32-hex secrets (which get DPI-blocked in Iran)
  const fakeTlsCandidates = workingPool.filter(c => {
    const s = String(c.secret || '').toLowerCase();
    return s.startsWith('ee') || s.startsWith('dd') || !/^[0-9a-f]{32}$/.test(s);
  });
  const secretFilteredPool = fakeTlsCandidates.length > 0 ? fakeTlsCandidates : workingPool;
  const stdCandidates = secretFilteredPool.filter(c => standardPorts.includes(c.port));
  const pool = stdCandidates.length > 0 ? stdCandidates : secretFilteredPool;

  // 3. Take a randomized sample across the list so we don't pick the exact same proxies every run
  const shuffledPool = [...pool].sort(() => Math.random() - 0.5);
  const probePool = shuffledPool.slice(0, Math.min(shuffledPool.length, 12));
  if (addLog) {
    addLog(`   │  ├─ Sampling Pool: ${probePool.length} distributed proxies selected for TCP pre-filter & Check-Host Iran test`);
  }

  // 4. Fast Edge TCP Socket Pre-Filter (so we only call Check-Host Iran API on live, open MTProto ports)
  const batchSize = 6;
  const liveSocketResults = [];

  for (let i = 0; i < probePool.length; i += batchSize) {
    const batch = probePool.slice(i, i + batchSize);
    if (addLog) {
      addLog(`   │  ├─ Pre-filtering TCP batch ${Math.floor(i / batchSize) + 1} (${batch.length} sockets)...`);
    }
    const promises = batch.map(async (candidate) => {
      const ping = await testTcpSocketLatency(candidate.server, candidate.port, 2000, candidate.secret);
      return { candidate, ping };
    });

    const results = await Promise.allSettled(promises);
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value.ping !== null) {
        liveSocketResults.push(r.value);
        if (addLog) {
          addLog(`   │  │  ├─ 🟢 Edge Socket Open: ${r.value.candidate.server}:${r.value.candidate.port} (${r.value.ping}ms)`);
        }
      } else {
        if (addLog) {
          const item = r.status === 'fulfilled' ? r.value.candidate : batch[0];
          addLog(`   │  │  ├─ 🔴 Edge Socket Closed: ${item.server}:${item.port}`);
        }
      }
    }

    if (liveSocketResults.length >= 4) break;
  }

  // Combine live edge candidates first, plus up to 2 fallback candidates in case edge socket was blocked
  const orderedToVerify = [
    ...liveSocketResults.sort((a, b) => a.ping - b.ping).map(x => ({ candidate: x.candidate, edgePing: x.ping })),
    ...probePool.slice(0, 3).map(c => ({ candidate: c, edgePing: null }))
  ];

  // Deduplicate orderedToVerify
  const seenVerify = new Set();
  const uniqueVerifyList = [];
  for (const item of orderedToVerify) {
    const k = `${item.candidate.server}:${item.candidate.port}`;
    if (!seenVerify.has(k)) {
      seenVerify.add(k);
      uniqueVerifyList.push(item);
    }
  }

  // 5. Verify Foreign GeoIP AND test real reachability/ping from Iran Datacenters via Check-Host.net!
  const maxCheckHostAttempts = Math.min(uniqueVerifyList.length, 2);
  for (let idx = 0; idx < maxCheckHostAttempts; idx++) {
    const { candidate, edgePing } = uniqueVerifyList[idx];
    const geo = await resolveGeoIp(candidate.server);

    if (!geo || geo.country_code === 'IR') {
      if (addLog) {
        addLog(`   │  ├─ ❌ Excluded Domestic Host: ${candidate.server}:${candidate.port} geolocated to Iran (IR)`);
      }
      continue;
    }

    if (addLog) {
      addLog(`   │  ├─ 🌍 Foreign Host Confirmed: ${candidate.server} -> ${geo.city ? geo.city + ', ' : ''}${geo.country} ${geo.flag}`);
      addLog(`   │  ├─ 📡 Testing real Iran ping via Check-Host.net (Isfahan, Shiraz, Tehran)...`);
    }

    const iranCheck = await verifyProxyViaCheckHostIran(candidate.server, candidate.port, addLog);

    if (iranCheck && iranCheck.inconclusive) {
      if (addLog) addLog(`   │  └─ ⚠️ Check-Host unavailable (${iranCheck.reason}) — skipped, not a proxy failure`);
      continue;
    }

    if (iranCheck && iranCheck.passed) {
      // Double-check if Check-Host resolved the domain to an Iranian IP inside Iran (split-horizon DNS protection!)
      if (iranCheck.resolvedIp && isIranianIp(iranCheck.resolvedIp)) {
        if (addLog) {
          addLog(`   │  └─ ❌ Split-DNS Leak Blocked: ${candidate.server} resolved to Iranian IP ${iranCheck.resolvedIp} inside Iran!`);
        }
        continue;
      }

      if (addLog) {
        addLog(`   │  ├─ ✅ Check-Host Iran PASSED (${iranCheck.healthyCount}/${iranCheck.totalNodes} Iran nodes OK): ${iranCheck.summary}`);
        addLog(`   │  └─ ⚡️ Real Iran Average Ping: ${iranCheck.avgPing}ms | Report: ${iranCheck.reportUrl}`);
      }

      return {
        ...candidate,
        geo,
        edgePing,
        iranPing: iranCheck.avgPing,
        iranNodes: iranCheck.nodes || [],
        checkHostSummary: iranCheck.summary,
        checkHostReportUrl: iranCheck.reportUrl
      };
    } else {
      if (addLog) {
        addLog(`   │  └─ ❌ Filtered in Iran: ${candidate.server}:${candidate.port} failed Check-Host Iran datacenter ping/TCP test`);
      }
    }
  }

  return null;
}

async function testTcpSocketLatency(hostname, port, timeoutMs = 2000, secret = '') {
  const startTime = Date.now();
  let socketInstance;

  try {
    // Reject plain raw 32-hex secrets on port 443 where DPI in Iran blocks them after TCP handshake
    const cleanSec = String(secret || '').trim().toLowerCase();
    if (cleanSec.length === 32 && /^[0-9a-f]{32}$/.test(cleanSec) && (port === 443 || port === 8443)) {
      return null;
    }

    socketInstance = connect({ hostname, port });
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('timeout')), timeoutMs);
    });

    const connectPromise = (socketInstance && socketInstance.opened)
      ? socketInstance.opened.then(() => Date.now() - startTime)
      : Promise.resolve(Date.now() - startTime);

    const latency = await Promise.race([connectPromise, timeoutPromise]);
    return typeof latency === 'number' ? latency : (Date.now() - startTime);
  } catch (e) {
    return null;
  } finally {
    try {
      if (socketInstance && typeof socketInstance['close'] === 'function') {
        socketInstance['close']();
      }
    } catch (_) {}
  }
}

// Multi-Tier GeoIP Resolver with Strict Iranian Subnet & ASN Cross-Verification
async function resolveGeoIp(host) {
  let targetIp = host;
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);

  // 1. If host is a domain, resolve to real IP via Cloudflare DoH first
  if (!isIp) {
    try {
      const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
        headers: { "Accept": "application/dns-json" }
      });
      if (dohRes.ok) {
        const dohData = await dohRes.json();
        if (dohData.Answer && Array.isArray(dohData.Answer)) {
          const aRec = dohData.Answer.slice().reverse().find(a => a.type === 1 && /^(\d{1,3}\.){3}\d{1,3}$/.test(a.data));
          if (aRec && aRec.data) {
            targetIp = aRec.data;
          }
        }
      }
    } catch (_) {}
  }

  // 1.5 Immediate Iranian IPv4 Prefix Filter
  if (isIranianIp(targetIp)) {
    return {
      ip: targetIp,
      country: 'Iran',
      country_code: 'IR',
      city: 'Tehran',
      flag: '🇮🇷',
      org: 'Iranian Subnet Detected'
    };
  }

  // 2. Primary: ip-api.com (includes ISP, Org, AS, and high accuracy for Iranian subnets)
  try {
    const resIpApi = await fetch(`http://ip-api.com/json/${encodeURIComponent(targetIp)}?fields=status,country,countryCode,city,isp,org,as`);
    if (resIpApi.ok) {
      const d = await resIpApi.json();
      if (d && d.status === 'success') {
        const fullTelemetry = `${d.country} ${d.countryCode} ${d.isp} ${d.org} ${d.as}`;
        if (d.countryCode === 'IR' || hasIranianTelemetry(fullTelemetry)) {
          return {
            ip: targetIp,
            country: 'Iran',
            country_code: 'IR',
            city: d.city || 'Tehran',
            flag: '🇮🇷',
            org: d.org || d.isp || 'Iranian Network'
          };
        }
        return {
          ip: targetIp,
          country: d.country || 'Unknown',
          country_code: d.countryCode,
          city: d.city || '',
          flag: getCountryFlag(d.countryCode),
          org: d.org || d.isp || ''
        };
      }
    }
  } catch (_) {}

  // 3. Secondary: DB-IP (Engine powering Check-Host.net primary location)
  try {
    const resDbIp = await fetch(`https://api.db-ip.com/v2/free/${encodeURIComponent(targetIp)}`);
    if (resDbIp.ok) {
      const d = await resDbIp.json();
      if (d && d.countryCode && d.countryCode !== 'ZZ' && d.countryCode !== 'XX') {
        const fullTelemetry = `${d.countryName} ${d.countryCode} ${d.city}`;
        if (d.countryCode === 'IR' || hasIranianTelemetry(fullTelemetry)) {
          return {
            ip: targetIp,
            country: 'Iran',
            country_code: 'IR',
            city: d.city || 'Tehran',
            flag: '🇮🇷',
            org: 'DB-IP Flagged IR'
          };
        }
        return {
          ip: targetIp,
          country: d.countryName || 'Unknown',
          country_code: d.countryCode,
          city: d.city || '',
          flag: getCountryFlag(d.countryCode)
        };
      }
    }
  } catch (_) {}

  // 4. Tertiary: ipwho.is (Returns exact City, Country, Flag, Connection ASN over HTTPS)
  try {
    const res1 = await fetch(`https://ipwho.is/${encodeURIComponent(targetIp)}`);
    if (res1.ok) {
      const d1 = await res1.json();
      if (d1 && d1.success && d1.country_code) {
        const conn = d1.connection || {};
        const fullTelemetry = `${d1.country} ${d1.country_code} ${conn.org} ${conn.isp} ${conn.asn}`;
        if (d1.country_code === 'IR' || hasIranianTelemetry(fullTelemetry)) {
          return {
            ip: targetIp,
            country: 'Iran',
            country_code: 'IR',
            city: d1.city || 'Tehran',
            flag: '🇮🇷',
            org: conn.org || conn.isp || 'ipwho.is Flagged IR'
          };
        }
        return {
          ip: targetIp,
          country: d1.country || 'Unknown',
          country_code: d1.country_code || 'UN',
          city: d1.city || '',
          flag: d1.flag?.emoji || getCountryFlag(d1.country_code),
          org: conn.org || conn.isp || ''
        };
      }
    }
  } catch (_) {}

  // 5. Quaternary: ipinfo.io (Always inspect org for Iranian ASNs like AS201309)
  try {
    const res2 = await fetch(`https://ipinfo.io/${encodeURIComponent(targetIp)}/json`);
    if (res2.ok) {
      const d2 = await res2.json();
      if (d2 && d2.country) {
        const fullTelemetry = `${d2.country} ${d2.org} ${d2.city}`;
        if (d2.country === 'IR' || hasIranianTelemetry(fullTelemetry)) {
          return {
            ip: targetIp,
            country: 'Iran',
            country_code: 'IR',
            city: d2.city || 'Tehran',
            flag: '🇮🇷',
            org: d2.org || 'ipinfo.io Flagged IR'
          };
        }
        let countryName = d2.country;
        try {
          countryName = new Intl.DisplayNames(['en'], { type: 'region' }).of(d2.country) || d2.country;
        } catch (_) {}
        return {
          ip: targetIp,
          country: countryName,
          country_code: d2.country,
          city: d2.city || '',
          flag: getCountryFlag(d2.country),
          org: d2.org || ''
        };
      }
    }
  } catch (_) {}

  // 6. Quinary: freeipapi.com
  try {
    const res3 = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(targetIp)}`);
    if (res3.ok) {
      const d3 = await res3.json();
      if (d3 && d3.countryCode) {
        if (d3.countryCode === 'IR') {
          return {
            ip: targetIp,
            country: 'Iran',
            country_code: 'IR',
            city: d3.cityName || 'Tehran',
            flag: '🇮🇷',
            org: 'freeipapi Flagged IR'
          };
        }
        return {
          ip: targetIp,
          country: d3.countryName || 'Unknown',
          country_code: d3.countryCode || 'UN',
          city: d3.cityName || '',
          flag: getCountryFlag(d3.countryCode)
        };
      }
    }
  } catch (_) {}

  // 7. Senary: api.country.is with dynamic Intl country names
  try {
    const res4 = await fetch(`https://api.country.is/${encodeURIComponent(targetIp)}`);
    if (res4.ok) {
      const d4 = await res4.json();
      if (d4 && d4.country) {
        if (d4.country === 'IR') {
          return {
            ip: targetIp,
            country: 'Iran',
            country_code: 'IR',
            city: 'Tehran',
            flag: '🇮🇷',
            org: 'country.is Flagged IR'
          };
        }
        let countryName = d4.country;
        try {
          countryName = new Intl.DisplayNames(['en'], { type: 'region' }).of(d4.country) || d4.country;
        } catch (_) {}
        const defaultCities = {
          DE: 'Frankfurt', FI: 'Helsinki', NL: 'Amsterdam', FR: 'Paris',
          GB: 'London', US: 'New York', SE: 'Stockholm', PL: 'Warsaw'
        };
        return {
          ip: targetIp,
          country: countryName,
          country_code: d4.country,
          city: defaultCities[d4.country] || '',
          flag: getCountryFlag(d4.country)
        };
      }
    }
  } catch (_) {}

  return {
    ip: targetIp,
    country: 'International',
    country_code: 'INT',
    city: '',
    flag: '🌐'
  };
}

function getPingStatusEmoji(ping) {
  if (ping <= 350) return '🟢';
  if (ping <= 1000) return '🟡';
  return '🔴';
}

function getCountryFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function renderMessageFromTemplate(proxy, templateConfig) {
  const now = new Date();
  const unixTime = Math.floor(now.getTime() / 1000);
  const timeStr = now.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'Asia/Tehran'
  });

  const city = proxy.geo.city || '';
  const country = proxy.geo.country || 'Unknown';
  const flag = proxy.geo.flag || '🌐';
  const locationText = `${city ? city + ', ' : ''}${country} ${flag}`;
  const statusDot = getPingStatusEmoji(proxy.iranPing);
  const signature = templateConfig.signature || CONFIG.CHANNEL_SIGNATURE;
  const tgTimeTag = `<tg-time unix="${unixTime}" format="r">${timeStr}</tg-time>`;

  const rawTemplate = templateConfig.messageTemplate || CONFIG.DEFAULT_TEMPLATE.messageTemplate;

  return rawTemplate
    .replace(/\{location\}/g, locationText)
    .replace(/\{country\}/g, country)
    .replace(/\{city\}/g, city || country)
    .replace(/\{flag\}/g, flag)
    .replace(/\{ping\}/g, String(proxy.iranPing))
    .replace(/\{status_dot\}/g, statusDot)
    .replace(/\{unix\}/g, String(unixTime))
    .replace(/\{time\}/g, timeStr)
    .replace(/\{tg_time\}/g, tgTimeTag)
    .replace(/\{server\}/g, proxy.server)
    .replace(/\{port\}/g, String(proxy.port))
    .replace(/\{source\}/g, proxy.source || 'Pipeline')
    .replace(/\{url\}/g, proxy.rawUrl)
    .replace(/\{iran_report\}/g, proxy.checkHostSummary || `${proxy.iranPing}ms (Iran DCs)`)
    .replace(/\{check_host_url\}/g, proxy.checkHostReportUrl || `https://check-host.net/check-ping?host=${encodeURIComponent(proxy.server)}`)
    .replace(/\{signature\}/g, signature)
    .replace(/\{separator\}/g, '━━━━━━━━━━━━━━━━━━');
}

async function postToTelegram(proxy, templateConfig = CONFIG.DEFAULT_TEMPLATE) {
  const messageText = renderMessageFromTemplate(proxy, templateConfig);
  const buttonText = (templateConfig.buttonText || CONFIG.DEFAULT_TEMPLATE.buttonText)
    .replace(/\{flag\}/g, proxy.geo.flag || '🚀')
    .replace(/\{country\}/g, proxy.geo.country || '')
    .replace(/\{ping\}/g, String(proxy.iranPing));

  const inlineKeyboard = [
    [
      {
        text: buttonText,
        url: proxy.rawUrl
      }
    ]
  ];

  if (templateConfig.secondButtonEnabled && templateConfig.secondButtonText && templateConfig.secondButtonUrl) {
    inlineKeyboard.push([
      {
        text: templateConfig.secondButtonText,
        url: templateConfig.secondButtonUrl
      }
    ]);
  }

  const payload = {
    chat_id: CONFIG.CHANNEL_ID,
    text: messageText,
    parse_mode: 'HTML',
    disable_web_page_preview: templateConfig.disableWebPagePreview !== false,
    reply_markup: {
      inline_keyboard: inlineKeyboard
    }
  };

  const tgUrl = `https://api.telegram.org/bot${CONFIG.BOT_TOKEN}/sendMessage`;
  const res = await fetch(tgUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  return await res.json();
}


function renderDashboardHtml() {
  return `<!DOCTYPE html>
<html lang="en" dir="ltr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MST PROXY | Telegram Studio Management Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            appBg: '#090D16',
            appSurface: '#0F172A',
            appCard: '#131D31',
            appBorder: '#1E293B',
            tgBlue: '#0EA5E9',
            tgBlueHover: '#0284C7',
            tgBubble: '#142033',
            tgBubbleBorder: '#1E2E48',
            accentGreen: '#10B981',
            accentCyan: '#38BDF8',
            textMuted: '#94A3B8'
          },
          fontFamily: {
            sans: ['Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif],
            mono: ['JetBrains Mono', 'monospace']
          }
        }
      }
    };
  </script>
  <style>
    body {
      font-family: 'Inter', sans-serif;
      background-color: #090D16;
      color: #F8FAFC;
      background-image:
        radial-gradient(circle at 15% 10%, rgba(14, 165, 233, 0.08) 0px, transparent 45%),
        radial-gradient(circle at 85% 90%, rgba(16, 185, 129, 0.06) 0px, transparent 50%);
      background-attachment: fixed;
    }
    .panel-box {
      background-color: #0F172A;
      border: 1px solid #1E293B;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.45);
    }
    .chat-stage-bg {
      background-color: #090D16;
      background-image: radial-gradient(rgba(14, 165, 233, 0.06) 1px, transparent 1px);
      background-size: 22px 22px;
    }
    .post-bubble {
      background-color: #142033;
      border: 1px solid #1E2E48;
      border-radius: 18px 18px 18px 4px;
      box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.4);
    }
    .btn-connect-hero {
      background: linear-gradient(135deg, #0284C7 0%, #0EA5E9 50%, #38BDF8 100%);
      color: #FFFFFF;
      font-weight: 800;
      letter-spacing: 0.04em;
      transition: all 0.2s ease;
      box-shadow: 0 4px 20px -2px rgba(14, 165, 233, 0.45);
    }
    .btn-connect-hero:hover {
      filter: brightness(1.12);
      transform: translateY(-1px);
      box-shadow: 0 6px 26px -2px rgba(14, 165, 233, 0.6);
    }
    .btn-connect-hero:active {
      transform: translateY(0);
    }
    .btn-action-dark {
      background-color: #131D31;
      border: 1px solid #1E293B;
      color: #F8FAFC;
      transition: all 0.15s ease;
    }
    .btn-action-dark:hover {
      background-color: #1A2844;
      border-color: #0EA5E9;
      color: #38BDF8;
    }
    .btn-pill-green {
      background: #10B981;
      color: #090D16;
      font-weight: 800;
    }
    .source-item {
      background-color: #0F172A;
      border: 1px solid #1E293B;
      transition: all 0.18s ease;
    }
    .source-item:hover {
      border-color: rgba(56, 189, 248, 0.4);
    }
    .source-item-priority1 {
      border: 1px solid rgba(16, 185, 129, 0.45);
      background: linear-gradient(90deg, rgba(16, 185, 129, 0.08) 0%, #0F172A 70%);
      box-shadow: 0 4px 20px -3px rgba(16, 185, 129, 0.15);
    }
    .source-item.dragging {
      opacity: 0.4;
      border: 1px dashed #38BDF8;
    }
    .source-item.drag-over {
      border-color: #10B981;
      background-color: rgba(16, 185, 129, 0.12);
      transform: translateY(-2px);
    }
    .ios-switch {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
    }
    .ios-switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }
    .ios-slider {
      position: absolute;
      cursor: pointer;
      top: 0; left: 0; right: 0; bottom: 0;
      background-color: #1E293B;
      transition: .22s;
      border-radius: 24px;
      border: 1px solid #334155;
    }
    .ios-slider:before {
      position: absolute;
      content: "";
      height: 18px;
      width: 18px;
      left: 2px;
      bottom: 2px;
      background-color: white;
      transition: .22s;
      border-radius: 50%;
      box-shadow: 0 1px 3px rgba(0,0,0,0.4);
    }
    input:checked + .ios-slider {
      background-color: #10B981;
      border-color: #059669;
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.4);
    }
    input:checked + .ios-slider:before {
      transform: translateX(20px);
    }
    .chip-token {
      background-color: #090D16;
      border: 1px solid #1E293B;
      transition: all 0.15s ease;
    }
    .chip-token:hover {
      background-color: #131D31;
      border-color: #38BDF8;
    }
    .custom-scroll::-webkit-scrollbar { width: 6px; height: 6px; }
    .custom-scroll::-webkit-scrollbar-track { background: #090D16; }
    .custom-scroll::-webkit-scrollbar-thumb { background: #1E293B; border-radius: 4px; }
    .custom-scroll::-webkit-scrollbar-thumb:hover { background: #0EA5E9; }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between selection:bg-[#0EA5E9] selection:text-white">

  <!-- TOP HEADER BAR: Telegram Utility Studio Header -->
  <header class="panel-box sticky top-0 z-40 px-4 sm:px-6 py-3 border-b border-[#1E293B]">
    <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3">

      <!-- Left: Channel Logo & Identity -->
      <div class="flex items-center gap-3">
        <div id="channelAvatarContainer" class="w-10 h-10 rounded-full bg-gradient-to-tr from-[#0284C7] to-[#38BDF8] flex items-center justify-center text-white font-black text-lg shadow-md shadow-sky-500/20 shrink-0 overflow-hidden border border-[#38BDF8]/40">
          <span id="channelAvatarFallback">M</span>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h1 id="channelTitleHeader" class="text-base font-black text-white tracking-tight font-mono">MST PROXY</h1>
            <span class="inline-flex items-center justify-center w-4 h-4 rounded-full bg-[#0EA5E9] text-white text-[10px]" title="Verified Channel Bot">✓</span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#131D31] text-[#38BDF8] border border-[#38BDF8]/30">Telegram Utility 3.2</span>
          </div>
          <p class="text-[11px] text-[#94A3B8]">channel &bull; <span id="channelSubscribersCount" class="text-slate-200 font-semibold">Loading subscribers...</span> &bull; Automated MTProto Publisher</p>
        </div>
      </div>

      <!-- Center: Real-Time Tehran Clock & Live Cron Countdown Pill -->
      <div class="flex items-center gap-2.5 bg-[#090D16] px-4 py-1.5 rounded-full border border-[#1E293B] text-xs">
        <div class="flex items-center gap-1.5 text-slate-300 font-mono">
          <span class="text-sm">🇮🇷</span>
          <span id="liveTehranClock" class="font-bold text-white text-xs sm:text-sm">--:--:--</span>
        </div>
        <span class="text-[#334155]">|</span>
        <div class="flex items-center gap-1.5 font-mono text-[11px]">
          <span class="text-[#94A3B8]">Next Cron:</span>
          <span id="nextCronTargetTime" class="text-[#38BDF8] font-bold">--:-- IRST</span>
          <span class="text-slate-400">(in <b id="cronCountdownDisplay" class="text-white">--:--</b>)</span>
        </div>
        <div class="w-14 bg-[#1E293B] rounded-full h-1.5 overflow-hidden ml-1 hidden sm:block">
          <div id="cronProgressBar" class="bg-[#0EA5E9] h-1.5 rounded-full transition-all duration-1000" style="width: 50%"></div>
        </div>
      </div>

      <!-- Right: Channel Shortcut & Quick Dispatch -->
      <div class="flex items-center gap-2.5">
        <a href="https://t.me/MSTProxy" target="_blank" rel="noopener noreferrer" class="btn-action-dark flex items-center gap-1.5 text-xs font-semibold px-3.5 py-2 rounded-xl text-[#38BDF8]">
          <span>✓</span>
          <span>@MSTProxy</span>
        </a>
        <button id="sendBtnTop" onclick="triggerManualSend(false)" class="btn-action-dark hover:border-[#10B981] hover:text-[#10B981] px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-sm transition">
          <span class="text-[#10B981]">⚡️</span>
          <span>Dispatch Now</span>
        </button>
      </div>

    </div>
  </header>

  <!-- MAIN BODY: 2-Column Studio Layout -->
  <main class="max-w-7xl mx-auto w-full p-3 sm:p-5 lg:p-6 flex-1 flex flex-col gap-5">

    <div class="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">

      <!-- LEFT COLUMN: Scraping Sources Pipeline Sidebar (5 cols) -->
      <div class="lg:col-span-5 flex flex-col gap-4">

        <!-- Sources Header Box -->
        <div class="panel-box p-4 rounded-2xl flex flex-col gap-3">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-base text-[#38BDF8]">🌐</span>
              <h2 class="text-sm font-bold text-white uppercase tracking-wider font-mono">SOURCES PIPELINE</h2>
            </div>
            <span id="statActiveSources" class="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-[#131D31] text-[#38BDF8] border border-[#38BDF8]/30">3 / 4 Active</span>
          </div>
          <p class="text-xs text-[#94A3B8] leading-relaxed">
            Drag cards to reorder priority, <strong class="text-white">#1 checked first</strong>. Zero Iranian domestic proxies leak into the channel.
          </p>

          <!-- Add Source Input -->
          <div class="flex flex-col gap-2 pt-2 border-t border-[#1E293B]">
            <input id="newSrcName" type="text" placeholder="Source Display Name (e.g. Channel)" class="bg-[#090D16] border border-[#1E293B] rounded-xl px-3.5 py-2 text-xs text-white focus:outline-none focus:border-[#0EA5E9]">
            <div class="flex items-center gap-2">
              <input id="newSrcUrl" type="text" placeholder="https://t.me/s/... or raw RRL" class="bg-[#090D16] border border-[#1E293B] flex-1 rounded-xl px-3.5 py-2 text-xs font-mono text-[#38BDF8] focus:outline-none focus:border-[#0EA5E9]">
              <button onclick="addNewSource()" class="btn-action-dark px-3.5 py-2 rounded-xl text-xs font-bold shrink-0 text-[#38BDF8]">
                + Add
              </button>
            </div>
          </div>
        </div>

        <!-- Sources Cards List -->
        <div id="sourcesList" class="flex flex-col gap-2.5"></div>

        <!-- Save Sources Order Action -->
        <button id="saveSourcesBtn" onclick="saveSourcesConfiguration()" class="btn-action-dark w-full py-3 px-4 rounded-xl text-xs font-bold flex items-center justify-center gap-2 font-mono">
          <span id="saveIcon">💾</span>
          <span id="saveText">Save Pipeline Order to KV</span>
        </button>

        <!-- System, Check-Host Iran & Pre-Stage Queue Telemetry Badges -->
        <div class="panel-box p-3.5 rounded-xl text-[11px] font-mono text-[#94A3B8] flex flex-col gap-2 border border-[#1E293B]">
          <div class="flex items-center justify-between">
            <span>Iran Verification:</span>
            <span class="text-[#10B981] font-bold flex items-center gap-1.5"><span class="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></span> Check-Host.net (IR DCs)</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Anti-Leak IR Filter:</span>
            <span class="text-[#10B981] font-bold">Strict CIDR + Split-DNS</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Storage State:</span>
            <span id="statKvStatus" class="text-[#38BDF8] font-bold">KV (PROXIES_KV)</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Staged for :00 Cron:</span>
            <span id="statStagedProxy" class="text-amber-400 font-bold truncate max-w-[180px]">None (Waiting for :55)</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Last Dispatched:</span>
            <span id="statLastProxy" class="text-white truncate max-w-[180px]">—</span>
          </div>
        </div>

        <!-- Check-Host.net Iran Datacenter Live Results Card -->
        <div class="panel-box p-4 rounded-2xl flex flex-col gap-2.5 border border-[#1E293B]">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-sm">🇮🇷</span>
              <h3 class="text-xs font-bold text-white font-mono uppercase tracking-wider">CHECK-HOST.NET IRAN PING</h3>
            </div>
            <a id="checkHostExternalLink" href="https://check-host.net" target="_blank" rel="noopener noreferrer" class="text-[10px] font-mono text-[#38BDF8] hover:underline">check-host.net ↗</a>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-[11px] font-mono">
              <thead>
                <tr class="text-[#94A3B8] border-b border-[#1E293B]">
                  <th class="py-1.5">Location</th>
                  <th class="py-1.5">Result</th>
                  <th class="py-1.5">rtt min / avg / max</th>
                  <th class="py-1.5">IP</th>
                </tr>
              </thead>
              <tbody id="checkHostIranTableBody" class="divide-y divide-[#1E293B]/60 text-slate-200">
                <tr>
                  <td colspan="4" class="py-3 text-center text-[#94A3B8]">Run "Pre-Test &amp; Stage (:55)" or "Dispatch" to view real Iran DC pings (Isfahan, Shiraz, Tehran)</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </div>

      <!-- CENTER / RIGHT: Telegram Channel Post Preview & Telemetry (7 cols) -->
      <div class="lg:col-span-7 flex flex-col gap-4">

        <!-- Telegram Chat Stage Window -->
        <div class="chat-stage-bg p-4 sm:p-6 rounded-2xl border border-[#1E293B] flex flex-col gap-4 shadow-xl">

          <!-- Date Badge inside Telegram Chat -->
          <div class="flex justify-center">
            <span class="bg-[#131D31]/90 text-[#94A3B8] text-[11px] font-semibold px-3 py-1 rounded-full border border-[#1E293B]">
              Today, Channel Post Preview
            </span>
          </div>

          <!-- The Telegram Channel Post Bubble (Exact Replica) -->
          <div class="max-w-lg mx-auto w-full flex flex-col gap-2.5">

            <div class="post-bubble p-4 sm:p-5 text-slate-100 text-[13px] sm:text-sm leading-relaxed">
              <!-- Header inside bubble -->
              <div class="flex items-center justify-between mb-2.5 pb-2 border-b border-[#1E2E48]">
                <div class="flex items-center gap-2">
                  <div id="postBubbleAvatarContainer" class="w-5 h-5 rounded-full bg-gradient-to-tr from-[#0284C7] to-[#38BDF8] flex items-center justify-center text-white font-bold text-[9px] shrink-0 overflow-hidden border border-[#0EA5E9]/40">
                    <span>M</span>
                  </div>
                  <span id="postBubbleTitle" class="text-[#0EA5E9] font-bold text-xs sm:text-sm">MST PROXY</span>
                  <span class="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full bg-[#0EA5E9] text-white text-[9px]">✓</span>
                  <span class="text-[10px] text-slate-300 px-1.5 py-0.5 rounded bg-[#1E2E48]">channel</span>
                </div>
                <span class="text-[10px] font-mono text-[#94A3B8]">Bot Message</span>
              </div>

              <!-- Body with HTML formatted text -->
              <div id="liveTelegramPreviewText" class="whitespace-pre-wrap break-words"></div>

              <!-- Footer with views and time -->
              <div class="mt-3 flex items-center justify-end gap-1.5 text-[10px] text-[#94A3B8] font-mono">
                <span>👁 2.1K</span>
                <span>&bull;</span>
                <span id="previewBubbleTime">17:41</span>
                <span class="text-[#0EA5E9] font-bold">✓✓</span>
              </div>
            </div>

            <!-- Big Bold Glowing Connect Button -->
            <div id="liveTelegramPreviewButtons" class="flex flex-col gap-2"></div>

            <!-- Dispatch & 5-Min Pre-Stage Controls below Preview -->
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
              <button id="sendBtn" onclick="triggerManualSend(false, 'immediate')" class="btn-action-dark py-3 px-3 rounded-xl text-xs font-bold flex items-center justify-center gap-1.5 text-[#38BDF8] hover:border-[#0EA5E9]">
                <span id="sendIcon">✈️</span>
                <span id="sendText">Test &amp; Dispatch Now</span>
              </button>
              <button id="stageBtn" onclick="triggerManualSend(false, 'prepare')" class="btn-action-dark py-3 px-3 rounded-xl text-xs font-bold flex items-center justify-center gap-1.5 text-[#10B981] hover:border-[#10B981]" title="Test via Check-Host Iran now & queue in KV for instant :00 publish">
                <span id="stageIcon">🕒</span>
                <span id="stageText">Pre-Test &amp; Stage (:55)</span>
              </button>
              <button onclick="triggerManualSend(true, 'immediate')" class="btn-action-dark py-3 px-3 rounded-xl text-xs font-bold flex items-center justify-center gap-1.5 hover:border-amber-500 hover:text-amber-400" title="Bypass recent duplicate check in KV">
                <span>🔥</span>
                <span>Force Skip Cache</span>
              </button>
            </div>

          </div>

        </div>

        <!-- Post Layout Customizer (Expandable Studio) -->
        <div class="panel-box p-4 rounded-2xl flex flex-col gap-3">
          <div class="flex items-center justify-between cursor-pointer" onclick="toggleStudioDrawer()">
            <div class="flex items-center gap-2">
              <span class="text-sm">🎨</span>
              <h3 class="text-xs font-bold uppercase tracking-wider text-white font-mono">CUSTOMIZE POST LAYOUT &amp; BUTTONS</h3>
            </div>
            <span id="studioDrawerState" class="text-xs text-[#0EA5E9] font-mono font-bold">Expand Studio ↓</span>
          </div>

          <div id="studioDrawerContent" class="hidden flex flex-col gap-3.5 pt-3 border-t border-[#1E293B]">

            <!-- Presets -->
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-xs text-[#94A3B8] font-medium mr-1">Presets:</span>
              <button onclick="applyPreset('default')" class="chip-token px-2.5 py-1 rounded-lg text-xs font-semibold text-white">🔥 Classic MST</button>
              <button onclick="applyPreset('cyber')" class="chip-token px-2.5 py-1 rounded-lg text-xs font-semibold text-[#0EA5E9]">💎 Cyber Pro</button>
              <button onclick="applyPreset('detailed')" class="chip-token px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-300">📡 NOC Telemetry</button>
              <button onclick="applyPreset('minimal')" class="chip-token px-2.5 py-1 rounded-lg text-xs font-semibold text-slate-400">⚡ Minimal</button>
            </div>

            <!-- Dynamic Variables -->
            <div class="flex flex-wrap gap-1.5">
              <button type="button" onclick="insertToken('{location}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#0EA5E9]">📍 {location}</button>
              <button type="button" onclick="insertToken('{country}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#0EA5E9]">🌍 {country}</button>
              <button type="button" onclick="insertToken('{city}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#0EA5E9]">🏙️ {city}</button>
              <button type="button" onclick="insertToken('{flag}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-white">🏳️ {flag}</button>
              <button type="button" onclick="insertToken('{ping}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#10B981]">⚡️ {ping}</button>
              <button type="button" onclick="insertToken('{status_dot}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#10B981]">🟢 {status_dot}</button>
              <button type="button" onclick="insertToken('{tg_time}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#0EA5E9]">🕒 {tg_time}</button>
              <button type="button" onclick="insertToken('{time}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#0EA5E9]">⏰ {time}</button>
              <button type="button" onclick="insertToken('{server}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-slate-300">🖥️ {server}</button>
              <button type="button" onclick="insertToken('{port}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-slate-300">🔌 {port}</button>
              <button type="button" onclick="insertToken('{signature}')" class="chip-token px-2 py-1 rounded-md text-[11px] font-mono text-[#0EA5E9]">🆔 {signature}</button>
            </div>

            <!-- Template Editor -->
            <div>
              <label class="text-xs text-[#94A3B8] mb-1 block font-medium">Message Body Template (HTML):</label>
              <textarea id="tplMessageInput" rows="5" oninput="updateLivePreview()" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl p-3 text-xs sm:text-sm font-mono leading-relaxed resize-y text-white focus:outline-none focus:border-[#0EA5E9]"></textarea>
            </div>

            <!-- Inputs for Buttons & Signature -->
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label class="text-xs text-[#94A3B8] mb-1 block">Channel Signature (<code class="text-[#0EA5E9]">{signature}</code>):</label>
                <input type="text" id="tplSignatureInput" oninput="updateLivePreview()" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#0EA5E9]">
              </div>
              <div>
                <label class="text-xs text-[#94A3B8] mb-1 block">Primary Connect Button Label:</label>
                <input type="text" id="tplButtonTextInput" oninput="updateLivePreview()" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs font-mono text-[#0EA5E9] focus:outline-none focus:border-[#0EA5E9]">
              </div>
            </div>

            <!-- Second Button Toggle -->
            <div class="flex flex-col gap-2 pt-2 border-t border-[#1E293B]">
              <label class="inline-flex items-center gap-2 cursor-pointer">
                <input type="checkbox" id="tplSecondBtnToggle" onchange="updateLivePreview()" class="w-4 h-4 rounded accent-[#0EA5E9]">
                <span class="text-xs font-semibold text-slate-200">Enable Secondary Inline Button (Join Channel / Announcement)</span>
              </label>

              <div id="secondBtnFields" class="grid grid-cols-1 sm:grid-cols-2 gap-3 hidden">
                <input type="text" id="tplSecondBtnText" placeholder="Button Text (e.g. Join Channel)" oninput="updateLivePreview()" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs text-white">
                <input type="text" id="tplSecondBtnUrl" placeholder="https://t.me/MSTProxy" oninput="updateLivePreview()" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs font-mono text-[#0EA5E9]">
              </div>
            </div>

            <!-- Save Format Button -->
            <div class="flex justify-end gap-2 pt-2">
              <button onclick="resetTemplateToDefault()" class="btn-action-dark px-4 py-2 rounded-xl text-xs font-semibold">
                Reset
              </button>
              <button id="saveTemplateBtn" onclick="saveTemplateConfiguration()" class="btn-action-dark hover:border-[#10B981] hover:text-[#10B981] px-5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 font-mono">
                <span id="saveTplIcon">💾</span>
                <span id="saveTplText">Save Post Format to KV</span>
              </button>
            </div>

          </div>
        </div>

        <!-- Integrated Telemetry Terminal Dock -->
        <div class="panel-box p-4 rounded-2xl flex flex-col gap-2.5">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></span>
                <span>EXECUTION &amp; TELEMETRY LOGS</span>
              </span>
            </div>
            <div class="flex items-center gap-2">
              <span id="savedKvPill" class="text-[10px] font-mono px-2.5 py-0.5 rounded-full bg-[#131D31] text-[#38BDF8] border border-[#38BDF8]/30">Saved to KV (PROXIES_KV)</span>
              <button onclick="copyTerminalLogs()" class="btn-action-dark text-[11px] px-2.5 py-1 rounded-lg font-medium">Copy</button>
              <button onclick="clearTerminal()" class="btn-action-dark text-[11px] px-2.5 py-1 rounded-lg font-medium">Clear</button>
            </div>
          </div>

          <pre id="logTerminal" class="custom-scroll bg-[#090D16] p-3.5 rounded-xl text-xs font-mono text-[#38BDF8] h-36 overflow-y-auto whitespace-pre-wrap leading-relaxed select-text border border-[#1E293B]">// Telegram Utility Initialized. Click "Dispatch to @MSTProxy" to stream step-by-step pipeline execution...</pre>
        </div>

      </div>

    </div>

  </main>

  <!-- Edit Source Modal Dialog -->
  <div id="editSourceModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm hidden opacity-0 transition-opacity duration-200">
    <div class="panel-box w-full max-w-md rounded-2xl p-5 flex flex-col gap-4 border border-[#1E293B] shadow-2xl transform scale-95 transition-transform duration-200" id="editModalBox">
      <div class="flex items-center justify-between border-b border-[#1E293B] pb-3">
        <h3 class="text-sm font-bold text-white flex items-center gap-1.5 font-mono">
          <span>✏️</span>
          <span>Edit Scraping Source</span>
        </h3>
        <button onclick="closeEditModal()" class="text-[#94A3B8] hover:text-white text-base">✕</button>
      </div>

      <input type="hidden" id="editSrcId">

      <div class="flex flex-col gap-3">
        <div>
          <label class="text-xs text-[#94A3B8] mb-1 block">Display Name:</label>
          <input type="text" id="editSrcName" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs text-white">
        </div>
        <div>
          <label class="text-xs text-[#94A3B8] mb-1 block">Source URL:</label>
          <input type="text" id="editSrcUrl" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs font-mono text-[#38BDF8]">
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="text-xs text-[#94A3B8] mb-1 block">Source Type:</label>
            <select id="editSrcType" class="bg-[#090D16] border border-[#1E293B] w-full rounded-xl px-3 py-2 text-xs text-white">
              <option value="telegram">Telegram (HTML)</option>
              <option value="text">Raw Text Feed</option>
            </select>
          </div>
          <div class="flex items-center pt-4">
            <label class="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" id="editSrcEnabled" class="w-4 h-4 rounded accent-[#10B981]">
              <span class="text-xs text-white">Active</span>
            </label>
          </div>
        </div>
      </div>

      <div class="flex items-center justify-end gap-2 pt-3 border-t border-[#1E293B]">
        <button onclick="closeEditModal()" class="btn-action-dark px-3.5 py-2 rounded-xl text-xs font-mono">Cancel</button>
        <button onclick="saveEditedSource()" class="btn-action-dark hover:border-[#10B981] hover:text-[#10B981] px-4 py-2 rounded-xl text-xs font-bold font-mono">Save</button>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast" class="fixed bottom-5 right-5 z-50 transform translate-y-24 opacity-0 transition-all duration-300 px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2.5 text-xs font-bold font-mono"></div>

  <script>
    const NL = String.fromCharCode(10);
    const PRESETS = {
      default: {
        messageTemplate: [
          '📍 <b>Location:</b> {location}',
          '⚡️ <b>Ping:</b> {ping}ms {status_dot}',
          '🕒 <b>Updated:</b> <tg-time unix="{unix}" format="r">{time}</tg-time>',
          '━━━━━━━━━━━━━━━━━━',
          '{signature}'
        ].join(NL),
        signature: '🔥 <a href="https://t.me/MSTProxy">𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬</a>',
        buttonText: '⚡️ CONNECT TO PROXY ⚡️',
        secondButtonEnabled: false,
        secondButtonText: '📢 Join @MSTProxy',
        secondButtonUrl: 'https://t.me/MSTProxy'
      },
      cyber: {
        messageTemplate: [
          '🛡️ <b>𝗠𝗧𝗣𝗥𝗢𝗧𝗢 𝗛𝗜𝗚𝗛-𝗦𝗣𝗘𝗘𝗗</b>',
          '',
          '🌍 <b>Location:</b> {country} {flag} <i>({city})</i>',
          '⚡️ <b>Latency:</b> <code>{ping}ms</code> {status_dot}',
          '🔌 <b>Port:</b> <code>{port}</code>',
          '🕒 <b>Synced:</b> <tg-time unix="{unix}" format="r">{time}</tg-time>',
          '━━━━━━━━━━━━━━━━━━',
          '{signature}'
        ].join(NL),
        signature: '💎 <a href="https://t.me/MSTProxy">𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬 𝗡𝗘𝗧𝗪𝗢𝗥𝗞</a>',
        buttonText: '⚡️ Tap to Connect ({flag} {ping}ms)',
        secondButtonEnabled: true,
        secondButtonText: '🔥 Join @MSTProxy',
        secondButtonUrl: 'https://t.me/MSTProxy'
      },
      detailed: {
        messageTemplate: [
          '📡 <b>NOC Telemetry: New Proxy Verified</b>',
          '',
          '📍 <b>Region:</b> {location}',
          '🖥️ <b>Host:</b> <code>{server}:{port}</code>',
          '⚡️ <b>Edge Latency:</b> <code>{ping}ms</code> {status_dot}',
          '🕒 <b>Time:</b> <tg-time unix="{unix}" format="r">{time}</tg-time>',
          '━━━━━━━━━━━━━━━━━━',
          '{signature}'
        ].join(NL),
        signature: '⚡️ <a href="https://t.me/MSTProxy">𝗠𝗦𝗧 𝗣𝗥⊂𝗢𝗫𝗬 𝗡𝗢𝗖</a>',
        buttonText: '🚀 Connect Proxy ({flag} {ping}ms)',
        secondButtonEnabled: false,
        secondButtonText: '📢 Channel @MSTProxy',
        secondButtonUrl: 'https://t.me/MSTProxy'
      },
      minimal: {
        messageTemplate: [
          '{flag} <b>{country}</b> • ⚡️ <code>{ping}ms</code> {status_dot} • 🕒 <tg-time unix="{unix}" format="r">{time}</tg-time>',
          '{signature}'
        ].join(NL),
        signature: '🆔 <a href="https://t.me/MSTProxy">@MSTProxy</a>',
        buttonText: '🚀 Connect ({flag})',
        secondButtonEnabled: false,
        secondButtonText: '📢 Channel',
        secondButtonUrl: 'https://t.me/MSTProxy'
      }
    };

    let currentSources = [
      { id: "Ela_Proxy", name: "Ela Proxy (Telegram Channel)", type: "telegram", url: "https://t.me/s/Ela_Proxy", enabled: true, priority: 1 },
      { id: "GitHub", name: "GitHub Master List (SoliSpirit)", type: "text", url: "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt", enabled: true, priority: 2 },
      { id: "drproxy_channel", name: "drproxy_channel", type: "telegram", url: "https://t.me/s/drproxy_channel", enabled: true, priority: 3 },
      { id: "mtprotoline", name: "mtprotoline", type: "telegram", url: "https://t.me/s/mtprotoline", enabled: true, priority: 4 }
    ];

    let currentTemplate = { ...PRESETS.default };

    // Real-Time Iran Clock & Dynamic Hourly Cron Countdown (Directly from Clock)
    function updateTehranClockAndCountdown() {
      const now = new Date();

      // Live 24h Tehran Time String
      const tehranTimeStr = now.toLocaleTimeString('en-GB', {
        timeZone: 'Asia/Tehran',
        hour12: false
      });

      // Tehran date object
      const tehranDate = new Date(now.toLocaleString('en-US', { timeZone: 'Asia/Tehran' }));
      const mins = tehranDate.getMinutes();
      const secs = tehranDate.getSeconds();

      // Exact countdown until next top of the hour (:00)
      const remainingSeconds = (59 - mins) * 60 + (60 - secs);
      const remMins = Math.floor(remainingSeconds / 60);
      const remSecs = remainingSeconds % 60;
      const countdownStr = String(remMins).padStart(2, '0') + ':' + String(remSecs).padStart(2, '0');

      // Next execution hour
      const nextHour = (tehranDate.getHours() + 1) % 24;
      const nextRunStr = String(nextHour).padStart(2, '0') + ':00';

      const clockEl = document.getElementById('liveTehranClock');
      if (clockEl) clockEl.innerText = tehranTimeStr;

      const countEl = document.getElementById('cronCountdownDisplay');
      if (countEl) countEl.innerText = countdownStr;

      const nextRunEl = document.getElementById('nextCronTargetTime');
      if (nextRunEl) nextRunEl.innerText = nextRunStr + ' IRST';

      const progressEl = document.getElementById('cronProgressBar');
      if (progressEl) {
        const elapsedPercent = ((mins * 60 + secs) / 3600) * 100;
        progressEl.style.width = elapsedPercent.toFixed(1) + '%';
      }
    }
    setInterval(updateTehranClockAndCountdown, 1000);
    updateTehranClockAndCountdown();

    function getAuthKey() {
      var k = '';
      try { k = sessionStorage.getItem('mst_key') || ''; } catch (_) {}
      if (!k) {
        k = (window.prompt('Dashboard key:') || '').trim();
        try { if (k) sessionStorage.setItem('mst_key', k); } catch (_) {}
      }
      return k;
    }

    function showToast(text, isError = false) {
      const toast = document.getElementById('toast');
      if (!toast) return;
      toast.innerText = text;
      toast.className = isError
        ? 'fixed bottom-5 right-5 z-50 transform translate-y-0 opacity-100 transition-all duration-300 px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2 text-xs font-bold font-mono bg-[#131D31] text-rose-300 border border-rose-500/60'
        : 'fixed bottom-5 right-5 z-50 transform translate-y-0 opacity-100 transition-all duration-300 px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2 text-xs font-bold font-mono bg-[#131D31] text-[#10B981] border border-[#10B981]';

      setTimeout(() => {
        toast.className = 'fixed bottom-5 right-5 z-50 transform translate-y-24 opacity-0 transition-all duration-300 px-4 py-2.5 rounded-xl shadow-xl flex items-center gap-2 text-xs font-bold font-mono';
      }, 3200);
    }

    let isStudioDrawerOpen = false;
    function toggleStudioDrawer() {
      isStudioDrawerOpen = !isStudioDrawerOpen;
      const content = document.getElementById('studioDrawerContent');
      const stateTxt = document.getElementById('studioDrawerState');
      if (content && stateTxt) {
        if (isStudioDrawerOpen) {
          content.classList.remove('hidden');
          stateTxt.innerText = 'Collapse Studio ↑';
        } else {
          content.classList.add('hidden');
          stateTxt.innerText = 'Expand Studio ↓';
        }
      }
    }

    let lastExecutionData = null;

    function renderTerminalContent() {
      const terminal = document.getElementById('logTerminal');
      if (!terminal) return;
      if (!lastExecutionData) {
        terminal.innerText = '// Telegram Utility Initialized. Click "Dispatch to @MSTProxy" to stream step-by-step pipeline execution...';
        return;
      }
      if (Array.isArray(lastExecutionData.logs)) {
        terminal.innerText = lastExecutionData.logs.join(NL);
      } else {
        terminal.innerText = JSON.stringify(lastExecutionData, null, 2);
      }
    }

    function copyTerminalLogs() {
      const terminal = document.getElementById('logTerminal');
      if (terminal) {
        navigator.clipboard.writeText(terminal.innerText);
        showToast('Logs copied to clipboard');
      }
    }

    function clearTerminal() {
      lastExecutionData = null;
      const terminal = document.getElementById('logTerminal');
      if (terminal) {
        terminal.innerText = '// Telemetry buffer cleared. Ready for next dispatch.';
      }
    }

    function syncTemplateInputsFromState() {
      const msgInput = document.getElementById('tplMessageInput');
      const sigInput = document.getElementById('tplSignatureInput');
      const btnInput = document.getElementById('tplButtonTextInput');
      const secToggle = document.getElementById('tplSecondBtnToggle');
      const secText = document.getElementById('tplSecondBtnText');
      const secUrl = document.getElementById('tplSecondBtnUrl');

      if (msgInput) msgInput.value = currentTemplate.messageTemplate || PRESETS.default.messageTemplate;
      if (sigInput) sigInput.value = currentTemplate.signature ?? PRESETS.default.signature;
      if (btnInput) btnInput.value = currentTemplate.buttonText || PRESETS.default.buttonText;
      if (secToggle) secToggle.checked = Boolean(currentTemplate.secondButtonEnabled);
      if (secText) secText.value = currentTemplate.secondButtonText || PRESETS.default.secondButtonText;
      if (secUrl) secUrl.value = currentTemplate.secondButtonUrl || PRESETS.default.secondButtonUrl;
      updateLivePreview();
    }

    function readTemplateStateFromInputs() {
      const msgInput = document.getElementById('tplMessageInput');
      const sigInput = document.getElementById('tplSignatureInput');
      const btnInput = document.getElementById('tplButtonTextInput');
      const secToggle = document.getElementById('tplSecondBtnToggle');
      const secText = document.getElementById('tplSecondBtnText');
      const secUrl = document.getElementById('tplSecondBtnUrl');

      return {
        messageTemplate: msgInput ? msgInput.value : PRESETS.default.messageTemplate,
        signature: sigInput ? sigInput.value : PRESETS.default.signature,
        buttonText: btnInput ? btnInput.value : PRESETS.default.buttonText,
        secondButtonEnabled: secToggle ? secToggle.checked : false,
        secondButtonText: secText ? secText.value : PRESETS.default.secondButtonText,
        secondButtonUrl: secUrl ? secUrl.value : PRESETS.default.secondButtonUrl
      };
    }

    function insertToken(token) {
      const textarea = document.getElementById('tplMessageInput');
      if (!textarea) return;
      const start = textarea.selectionStart || 0;
      const end = textarea.selectionEnd || 0;
      const val = textarea.value;
      textarea.value = val.substring(0, start) + token + val.substring(end);
      textarea.focus();
      textarea.selectionStart = textarea.selectionEnd = start + token.length;
      updateLivePreview();
    }

    function applyPreset(name) {
      if (!PRESETS[name]) return;
      currentTemplate = { ...PRESETS[name] };
      syncTemplateInputsFromState();
      showToast('Preset applied — save to persist');
    }

    function resetTemplateToDefault() {
      currentTemplate = { ...PRESETS.default };
      syncTemplateInputsFromState();
      showToast('Reset to default post layout');
    }

    function sanitizeTelegramHtmlForPreview(rawHtml) {
      if (!rawHtml) return '';
      return rawHtml
        .split('<tg-spoiler>').join('<span class="bg-[#1E2E48] text-transparent hover:text-white transition px-1 rounded cursor-pointer">')
        .split('</tg-spoiler>').join('</span>')
        .split('<code>').join('<code class="bg-[#090D16] text-[#38BDF8] px-1.5 py-0.5 rounded font-mono text-xs border border-[#1E293B]">')
        .split('</code>').join('</code>');
    }

    function updateLivePreview() {
      currentTemplate = readTemplateStateFromInputs();
      try {
        localStorage.setItem('mst_template_backup', JSON.stringify(currentTemplate));
      } catch (_) {}

      const secondFields = document.getElementById('secondBtnFields');
      if (secondFields) {
        if (currentTemplate.secondButtonEnabled) {
          secondFields.classList.remove('hidden');
        } else {
          secondFields.classList.add('hidden');
        }
      }

      const now = new Date();
      const unixTime = Math.floor(now.getTime() / 1000);
      const timeStr = now.toLocaleTimeString('en-US', {
        hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Tehran'
      });
      const timeEl = document.getElementById('previewBubbleTime');
      if (timeEl) timeEl.innerText = timeStr;

      const sample = {
        location: 'Frankfurt, Germany 🇩🇪',
        country: 'Germany',
        city: 'Frankfurt',
        flag: '🇩🇪',
        ping: '88',
        status_dot: '🟢',
        unix: String(unixTime),
        time: timeStr,
        tg_time: '<span class="text-[#38BDF8] font-mono">' + timeStr + '</span>',
        server: 'de1.mst-proxy.net',
        port: '443',
        source: 'Ela_Proxy',
        url: 'https://t.me/proxy?server=de1.mst-proxy.net&port=443&secret=ee0000',
        signature: currentTemplate.signature || PRESETS.default.signature,
        separator: '━━━━━━━━━━━━━━━━━━'
      };

      let rendered = currentTemplate.messageTemplate || PRESETS.default.messageTemplate;
      rendered = rendered
        .split('{location}').join(sample.location)
        .split('{country}').join(sample.country)
        .split('{city}').join(sample.city)
        .split('{flag}').join(sample.flag)
        .split('{ping}').join(sample.ping)
        .split('{status_dot}').join(sample.status_dot)
        .split('{unix}').join(sample.unix)
        .split('{time}').join(timeStr)
        .split('{tg_time}').join(sample.tg_time)
        .split('{server}').join(sample.server)
        .split('{port}').join(sample.port)
        .split('{source}').join(sample.source)
        .split('{url}').join(sample.url)
        .split('{signature}').join(sample.signature)
        .split('{separator}').join(sample.separator);

      const safeHtml = sanitizeTelegramHtmlForPreview(rendered);
      const textPreview = document.getElementById('liveTelegramPreviewText');
      if (textPreview) textPreview.innerHTML = safeHtml;

      const btn1Text = (currentTemplate.buttonText || '⚡️ CONNECT TO PROXY ⚡️')
        .split('{flag}').join(sample.flag)
        .split('{country}').join(sample.country)
        .split('{ping}').join(sample.ping);

      let btnsHtml = '<div class="btn-connect-hero py-3.5 px-6 rounded-xl text-center text-xs sm:text-sm cursor-pointer flex items-center justify-center gap-2 font-mono shadow-lg">' +
        '<span>' + btn1Text + '</span>' +
        '<span class="text-xs">↗</span>' +
      '</div>';

      if (currentTemplate.secondButtonEnabled && currentTemplate.secondButtonText) {
        btnsHtml += '<div class="btn-action-dark py-2.5 px-4 rounded-xl text-center text-xs font-semibold text-[#38BDF8] cursor-pointer flex items-center justify-center gap-1.5 font-mono mt-1.5">' +
          '<span>' + currentTemplate.secondButtonText + '</span>' +
          '<span class="text-xs">↗</span>' +
        '</div>';
      }

      const liveBtns = document.getElementById('liveTelegramPreviewButtons');
      if (liveBtns) liveBtns.innerHTML = btnsHtml;
    }

    async function saveTemplateConfiguration() {
      const btn = document.getElementById('saveTemplateBtn');
      const icon = document.getElementById('saveTplIcon');
      const txt = document.getElementById('saveTplText');

      if (btn) btn.disabled = true;
      if (icon) icon.innerText = '⏳';
      if (txt) txt.innerText = 'Saving...';

      currentTemplate = readTemplateStateFromInputs();

      try {
        localStorage.setItem('mst_template_backup', JSON.stringify(currentTemplate));
        const res = await fetch('/api/save-template', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            key: getAuthKey(),
            template: currentTemplate
          })
        });
        const data = await res.json();
        if (res.ok && data.status === 'success') {
          showToast('Telegram post format saved to KV');
        } else {
          showToast('Save failed: ' + (data.message || 'Unknown error'), true);
        }
      } catch (err) {
        showToast('Saved locally in browser', true);
      } finally {
        if (btn) btn.disabled = false;
        if (icon) icon.innerText = '💾';
        if (txt) txt.innerText = 'Save Post Format to KV';
      }
    }

    let draggedSourceIndex = null;

    function normalizeSourcePriorities() {
      currentSources.forEach((src, index) => {
        src.priority = index + 1;
      });
    }

    function renderSourcesUI() {
      const container = document.getElementById('sourcesList');
      if (!container) return;
      container.innerHTML = '';

      normalizeSourcePriorities();
      const activeCount = currentSources.filter(s => s.enabled).length;
      const statEl = document.getElementById('statActiveSources');
      if (statEl) statEl.innerText = activeCount + ' / ' + currentSources.length + ' Active';

      currentSources.forEach((src, idx) => {
        const card = document.createElement('div');
        const isPriorityOne = idx === 0 && src.enabled;
        card.className = (isPriorityOne ? 'source-item source-item-priority1' : 'source-item') + ' p-3.5 rounded-2xl flex items-center justify-between gap-3 select-none';
        card.setAttribute('draggable', 'true');
        card.dataset.index = String(idx);

        card.addEventListener('dragstart', (e) => {
          draggedSourceIndex = idx;
          card.classList.add('dragging');
          if (e.dataTransfer) {
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', String(idx));
          }
        });

        card.addEventListener('dragover', (e) => {
          e.preventDefault();
          if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
          if (draggedSourceIndex !== null && draggedSourceIndex !== idx) {
            card.classList.add('drag-over');
          }
        });

        card.addEventListener('dragleave', () => {
          card.classList.remove('drag-over');
        });

        card.addEventListener('drop', (e) => {
          e.preventDefault();
          card.classList.remove('drag-over');
          if (draggedSourceIndex === null || draggedSourceIndex === idx) return;
          const movedItem = currentSources.splice(draggedSourceIndex, 1)[0];
          currentSources.splice(idx, 0, movedItem);
          draggedSourceIndex = null;
          normalizeSourcePriorities();
          renderSourcesUI();
          saveSourcesConfiguration(true);
        });

        card.addEventListener('dragend', () => {
          draggedSourceIndex = null;
          document.querySelectorAll('.source-item').forEach(el => {
            el.classList.remove('dragging', 'drag-over');
          });
        });

        const isChecked = src.enabled ? 'checked' : '';
        const priorityPillClass = isPriorityOne
          ? 'bg-[#10B981] text-[#090D16] font-black'
          : 'bg-[#131D31] text-[#94A3B8] font-bold border border-[#1E293B]';

        card.innerHTML =
          '<div class="flex items-center gap-2.5 min-w-0 flex-1">' +
            '<div class="drag-handle p-1.5 rounded-lg text-slate-500 hover:text-white transition" title="Drag to reorder">' +
              '<svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20">' +
                '<path d="M7 4a1 1 0 11-2 0 1 1 0 012 0zm0 6a1 1 0 11-2 0 1 1 0 012 0zm0 6a1 1 0 11-2 0 1 1 0 012 0zm8-12a1 1 0 11-2 0 1 1 0 012 0zm0 6a1 1 0 11-2 0 1 1 0 012 0zm0 6a1 1 0 11-2 0 1 1 0 012 0z"/>' +
              '</svg>' +
            '</div>' +
            '<div class="w-7 h-7 rounded-xl flex items-center justify-center font-mono text-xs shrink-0 ' + priorityPillClass + '">#' + src.priority + '</div>' +
            '<div class="min-w-0 flex-1">' +
              '<div class="flex items-center gap-1.5">' +
                '<span class="font-bold text-xs sm:text-sm text-white truncate">' + src.name + '</span>' +
              '</div>' +
              '<p class="text-[11px] text-[#94A3B8] font-mono truncate">' + src.url + '</p>' +
            '</div>' +
          '</div>' +
          '<div class="flex items-center gap-2.5 shrink-0">' +
            '<label class="ios-switch" title="Toggle Source Active/Disabled">' +
              '<input type="checkbox" ' + isChecked + ' class="src-toggle-cb">' +
              '<span class="ios-slider"></span>' +
            '</label>' +
            '<button type="button" class="btn-edit-src p-1.5 rounded-lg text-slate-400 hover:text-[#38BDF8] hover:bg-[#131D31] transition" title="Edit Source">✏️</button>' +
            '<button type="button" class="btn-remove-src p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-[#131D31] transition" title="Delete Source">🗑️</button>' +
          '</div>';

        const toggleCb = card.querySelector('.src-toggle-cb');
        if (toggleCb) toggleCb.addEventListener('change', (e) => toggleSourceEnabled(src.id, e.target.checked));

        const editBtn = card.querySelector('.btn-edit-src');
        if (editBtn) editBtn.addEventListener('click', () => openEditModal(src.id));

        const removeBtn = card.querySelector('.btn-remove-src');
        if (removeBtn) removeBtn.addEventListener('click', () => removeSource(src.id));

        container.appendChild(card);
      });
    }

    function addNewSource() {
      const nameInput = document.getElementById('newSrcName');
      const urlInput = document.getElementById('newSrcUrl');
      if (!nameInput || !urlInput) return;

      const name = nameInput.value.trim();
      const url = urlInput.value.trim();

      if (!name || !url) {
        showToast('Please enter both source name and URL', true);
        return;
      }

      const id = name.replace(/[^a-zA-Z0-9_]/g, '_') + '_' + Date.now().toString().slice(-3);
      const type = url.includes('t.me/') ? 'telegram' : 'text';
      const priority = currentSources.length + 1;

      currentSources.push({ id, name, type, url, enabled: true, priority });
      nameInput.value = '';
      urlInput.value = '';
      renderSourcesUI();
      saveSourcesConfiguration(false);
    }

    function removeSource(id) {
      if (currentSources.length <= 1) {
        showToast('At least one source must remain in the pipeline', true);
        return;
      }
      currentSources = currentSources.filter(s => s.id !== id);
      normalizeSourcePriorities();
      renderSourcesUI();
      saveSourcesConfiguration(true);
    }

    function toggleSourceEnabled(id, isEnabled) {
      const src = currentSources.find(s => s.id === id);
      if (src) {
        src.enabled = Boolean(isEnabled);
        renderSourcesUI();
        saveSourcesConfiguration(true);
      }
    }

    function openEditModal(id) {
      const src = currentSources.find(s => s.id === id);
      if (!src) return;

      const idEl = document.getElementById('editSrcId');
      const nameEl = document.getElementById('editSrcName');
      const urlEl = document.getElementById('editSrcUrl');
      const typeEl = document.getElementById('editSrcType');
      const enEl = document.getElementById('editSrcEnabled');

      if (idEl) idEl.value = src.id;
      if (nameEl) nameEl.value = src.name;
      if (urlEl) urlEl.value = src.url;
      if (typeEl) typeEl.value = src.type || (src.url.includes('t.me/') ? 'telegram' : 'text');
      if (enEl) enEl.checked = src.enabled !== false;

      const modal = document.getElementById('editSourceModal');
      const box = document.getElementById('editModalBox');
      if (modal && box) {
        modal.classList.remove('hidden');
        setTimeout(() => {
          modal.classList.remove('opacity-0');
          box.classList.remove('scale-95');
          box.classList.add('scale-100');
        }, 10);
      }
    }

    function closeEditModal() {
      const modal = document.getElementById('editSourceModal');
      const box = document.getElementById('editModalBox');
      if (modal && box) {
        modal.classList.add('opacity-0');
        box.classList.remove('scale-100');
        box.classList.add('scale-95');
        setTimeout(() => {
          modal.classList.add('hidden');
        }, 200);
      }
    }

    function saveEditedSource() {
      const idEl = document.getElementById('editSrcId');
      const nameEl = document.getElementById('editSrcName');
      const urlEl = document.getElementById('editSrcUrl');
      const typeEl = document.getElementById('editSrcType');
      const enEl = document.getElementById('editSrcEnabled');

      if (!idEl || !nameEl || !urlEl) return;

      const id = idEl.value;
      const name = nameEl.value.trim();
      const url = urlEl.value.trim();
      const type = typeEl ? typeEl.value : 'telegram';
      const enabled = enEl ? enEl.checked : true;

      if (!name || !url) {
        showToast('Source name and URL cannot be empty', true);
        return;
      }

      const src = currentSources.find(s => s.id === id);
      if (src) {
        src.name = name;
        src.url = url;
        src.type = type;
        src.enabled = enabled;
        renderSourcesUI();
        closeEditModal();
        saveSourcesConfiguration(true);
        showToast('Source updated');
      }
    }

    async function saveSourcesConfiguration(isAuto = false) {
      const saveBtn = document.getElementById('saveSourcesBtn');
      const saveIcon = document.getElementById('saveIcon');
      const saveText = document.getElementById('saveText');

      normalizeSourcePriorities();
      try {
        localStorage.setItem('mst_sources_backup', JSON.stringify(currentSources));
      } catch (_) {}

      if (saveBtn) {
        saveBtn.disabled = true;
        if (saveIcon) saveIcon.innerText = '⏳';
        if (saveText) saveText.innerText = isAuto ? 'Syncing...' : 'Saving...';
      }

      try {
        const key = getAuthKey();
        const res = await fetch('/api/save-sources', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key, sources: currentSources })
        });

        const data = await res.json();
        if (res.ok && data.status === 'success') {
          if (Array.isArray(data.sources)) {
            currentSources = data.sources;
            renderSourcesUI();
          }
          showToast(data.message || 'Pipeline saved');
        } else {
          showToast('Save failed: ' + (data.message || 'Unknown error'), true);
        }
      } catch (err) {
        showToast('Network error: ' + err.message, true);
      } finally {
        if (saveBtn) {
          saveBtn.disabled = false;
          if (saveIcon) saveIcon.innerText = '💾';
          if (saveText) saveText.innerText = 'Save Pipeline Order to KV';
        }
      }
    }

    function renderCheckHostIranNodes(iranNodes, reportUrl) {
      const tbody = document.getElementById('checkHostIranTableBody');
      const linkEl = document.getElementById('checkHostExternalLink');
      if (linkEl && reportUrl) {
        linkEl.href = reportUrl;
      }
      if (!tbody || !Array.isArray(iranNodes) || iranNodes.length === 0) return;

      tbody.innerHTML = iranNodes.map(n => {
        const badgeColor = n.ok >= 2 ? 'text-[#10B981] font-bold' : 'text-rose-400';
        return '<tr class="hover:bg-[#131D31]/60">' +
          '<td class="py-1.5 pr-2">🇮🇷 ' + (n.location || n.node) + '</td>' +
          '<td class="py-1.5 pr-2 ' + badgeColor + '">' + (n.ok ?? 0) + ' / ' + (n.total ?? 4) + '</td>' +
          '<td class="py-1.5 pr-2 text-[#38BDF8]">' + (n.rttText || '—') + '</td>' +
          '<td class="py-1.5 text-slate-400">' + (n.ip || '—') + '</td>' +
        '</tr>';
      }).join('');
    }

    async function triggerManualSend(ignoreKv = false, mode = 'immediate') {
      const sendBtn = document.getElementById('sendBtn');
      const sendIcon = document.getElementById('sendIcon');
      const sendText = document.getElementById('sendText');
      const stageBtn = document.getElementById('stageBtn');
      const stageIcon = document.getElementById('stageIcon');
      const stageText = document.getElementById('stageText');
      const sendBtnTop = document.getElementById('sendBtnTop');
      const terminal = document.getElementById('logTerminal');

      if (sendBtn) sendBtn.disabled = true;
      if (stageBtn) stageBtn.disabled = true;
      if (sendBtnTop) sendBtnTop.disabled = true;

      if (mode === 'prepare') {
        if (stageIcon) stageIcon.innerText = '⏳';
        if (stageText) stageText.innerText = 'Testing on Iran DCs...';
      } else {
        if (sendIcon) sendIcon.innerText = '⏳';
        if (sendText) sendText.innerText = 'Testing Iran & Sending...';
      }

      const nowStr = new Date().toLocaleTimeString('en-GB', { hour12: false });
      if (terminal) {
        terminal.innerText =
          '[' + nowStr + '] 🚀 [PIPELINE] Starting (' + mode.toUpperCase() + ' mode)...' + NL +
          '[' + nowStr + '] 🇮🇷 Querying Check-Host.net Iranian datacenters (Isfahan, Shiraz, Tehran)...';
      }

      currentTemplate = readTemplateStateFromInputs();

      try {
        const key = getAuthKey();
        const res = await fetch('/api/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            key,
            ignoreKv,
            mode,
            sourcesOverride: currentSources,
            templateOverride: currentTemplate
          })
        });

        const data = await res.json();
        lastExecutionData = data;
        renderTerminalContent();

        if (data.proxy && Array.isArray(data.proxy.iran_nodes)) {
          renderCheckHostIranNodes(data.proxy.iran_nodes, data.proxy.check_host_url);
        }

        if (data.status === 'success') {
          showToast('Iran-verified proxy published to @MSTProxy!');
          const lastProxyEl = document.getElementById('statLastProxy');
          if (lastProxyEl && data.proxy) {
            lastProxyEl.innerText = data.proxy.server + ':' + data.proxy.port + ' (' + data.proxy.ping + 'ms)';
          }
          const stagedEl = document.getElementById('statStagedProxy');
          if (stagedEl) stagedEl.innerText = 'None (Published)';
        } else if (data.status === 'staged') {
          showToast('Proxy verified from Iran & queued for :00!');
          const stagedEl = document.getElementById('statStagedProxy');
          if (stagedEl && data.proxy) {
            stagedEl.innerText = data.proxy.server + ':' + data.proxy.port + ' (' + data.proxy.ping + 'ms Ready)';
          }
        } else {
          showToast('Outcome: ' + (data.reason || data.status), true);
        }
      } catch (err) {
        if (terminal) terminal.innerText = 'Error connecting to worker:' + NL + err.message;
        showToast('Failed to trigger pipeline', true);
      } finally {
        if (sendBtn) sendBtn.disabled = false;
        if (stageBtn) stageBtn.disabled = false;
        if (sendBtnTop) sendBtnTop.disabled = false;
        if (sendIcon) sendIcon.innerText = '✈️';
        if (sendText) sendText.innerText = 'Test & Dispatch Now';
        if (stageIcon) stageIcon.innerText = '🕒';
        if (stageText) stageText.innerText = 'Pre-Test & Stage (:55)';
      }
    }

    async function initDashboard() {
      try {
        const localTpl = localStorage.getItem('mst_template_backup');
        if (localTpl) {
          currentTemplate = { ...PRESETS.default, ...JSON.parse(localTpl) };
        }
      } catch (_) {}

      syncTemplateInputsFromState();
      renderSourcesUI();

      function applyChannelInfo(info) {
        if (!info) return;
        const avatarContainer = document.getElementById('channelAvatarContainer');
        if (avatarContainer && info.avatar) {
          const img = document.createElement('img');
          img.src = info.avatar;
          img.alt = info.title || 'MST Proxy';
          img.className = 'w-full h-full object-cover rounded-full';
          img.onerror = function() {
            avatarContainer.innerHTML = '<span id="channelAvatarFallback">M</span>';
          };
          avatarContainer.innerHTML = '';
          avatarContainer.appendChild(img);
        }
        const bubbleAvatar = document.getElementById('postBubbleAvatarContainer');
        if (bubbleAvatar && info.avatar) {
          const bImg = document.createElement('img');
          bImg.src = info.avatar;
          bImg.className = 'w-full h-full object-cover rounded-full';
          bubbleAvatar.innerHTML = '';
          bubbleAvatar.appendChild(bImg);
        }
        const titleHeader = document.getElementById('channelTitleHeader');
        if (titleHeader && info.title) {
          titleHeader.innerText = info.title;
        }
        const bubbleTitle = document.getElementById('postBubbleTitle');
        if (bubbleTitle && info.title) {
          bubbleTitle.innerText = info.title;
        }
        const subCount = document.getElementById('channelSubscribersCount');
        if (subCount && info.subscribers) {
          subCount.innerText = info.subscribers;
        }
      }

      try {
        const key = getAuthKey();
        const [statusRes, sourcesRes, tplRes, channelRes] = await Promise.allSettled([
          fetch('/api/status'),
          fetch('/api/get-sources?key=' + encodeURIComponent(key)),
          fetch('/api/get-template?key=' + encodeURIComponent(key)),
          fetch('/api/channel-info')
        ]);

        if (statusRes.status === 'fulfilled' && statusRes.value.ok) {
          const statusData = await statusRes.value.json();
          const kvStat = document.getElementById('statKvStatus');
          const kvPill = document.getElementById('savedKvPill');
          const kvName = statusData.kv_binding || 'PROXIES_KV';
          const kvLabel = statusData.kv_connected ? ('KV (' + kvName + ')') : 'In-Memory';
          if (kvStat) kvStat.innerText = kvLabel;
          if (kvPill) kvPill.innerText = 'Saved to ' + kvLabel;
          if (statusData.channel_info) {
            applyChannelInfo(statusData.channel_info);
          }

          const lastProxyEl = document.getElementById('statLastProxy');
          if (lastProxyEl && statusData.last_run && statusData.last_run.server) {
            lastProxyEl.innerText =
              statusData.last_run.server + ':' + statusData.last_run.port + ' (' + statusData.last_run.ping + 'ms)';
            if (Array.isArray(statusData.last_run.iran_nodes) && statusData.last_run.iran_nodes.length > 0) {
              renderCheckHostIranNodes(statusData.last_run.iran_nodes, statusData.last_run.check_host_url);
            }
          }
          const stagedEl = document.getElementById('statStagedProxy');
          if (stagedEl && statusData.staged_proxy && statusData.staged_proxy.server) {
            stagedEl.innerText =
              statusData.staged_proxy.server + ':' + statusData.staged_proxy.port + ' (' + statusData.staged_proxy.iranPing + 'ms Ready)';
            if (Array.isArray(statusData.staged_proxy.iranNodes) && statusData.staged_proxy.iranNodes.length > 0) {
              renderCheckHostIranNodes(statusData.staged_proxy.iranNodes, statusData.staged_proxy.checkHostReportUrl);
            }
          }
        }

        if (sourcesRes.status === 'fulfilled' && sourcesRes.value.ok) {
          const sData = await sourcesRes.value.json();
          if (sData.status === 'success' && Array.isArray(sData.sources)) {
            currentSources = sData.sources.sort((a, b) => (a.priority || 1) - (b.priority || 1));
            renderSourcesUI();
          }
        }

        if (tplRes.status === 'fulfilled' && tplRes.value.ok) {
          const tData = await tplRes.value.json();
          if (tData.status === 'success' && tData.template) {
            currentTemplate = { ...PRESETS.default, ...tData.template };
            syncTemplateInputsFromState();
          }
        }

        if (channelRes && channelRes.status === 'fulfilled' && channelRes.value.ok) {
          const cData = await channelRes.value.json();
          if (cData.status === 'success' && cData.channel_info) {
            applyChannelInfo(cData.channel_info);
          }
        }
      } catch (e) {}
    }

    window.addEventListener('DOMContentLoaded', initDashboard);
  </script>
</body>
</html>`;
}
