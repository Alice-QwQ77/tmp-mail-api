const APP_NAME = "Temporary Mail API";
const KV_BINDING_NAME = "TMPMAIL_KV";
const ACCOUNT_TTL_MS = 24 * 60 * 60 * 1000;
const TOKEN_REFRESH_INTERVAL_MS = 10 * 60 * 1000;
const MAIL_MAP_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_SEC = 24 * 60 * 60;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const HMAC_KEY_CACHE = new Map();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function getKv() {
  if (typeof TMPMAIL_KV === "undefined") {
    throw new Error(`Missing EdgeOne KV binding: ${KV_BINDING_NAME}`);
  }
  return TMPMAIL_KV;
}

function env(context, key, fallback = "") {
  const value = context.env && context.env[key];
  return value === undefined || value === null || value === ""
    ? fallback
    : String(value);
}

function envPositiveInt(context, key, fallback) {
  const value = Number(env(context, key, String(fallback)));
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function envNonNegativeInt(context, key, fallback) {
  const value = Number(env(context, key, String(fallback)));
  return Number.isInteger(value) && value >= 0 ? value : fallback;
}

function jsonResponse(status, data, error = "", headers) {
  const finalHeaders = new Headers(headers);
  finalHeaders.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify({ success: status < 400, data, error }), {
    status,
    headers: finalHeaders,
  });
}

function htmlResponse(status, html, headers) {
  const finalHeaders = new Headers(headers);
  finalHeaders.set("content-type", "text/html; charset=utf-8");
  return new Response(html, { status, headers: finalHeaders });
}

function redirectResponse(location, status = 302, headers) {
  const finalHeaders = new Headers(headers);
  finalHeaders.set("location", location);
  return new Response(null, { status, headers: finalHeaders });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function randomHex(bytes) {
  const raw = new Uint8Array(bytes);
  crypto.getRandomValues(raw);
  return Array.from(raw, (value) => value.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function timingSafeEqual(a, b) {
  const left = textEncoder.encode(a);
  const right = textEncoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length === right.length ? 0 : 1;
  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function getHmacKey(secret) {
  if (!HMAC_KEY_CACHE.has(secret)) {
    HMAC_KEY_CACHE.set(
      secret,
      crypto.subtle.importKey("raw", textEncoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    );
  }
  return await HMAC_KEY_CACHE.get(secret);
}

async function signAdminSession(secret, payload) {
  const payloadB64 = bytesToBase64Url(textEncoder.encode(JSON.stringify(payload)));
  const key = await getHmacKey(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, textEncoder.encode(payloadB64)));
  return `${payloadB64}.${bytesToBase64Url(signature)}`;
}

async function verifyAdminSession(secret, token) {
  if (!token) return null;
  const [payloadB64, signatureB64] = token.split(".");
  if (!payloadB64 || !signatureB64) return null;
  const key = await getHmacKey(secret);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, textEncoder.encode(payloadB64)));
  if (!timingSafeEqual(bytesToBase64Url(signature), signatureB64)) return null;
  try {
    const payload = JSON.parse(textDecoder.decode(base64UrlToBytes(payloadB64)));
    return payload && typeof payload.exp === "number" && payload.exp > Math.floor(Date.now() / 1000)
      ? payload
      : null;
  } catch {
    return null;
  }
}

function parseCookies(rawCookie) {
  const result = {};
  if (!rawCookie) return result;
  for (const part of rawCookie.split(/;\s*/)) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex <= 0) continue;
    result[part.slice(0, separatorIndex)] = part.slice(separatorIndex + 1);
  }
  return result;
}

function buildCookie(name, value, options = {}) {
  const parts = [`${name}=${value}`, `Path=${options.path ?? "/"}`];
  if (options.httpOnly !== false) parts.push("HttpOnly");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push("Secure");
  if (typeof options.maxAge === "number") parts.push(`Max-Age=${options.maxAge}`);
  if (options.expires instanceof Date) parts.push(`Expires=${options.expires.toUTCString()}`);
  return parts.join("; ");
}

function clearCookie(name, secure) {
  return buildCookie(name, "", {
    path: "/",
    httpOnly: true,
    sameSite: "Strict",
    secure,
    maxAge: 0,
    expires: new Date(0),
  });
}

function keyForApiKey(id) {
  return `api_key:${id}`;
}

function keyForApiKeyHash(hash) {
  return `api_key_hash:${hash}`;
}

function keyForAccount(provider, email) {
  return `provider_account:${provider}:${email}`;
}

function keyForSessionOwner(email) {
  return `session_owner:${email}`;
}

function keyForMailMap(mailId) {
  return `mail_map:${mailId}`;
}

function keyForLinshiMailMeta(email, mailId) {
  return `linshi_mail_meta:${email}:${mailId}`;
}

function keyForMetric(name) {
  return `metric:${name}`;
}

function keyForMetricDay(name, yyyymmdd) {
  return `metric_day:${name}:${yyyymmdd}`;
}

function keyForProviderConfig(name) {
  return `provider_config:${name}`;
}

function keyForConfig(name) {
  return `config:${name}`;
}

async function kvPutJson(kv, key, value) {
  await kv.put(key, JSON.stringify(value));
}

async function kvGetJson(kv, key) {
  return await kv.get(key, "json");
}

async function kvGetText(kv, key) {
  const value = await kv.get(key);
  return value == null ? null : String(value);
}

async function kvDelete(kv, key) {
  await kv.delete(key);
}

async function kvListKeys(kv, prefix) {
  const keys = [];
  let cursor;
  do {
    const page = await kv.list({ prefix, limit: 256, cursor });
    for (const item of page.keys || []) {
      if (item && typeof item.name === "string") keys.push(item.name);
    }
    cursor = page.cursor;
    if (page.complete) break;
  } while (true);
  return keys;
}

function utcDayStamp(timestampMs = Date.now()) {
  return new Date(timestampMs).toISOString().slice(0, 10).replaceAll("-", "");
}

async function getNumberMetric(kv, key) {
  const raw = await kvGetText(kv, key);
  const parsed = raw == null ? 0 : Number(raw);
  return Number.isFinite(parsed) ? parsed : 0;
}

async function incrementMetric(kv, key, delta) {
  const current = await getNumberMetric(kv, key);
  await kv.put(key, String(current + delta));
}

async function persistUpstreamMetrics(kv, upstreamCalls) {
  if (!upstreamCalls) return;
  await incrementMetric(kv, keyForMetric("upstream_calls_total"), upstreamCalls);
  await incrementMetric(kv, keyForMetricDay("upstream_calls", utcDayStamp()), upstreamCalls);
}

function parseProviderList(context) {
  const raw = env(context, "ENABLED_PROVIDERS", "mailtm,mailgw");
  const names = Array.from(new Set(raw.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean)));
  const providers = {};
  if (names.includes("mailtm")) {
    providers.mailtm = {
      name: "mailtm",
      title: "mail.tm",
      baseUrl: env(context, "PROVIDER_MAILTM_BASE", "https://api.mail.tm").replace(/\/$/, ""),
      fromExtractor(message) {
        const from = message.from;
        if (from && typeof from === "object" && !Array.isArray(from)) {
          return String(from.address ?? from.name ?? "");
        }
        return typeof from === "string" ? from : "";
      },
    };
  }
  if (names.includes("mailgw")) {
    providers.mailgw = {
      name: "mailgw",
      title: "mail.gw",
      baseUrl: env(context, "PROVIDER_MAILGW_BASE", "https://api.mail.gw").replace(/\/$/, ""),
      fromExtractor(message) {
        const from = message.from;
        if (Array.isArray(from)) return from.length ? String(from[0]) : "";
        if (from && typeof from === "object") return String(from.address ?? from.name ?? "");
        return typeof from === "string" ? from : "";
      },
    };
  }
  if (names.includes("linshiyouxiang")) {
    providers.linshiyouxiang = {
      name: "linshiyouxiang",
      title: "linshiyouxiang",
      baseUrl: env(context, "PROVIDER_LINSHI_BASE", "https://www.linshiyouxiang.net").replace(/\/$/, ""),
      sessionTtlMs: envPositiveInt(context, "LINSHI_SESSION_TTL_MS", 3_000_000),
      maxDetailFetch: envNonNegativeInt(context, "LINSHI_MAX_DETAIL_FETCH", 0),
    };
  }
  return providers;
}

function normalizeProviderName(value) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(normalized)) {
    throw new HttpError(400, "Provider name may only contain lowercase letters, digits, underscores, and hyphens.");
  }
  return normalized;
}

function normalizeProviderUrl(value) {
  const url = String(value ?? "").trim();
  if (!/^https?:\/\//i.test(url)) {
    throw new HttpError(400, "Provider URL must start with http:// or https://");
  }
  return url.replace(/\/+$/, "");
}

function parseConfigBoolean(value) {
  return ["1", "true", "yes", "on", "disabled"].includes(String(value ?? "").trim().toLowerCase());
}

function providerDisabledConfigKey(name) {
  return `PROVIDER_DISABLED_${String(name).trim().toUpperCase()}`;
}

async function getResolvedConfigValue(kv, context, name, fallback = "") {
  const fromEnv = context.env && context.env[name];
  if (fromEnv !== undefined && fromEnv !== null && String(fromEnv) !== "") {
    return { key: name, value: String(fromEnv), source: "env", locked: true };
  }
  const fromKv = await getConfigValue(kv, name);
  if (fromKv !== null && fromKv !== "") {
    return { key: name, value: String(fromKv), source: "kv", locked: false };
  }
  return { key: name, value: fallback, source: "fallback", locked: false };
}

async function resolveProviderSecret(kv, context) {
  return await getResolvedConfigValue(kv, context, "PROVIDER_SECRET", "");
}

async function resolveDefaultProviderConfig(kv, context) {
  return await getResolvedConfigValue(kv, context, "DEFAULT_PROVIDER", "mailtm");
}

async function listDynamicProviders(kv) {
  const keys = await kvListKeys(kv, "provider_config:");
  const records = await Promise.all(keys.map((key) => kvGetJson(kv, key)));
  return records.filter(Boolean).sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

async function assembleAllProviders(context, kv) {
  const providers = parseProviderList(context);
  const kvDynamicProviders = await listDynamicProviders(kv);
  for (const provider of kvDynamicProviders) {
    if (!provider || typeof provider.name !== "string" || typeof provider.url !== "string") continue;
    if (!providers[provider.name]) {
      providers[provider.name] = {
        name: provider.name,
        title: provider.name,
        kind: "remote",
        url: provider.url,
        source: "kv",
      };
    }
  }
  const rows = [];
  for (const provider of Object.values(providers)) {
    const disabledResolved = await getResolvedConfigValue(
      kv,
      context,
      providerDisabledConfigKey(provider.name),
      "",
    );
    rows.push({
      ...provider,
      disabled: parseConfigBoolean(disabledResolved.value),
      disabledSource: disabledResolved.source,
      disableLocked: disabledResolved.locked,
    });
  }
  return rows.reduce((acc, row) => {
    acc[row.name] = row;
    return acc;
  }, {});
}

async function assembleProviders(context, kv) {
  const rows = Object.values(await assembleAllProviders(context, kv));
  return rows.reduce((acc, row) => {
    if (!row.disabled) acc[row.name] = row;
    return acc;
  }, {});
}

async function getConfigValue(kv, name) {
  return await kvGetText(kv, keyForConfig(name));
}

async function setConfigValue(kv, name, value) {
  await kv.put(keyForConfig(name), value);
}

async function deleteConfigValue(kv, name) {
  await kvDelete(kv, keyForConfig(name));
}

async function getDefaultProviderName(kv, context, providers) {
  const fromKv = (await getConfigValue(kv, "DEFAULT_PROVIDER") || "").trim().toLowerCase();
  if (fromKv && providers[fromKv]) return fromKv;
  const configured = env(context, "DEFAULT_PROVIDER", "mailtm").trim().toLowerCase();
  if (configured && providers[configured]) return configured;
  return Object.keys(providers)[0] || "";
}

async function listProviderEntries(kv, context, providers) {
  const allProviders = await assembleAllProviders(context, kv);
  const defaultProvider = await getDefaultProviderName(kv, context, allProviders);
  const entries = Object.values(allProviders).map((provider) => ({
    name: provider.name,
    type: provider.kind === "remote" ? "remote" : "builtin",
    target: provider.kind === "remote" ? provider.url : (provider.baseUrl || ""),
    isDefault: provider.name === defaultProvider,
    disabled: Boolean(provider.disabled),
    disabledSource: provider.disabledSource || "fallback",
    disableLocked: Boolean(provider.disableLocked),
    source: provider.source || (provider.kind === "remote" ? "kv" : "env"),
  }));
  return entries
    .map((provider) => ({
      ...provider,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function countedFetch(state, url, init) {
  const response = await fetch(url, init);
  state.upstreamCalls += 1;
  return response;
}

function parseHydraMembers(raw) {
  if (Array.isArray(raw)) return raw;
  if (raw && typeof raw === "object" && Array.isArray(raw["hydra:member"])) return raw["hydra:member"];
  return [];
}

async function loadAccount(kv, provider, email) {
  const record = await kvGetJson(kv, keyForAccount(provider, email));
  if (!record) return null;
  if (typeof record.expiresAt === "number" && record.expiresAt <= Date.now()) {
    await kvDelete(kv, keyForAccount(provider, email));
    return null;
  }
  return record;
}

async function saveAccount(kv, provider, account, ttlMs) {
  await kvPutJson(kv, keyForAccount(provider, account.address), {
    ...account,
    expiresAt: Date.now() + ttlMs,
  });
}

async function saveSessionOwner(kv, email, provider) {
  await kvPutJson(kv, keyForSessionOwner(email), {
    provider,
    expiresAt: Date.now() + ACCOUNT_TTL_MS,
  });
}

async function loadSessionOwner(kv, email) {
  const record = await kvGetJson(kv, keyForSessionOwner(email));
  if (!record) return null;
  if (typeof record.expiresAt === "number" && record.expiresAt <= Date.now()) {
    await kvDelete(kv, keyForSessionOwner(email));
    return null;
  }
  return typeof record.provider === "string" ? record.provider : null;
}

async function saveMailMap(kv, mailId, email, provider) {
  await kvPutJson(kv, keyForMailMap(mailId), {
    email,
    provider,
    expiresAt: Date.now() + MAIL_MAP_TTL_MS,
  });
}

async function loadMailMap(kv, mailId) {
  const record = await kvGetJson(kv, keyForMailMap(mailId));
  if (!record) return null;
  if (typeof record.expiresAt === "number" && record.expiresAt <= Date.now()) {
    await kvDelete(kv, keyForMailMap(mailId));
    return null;
  }
  return typeof record.email === "string" && typeof record.provider === "string" ? record : null;
}

async function listApiKeys(kv) {
  const keys = await kvListKeys(kv, "api_key:");
  const records = await Promise.all(keys.map((key) => kvGetJson(kv, key)));
  return records.filter(Boolean).sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
}

async function createApiKey(kv, label) {
  const rawKey = `sk-${randomHex(16)}`;
  const id = `${Date.now().toString(36)}-${randomHex(4)}`;
  const keyHash = await sha256Hex(rawKey);
  const now = Date.now();
  const record = { id, label, keyHash, status: "active", createdAt: now, updatedAt: now };
  await kvPutJson(kv, keyForApiKey(id), record);
  await kv.put(keyForApiKeyHash(keyHash), id);
  return { record, rawKey };
}

async function updateApiKeyStatus(kv, id, status) {
  const record = await kvGetJson(kv, keyForApiKey(id));
  if (!record) throw new HttpError(404, "API Key 不存在。");
  record.status = status;
  record.updatedAt = Date.now();
  await kvPutJson(kv, keyForApiKey(id), record);
}

async function deleteApiKey(kv, id) {
  const record = await kvGetJson(kv, keyForApiKey(id));
  if (!record) throw new HttpError(404, "API Key 不存在。");
  await kvDelete(kv, keyForApiKey(id));
  if (record.keyHash) await kvDelete(kv, keyForApiKeyHash(record.keyHash));
}

async function authenticateApiRequest(kv, request) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  const token = match && match[1] ? match[1].trim() : "";
  if (!token) throw new HttpError(401, "Missing API key.");
  const hash = await sha256Hex(token);
  const keyId = await kvGetText(kv, keyForApiKeyHash(hash));
  if (!keyId) throw new HttpError(401, "Invalid API key.");
  const record = await kvGetJson(kv, keyForApiKey(keyId));
  if (!record) throw new HttpError(401, "Invalid API key.");
  if (record.status !== "active") throw new HttpError(403, "API key is disabled.");
  return record;
}

function randomMailboxPrefix(length = 8) {
  return randomHex(Math.ceil(length / 2)).slice(0, length);
}

function randomMailboxPassword(length = 16) {
  return randomHex(Math.ceil(length / 2)).slice(0, length);
}

async function fetchHydraDomains(state, provider) {
  const response = await countedFetch(state, `${provider.baseUrl}/domains`, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw new HttpError(502, `无法读取 ${provider.title} 域名列表。`);
  const raw = await response.json();
  const domains = parseHydraMembers(raw)
    .filter((item) => item && item.isActive !== false && item.domain)
    .map((item) => String(item.domain));
  if (!domains.length) throw new HttpError(502, `${provider.title} 当前没有可用域名。`);
  return domains;
}

async function createHydraAccount(state, provider, address, password) {
  const response = await countedFetch(state, `${provider.baseUrl}/accounts`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ address, password }),
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new HttpError(502, `${provider.title} 创建邮箱失败: ${response.status} ${detail}`.trim());
  }
  const json = await response.json();
  return { id: String(json.id), address: String(json.address) };
}

async function fetchHydraToken(state, provider, address, password) {
  const response = await countedFetch(state, `${provider.baseUrl}/token`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ address, password }),
  });
  if (!response.ok) throw new HttpError(502, `${provider.title} 获取 Token 失败。`);
  const json = await response.json();
  if (!json || typeof json.token !== "string" || !json.token) {
    throw new HttpError(502, `${provider.title} 返回了空 Token。`);
  }
  return json.token;
}

function hydraAuthHeaders(token) {
  return { accept: "application/json", authorization: `Bearer ${token}` };
}

async function getValidHydraToken(kv, state, provider, account) {
  if (Date.now() - Number(account.tokenIssuedAt || 0) < TOKEN_REFRESH_INTERVAL_MS) return account.token;
  const token = await fetchHydraToken(state, provider, account.address, account.password);
  account.token = token;
  account.tokenIssuedAt = Date.now();
  account.updatedAt = Date.now();
  await saveAccount(kv, provider.name, account, ACCOUNT_TTL_MS);
  return token;
}

function mapHydraMessage(provider, message, email) {
  return {
    id: String(message.id),
    email_address: email,
    from_address: provider.fromExtractor(message),
    subject: String(message.subject ?? ""),
    content: String(message.text ?? ""),
    html_content: Array.isArray(message.html) ? message.html.join("") : String(message.html ?? ""),
  };
}

async function hydraGenerateEmail(kv, state, provider, payload) {
  const domains = await fetchHydraDomains(state, provider);
  const prefix = typeof payload.prefix === "string" && payload.prefix.trim()
    ? payload.prefix.trim()
    : randomMailboxPrefix();
  const domain = typeof payload.domain === "string" && payload.domain.trim()
    ? payload.domain.trim()
    : domains[Math.floor(Math.random() * domains.length)];
  if (!domains.includes(domain)) {
    throw new HttpError(400, `Provider ${provider.name} 不支持域名 ${domain}。`);
  }
  const address = `${prefix}@${domain}`;
  const password = randomMailboxPassword();
  const accountInfo = await createHydraAccount(state, provider, address, password);
  const token = await fetchHydraToken(state, provider, address, password);
  const account = {
    id: accountInfo.id,
    address,
    password,
    token,
    tokenIssuedAt: Date.now(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  await saveAccount(kv, provider.name, account, ACCOUNT_TTL_MS);
  await saveSessionOwner(kv, address, provider.name);
  return { email: address, provider: provider.name };
}

async function hydraListEmails(kv, state, provider, email) {
  const account = await loadAccount(kv, provider.name, email);
  if (!account) throw new HttpError(404, `邮箱 ${email} 在 provider ${provider.name} 上没有有效会话。`);
  const token = await getValidHydraToken(kv, state, provider, account);
  const requestOnce = async (authToken) =>
    countedFetch(state, `${provider.baseUrl}/messages?page=1`, {
      method: "GET",
      headers: hydraAuthHeaders(authToken),
    });
  let response = await requestOnce(token);
  if (response.status === 401) {
    const freshToken = await fetchHydraToken(state, provider, account.address, account.password);
    account.token = freshToken;
    account.tokenIssuedAt = Date.now();
    account.updatedAt = Date.now();
    await saveAccount(kv, provider.name, account, ACCOUNT_TTL_MS);
    response = await requestOnce(freshToken);
  }
  if (!response.ok) throw new HttpError(502, `读取 ${provider.title} 邮件列表失败。`);
  const raw = await response.json();
  const emails = parseHydraMembers(raw).map((message) => mapHydraMessage(provider, message, email));
  await Promise.all(emails.map((message) => saveMailMap(kv, message.id, email, provider.name)));
  return { emails, count: emails.length, provider: provider.name };
}

async function hydraGetEmail(kv, state, provider, email, mailId) {
  const account = await loadAccount(kv, provider.name, email);
  if (!account) throw new HttpError(404, `邮箱 ${email} 在 provider ${provider.name} 上没有有效会话。`);
  const token = await getValidHydraToken(kv, state, provider, account);
  const response = await countedFetch(state, `${provider.baseUrl}/messages/${encodeURIComponent(mailId)}`, {
    method: "GET",
    headers: hydraAuthHeaders(token),
  });
  if (!response.ok) throw new HttpError(response.status === 404 ? 404 : 502, `读取邮件 ${mailId} 失败。`);
  const raw = await response.json();
  const record = mapHydraMessage(provider, raw, email);
  await saveMailMap(kv, record.id, email, provider.name);
  return record;
}

async function hydraDeleteEmail(kv, state, provider, email, mailId) {
  const account = await loadAccount(kv, provider.name, email);
  if (!account) throw new HttpError(404, `邮箱 ${email} 在 provider ${provider.name} 上没有有效会话。`);
  const token = await getValidHydraToken(kv, state, provider, account);
  const response = await countedFetch(state, `${provider.baseUrl}/messages/${encodeURIComponent(mailId)}`, {
    method: "DELETE",
    headers: hydraAuthHeaders(token),
  });
  if (!response.ok && response.status !== 204) {
    throw new HttpError(response.status === 404 ? 404 : 502, `删除邮件 ${mailId} 失败。`);
  }
  await kvDelete(kv, keyForMailMap(mailId));
  return { message: "Deleted email.", provider: provider.name };
}

async function hydraClearEmails(kv, state, provider, email) {
  const list = await hydraListEmails(kv, state, provider, email);
  let deleted = 0;
  for (const message of list.emails) {
    await hydraDeleteEmail(kv, state, provider, email, message.id);
    deleted += 1;
  }
  return { message: "Cleared emails.", count: deleted, provider: provider.name };
}

function mergeSetCookies(existing, headers) {
  const merged = { ...existing };
  let rawCookies = [];
  try {
    const getSetCookie = headers.getSetCookie;
    rawCookies = typeof getSetCookie === "function" ? getSetCookie.call(headers) : [];
  } catch {
    rawCookies = [];
  }
  if (!rawCookies.length) {
    const raw = headers.get("set-cookie");
    if (raw) rawCookies = raw.split(/,(?=\s*\w+=)/);
  }
  for (const raw of rawCookies) {
    const eqIdx = raw.indexOf("=");
    if (eqIdx <= 0) continue;
    const name = raw.slice(0, eqIdx).trim();
    const rest = raw.slice(eqIdx + 1);
    const semiIdx = rest.indexOf(";");
    const value = semiIdx >= 0 ? rest.slice(0, semiIdx).trim() : rest.trim();
    merged[name] = value;
  }
  return merged;
}

function serializeCookies(cookies) {
  return Object.entries(cookies).map(([key, value]) => `${key}=${value}`).join("; ");
}

function linshiBuildHeaders(provider, cookies, extra = {}) {
  const headers = new Headers({
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
    origin: provider.baseUrl,
    referer: `${provider.baseUrl}/`,
  });
  for (const [key, value] of new Headers(extra).entries()) headers.set(key, value);
  if (Object.keys(cookies).length) headers.set("cookie", serializeCookies(cookies));
  return headers;
}

async function loadLinshiMailMeta(kv, email, mailId) {
  return await kvGetJson(kv, keyForLinshiMailMeta(email, mailId));
}

async function saveLinshiMailMeta(kv, email, mailId, value) {
  await kvPutJson(kv, keyForLinshiMailMeta(email, mailId), value);
}

async function linshiFetchHome(state, provider, cookies) {
  const response = await countedFetch(state, `${provider.baseUrl}/`, {
    method: "GET",
    headers: linshiBuildHeaders(provider, cookies),
  });
  const html = await response.text();
  const mergedCookies = mergeSetCookies(cookies, response.headers);
  const match = html.match(/window\.mailCodeGlobal\s*=\s*['"]([a-f0-9]+)['"]/i);
  if (!response.ok || !match || !match[1]) {
    throw new HttpError(502, "Failed to initialize linshiyouxiang session.");
  }
  return { html, cookies: mergedCookies, mailCode: match[1] };
}

async function linshiInitSession(state, provider) {
  const result = await linshiFetchHome(state, provider, {});
  return { cookies: result.cookies, mailCode: result.mailCode };
}

async function linshiGetGmail(state, provider, cookies) {
  const template = Math.random() < 0.5 ? "a.b.c@gmail.com" : "abc+hello@gmail.com";
  const response = await countedFetch(state, `${provider.baseUrl}/change-to-gmail`, {
    method: "POST",
    headers: linshiBuildHeaders(provider, cookies, {
      "content-type": "application/json",
      accept: "application/json, text/plain, */*",
      "X-Requested-With": "XMLHttpRequest",
    }),
    body: JSON.stringify({ type: "gmail_alias", template }),
  });
  let json;
  try {
    json = await response.json();
  } catch {
    throw new HttpError(502, "Linshiyouxiang upstream returned invalid JSON.");
  }
  const email = typeof json.email === "string" ? json.email : null;
  if (!response.ok || !email) {
    throw new HttpError(502, "Failed to generate linshiyouxiang Gmail alias.");
  }
  return { email, cookies: mergeSetCookies(cookies, response.headers) };
}

async function linshiRefreshMessages(state, provider, session) {
  let nextSession = { ...session };
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await countedFetch(state, `${provider.baseUrl}/get-messages?lang=zh`, {
      method: "POST",
      headers: linshiBuildHeaders(provider, nextSession.cookies, {
        "content-type": "application/json",
        accept: "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
      }),
      body: JSON.stringify({ email: nextSession.email, code: nextSession.mailCode }),
    });
    let json = null;
    try {
      json = await response.json();
    } catch {
      json = null;
    }
    nextSession = { ...nextSession, cookies: mergeSetCookies(nextSession.cookies, response.headers), updatedAt: Date.now() };
    if (response.ok && json && json.success === true) return nextSession;
    if (response.status !== 400 || attempt > 0) {
      throw new HttpError(502, "Failed to refresh linshiyouxiang inbox.");
    }
    const refreshed = await linshiFetchHome(state, provider, nextSession.cookies);
    nextSession = { ...nextSession, cookies: refreshed.cookies, mailCode: refreshed.mailCode, updatedAt: Date.now() };
  }
  throw new HttpError(502, "Failed to refresh linshiyouxiang inbox.");
}

function decodeHtmlEntities(value) {
  return String(value ?? "")
    .replaceAll("&nbsp;", " ")
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'");
}

function stripTags(html) {
  return decodeHtmlEntities(
    String(html ?? "")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/p>/gi, "\n")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+\n/g, "\n")
      .replace(/\n\s+/g, "\n")
      .replace(/[ \t]{2,}/g, " ")
      .trim(),
  );
}

function stripHtmlFragmentTags(html) {
  return stripTags(String(html ?? "").replace(/<[^>]+>/g, " ").trim());
}

function linshiParseMailList(html) {
  const tbodyMatch = html.match(/<tbody[^>]*id=["']message-list["'][^>]*>([\s\S]*?)<\/tbody>/i);
  const section = tbodyMatch ? tbodyMatch[1] : html;
  const rowMatches = section.match(/<tr\b[\s\S]*?<\/tr>/gi) || [];
  const results = [];
  for (const rowHtml of rowMatches) {
    if (/id=["']loading-row["']/i.test(rowHtml)) continue;
    const hrefMatch = rowHtml.match(/href=["'][^"']*\/mail\/view\/([a-f0-9]+)(?:\/(\w+))?[^"']*["']/i);
    if (!hrefMatch) continue;
    const cells = Array.from(rowHtml.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/gi)).map((match) => match[1]);
    if (cells.length < 3) continue;
    const timeMatch = cells[2].match(/<a\b[^>]*class=["'][^"']*receiveTime[^"']*["'][^>]*>([\s\S]*?)<\/a>/i);
    results.push({
      id: hrefMatch[1],
      type: hrefMatch[2] || "",
      sender: stripHtmlFragmentTags(cells[0]),
      subject: stripHtmlFragmentTags(cells[1]),
      timestamp: stripHtmlFragmentTags(timeMatch ? timeMatch[1] : cells[2]),
    });
  }
  return results;
}

async function linshiGetMailContent(state, provider, session, mailId) {
  const response = await countedFetch(state, `${provider.baseUrl}/mail/gmail-content/${encodeURIComponent(mailId)}`, {
    method: "GET",
    headers: linshiBuildHeaders(provider, session.cookies, {
      accept: "application/json, text/plain, */*",
      "X-Requested-With": "XMLHttpRequest",
    }),
  });
  let json;
  try {
    json = await response.json();
  } catch {
    throw new HttpError(502, "Linshiyouxiang upstream returned invalid mail detail JSON.");
  }
  const result = json && typeof json.result === "object" ? json.result : null;
  const html = result && typeof result.content === "string" ? result.content : null;
  if (!response.ok || html === null) {
    throw new HttpError(502, "Failed to fetch linshiyouxiang mail content.");
  }
  return {
    html,
    session: {
      ...session,
      cookies: mergeSetCookies(session.cookies, response.headers),
      updatedAt: Date.now(),
    },
  };
}

function linshiHtmlToText(html) {
  return stripTags(html);
}

async function refreshAndCacheLinshiMailList(kv, state, provider, session, email) {
  const refreshedSession = await linshiRefreshMessages(state, provider, session);
  const home = await linshiFetchHome(state, provider, refreshedSession.cookies);
  const nextSession = {
    ...refreshedSession,
    cookies: home.cookies,
    mailCode: home.mailCode,
    updatedAt: Date.now(),
  };
  const rawList = linshiParseMailList(home.html);
  await Promise.all(
    rawList.map((item) =>
      saveLinshiMailMeta(kv, email, item.id, {
        sender: item.sender,
        subject: item.subject,
        timestamp: item.timestamp,
      })),
  );
  await saveAccount(kv, provider.name, { ...nextSession, address: nextSession.email }, provider.sessionTtlMs);
  return { session: nextSession, rawList };
}

async function linshiGenerateEmail(kv, state, provider, payload) {
  if (payload.prefix || payload.domain) {
    throw new HttpError(400, "The linshiyouxiang provider does not support prefix or domain options.");
  }
  const initial = await linshiInitSession(state, provider);
  const gmail = await linshiGetGmail(state, provider, initial.cookies);
  const refreshed = await linshiFetchHome(state, provider, gmail.cookies);
  const session = {
    cookies: refreshed.cookies,
    mailCode: refreshed.mailCode,
    email: gmail.email,
    address: gmail.email,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  await saveAccount(kv, provider.name, session, provider.sessionTtlMs);
  await saveSessionOwner(kv, gmail.email, provider.name);
  return { email: gmail.email, provider: provider.name };
}

async function linshiListEmails(kv, state, provider, email) {
  const session = await loadAccount(kv, provider.name, email);
  if (!session) {
    throw new HttpError(404, "No active session for this email. Generate it first with provider=linshiyouxiang.");
  }
  const { session: nextSession, rawList } = await refreshAndCacheLinshiMailList(kv, state, provider, session, email);
  const limit = provider.maxDetailFetch > 0 ? Math.min(provider.maxDetailFetch, rawList.length) : rawList.length;
  const emails = [];
  let workingSession = nextSession;
  for (let index = 0; index < rawList.length; index += 1) {
    const item = rawList[index];
    if (index < limit) {
      const detail = await linshiGetMailContent(state, provider, workingSession, item.id);
      workingSession = detail.session;
      emails.push({
        id: item.id,
        email_address: email,
        from_address: item.sender,
        subject: item.subject,
        content: linshiHtmlToText(detail.html),
        html_content: detail.html,
      });
    } else {
      emails.push({
        id: item.id,
        email_address: email,
        from_address: item.sender,
        subject: item.subject,
        content: "",
        html_content: "",
      });
    }
  }
  await saveAccount(kv, provider.name, { ...workingSession, address: workingSession.email }, provider.sessionTtlMs);
  await Promise.all(emails.map((message) => saveMailMap(kv, message.id, email, provider.name)));
  return { emails, count: rawList.length, provider: provider.name };
}

async function linshiGetEmail(kv, state, provider, email, mailId) {
  let session = await loadAccount(kv, provider.name, email);
  if (!session) throw new HttpError(404, "No active session for this email.");
  const detail = await linshiGetMailContent(state, provider, session, mailId);
  session = detail.session;
  let meta = await loadLinshiMailMeta(kv, email, mailId);
  if (!meta) {
    const refreshed = await refreshAndCacheLinshiMailList(kv, state, provider, session, email);
    session = refreshed.session;
    meta = await loadLinshiMailMeta(kv, email, mailId);
  }
  await saveAccount(kv, provider.name, { ...session, address: session.email }, provider.sessionTtlMs);
  await saveMailMap(kv, mailId, email, provider.name);
  return {
    id: mailId,
    email_address: email,
    from_address: meta && meta.sender ? meta.sender : "",
    subject: meta && meta.subject ? meta.subject : "",
    content: linshiHtmlToText(detail.html),
    html_content: detail.html,
  };
}

async function linshiDeleteEmail() {
  throw new HttpError(501, "The linshiyouxiang provider does not support single email deletion.");
}

async function linshiClearEmails() {
  throw new HttpError(501, "The linshiyouxiang provider does not support clearing emails.");
}

async function callRemoteProvider(state, provider, request, routePath, providerSecret = "") {
  const headers = {
    accept: "application/json",
    "content-type": request.headers.get("content-type") || "application/json",
  };
  if (providerSecret) headers.authorization = `Bearer ${providerSecret}`;
  const response = await countedFetch(state, `${provider.url}${routePath}`, {
    method: request.method,
    headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.text(),
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const message = payload && payload.error ? payload.error : `Remote provider failed: ${response.status}`;
    throw new HttpError(response.status, message);
  }
  if (payload && typeof payload._upstream_calls === "number") {
    state.upstreamCalls += Number(payload._upstream_calls);
  }
  return payload;
}

async function remoteGenerateEmail(kv, state, provider, payload, providerSecret = "") {
  const response = await countedFetch(state, `${provider.url}/generate-email`, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      ...(providerSecret ? { authorization: `Bearer ${providerSecret}` } : {}),
    },
    body: JSON.stringify(payload || {}),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data || data.success !== true) {
    throw new HttpError(response.status || 502, data && data.error ? data.error : "Remote provider generate-email failed.");
  }
  if (typeof data._upstream_calls === "number") {
    state.upstreamCalls += Number(data._upstream_calls);
  }
  const email = data.data && typeof data.data.email === "string" ? data.data.email : null;
  if (!email) throw new HttpError(502, "Remote provider did not return email.");
  await saveSessionOwner(kv, email, provider.name);
  return { ...data.data, provider: provider.name };
}

async function remoteListEmails(kv, state, provider, email, providerSecret = "") {
  const payload = await callRemoteProvider(
    state,
    provider,
    new Request("http://local", { method: "GET" }),
    `/emails?email=${encodeURIComponent(email)}`,
    providerSecret,
  );
  const data = payload && payload.data ? payload.data : null;
  const emails = data && Array.isArray(data.emails) ? data.emails : [];
  await Promise.all(emails.map((message) => saveMailMap(kv, message.id, email, provider.name)));
  await saveSessionOwner(kv, email, provider.name);
  return { ...(data || {}), provider: provider.name };
}

async function remoteGetEmail(kv, state, provider, email, mailId, providerSecret = "") {
  const payload = await callRemoteProvider(
    state,
    provider,
    new Request("http://local", { method: "GET" }),
    `/email/${encodeURIComponent(mailId)}?email=${encodeURIComponent(email)}`,
    providerSecret,
  );
  const data = payload && payload.data ? payload.data : null;
  if (!data) throw new HttpError(502, "Remote provider did not return email detail.");
  await saveMailMap(kv, mailId, email, provider.name);
  return data;
}

async function remoteDeleteEmail(kv, state, provider, email, mailId, providerSecret = "") {
  const payload = await callRemoteProvider(
    state,
    provider,
    new Request("http://local", { method: "DELETE" }),
    `/email/${encodeURIComponent(mailId)}?email=${encodeURIComponent(email)}`,
    providerSecret,
  );
  await kvDelete(kv, keyForMailMap(mailId));
  return payload && payload.data ? payload.data : { message: "Deleted email." };
}

async function remoteClearEmails(_kv, state, provider, email, providerSecret = "") {
  const payload = await callRemoteProvider(
    state,
    provider,
    new Request("http://local", { method: "DELETE" }),
    `/emails/clear?email=${encodeURIComponent(email)}`,
    providerSecret,
  );
  return payload && payload.data ? payload.data : { message: "Cleared emails." };
}

async function testProviderConnection(state, provider, providerSecret = "") {
  try {
    if (provider.kind === "remote") {
      const response = await countedFetch(state, `${provider.url}/generate-email`, {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          ...(providerSecret ? { authorization: `Bearer ${providerSecret}` } : {}),
        },
        body: "{}",
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload || payload.success !== true) {
        return { ok: false, status: response.status, error: payload && payload.error ? payload.error : "Remote provider check failed." };
      }
      return { ok: true, email: payload.data && payload.data.email ? payload.data.email : "", latencyMs: 0 };
    }
    const startedAt = Date.now();
    const result = provider.name === "linshiyouxiang"
      ? await linshiGenerateEmail(getKv(), state, provider, {})
      : await hydraGenerateEmail(getKv(), state, provider, {});
    return { ok: true, email: result.email || "", latencyMs: Date.now() - startedAt };
  } catch (error) {
    return {
      ok: false,
      status: error instanceof HttpError ? error.status : 500,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function assertAdminConfigured(context) {
  if (!env(context, "ADMIN_PASSWORD")) throw new HttpError(500, "缺少 ADMIN_PASSWORD。");
  if (!env(context, "ADMIN_COOKIE_SECRET")) throw new HttpError(500, "缺少 ADMIN_COOKIE_SECRET。");
}

function requireSameOrigin(request, url) {
  const origin = request.headers.get("origin");
  if (origin && origin !== url.origin) throw new HttpError(403, "Invalid origin.");
}

async function requireAdmin(context, request) {
  assertAdminConfigured(context);
  const cookies = parseCookies(request.headers.get("cookie"));
  const session = await verifyAdminSession(env(context, "ADMIN_COOKIE_SECRET"), cookies.tmpmail_admin);
  if (!session) throw new HttpError(401, "请先登录。");
  return session;
}

async function resolveProviderForMailbox(kv, providers, email, explicitProvider) {
  if (explicitProvider && providers[explicitProvider]) return providers[explicitProvider];
  const owner = await loadSessionOwner(kv, email);
  if (owner && providers[owner]) return providers[owner];
  for (const providerName of Object.keys(providers)) {
    const account = await loadAccount(kv, providerName, email);
    if (account) return providers[providerName];
  }
  return null;
}

async function resolveMailRouteTarget(kv, providers, mailId, email, explicitProvider) {
  if (email) {
    const provider = await resolveProviderForMailbox(kv, providers, email, explicitProvider);
    if (!provider) throw new HttpError(404, "找不到该邮箱对应的 provider。");
    return { email, provider };
  }
  const mapping = await loadMailMap(kv, mailId);
  if (!mapping) throw new HttpError(404, "缺少 email 参数，且当前 mailId 没有缓存映射。");
  const provider = providers[mapping.provider];
  if (!provider) throw new HttpError(404, "mailId 对应的 provider 不可用。");
  return { email: mapping.email, provider };
}

function renderLayout({ title, body, nav = "", subtitle = "" }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} | ${APP_NAME}</title>
  <style>
    :root {
      --bg: #f3efe6;
      --panel: rgba(255,255,255,0.82);
      --line: rgba(27,41,53,0.12);
      --text: #17212b;
      --muted: #5e6a74;
      --brand: #b84f2f;
      --accent: #0f7b6c;
      --shadow: 0 24px 60px rgba(41,53,65,0.12);
      --radius: 22px;
      --mono: "SFMono-Regular", Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(184,79,47,0.18), transparent 26%),
        radial-gradient(circle at 85% 15%, rgba(15,123,108,0.16), transparent 24%),
        linear-gradient(180deg, #f7f3ea 0%, #efe7d8 100%);
      min-height: 100vh;
    }
    .shell { max-width: 1120px; margin: 0 auto; padding: 28px 18px 64px; }
    .hero, .card {
      backdrop-filter: blur(14px);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
    }
    .hero { padding: 28px; margin-bottom: 22px; }
    .eyebrow {
      display: inline-flex;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.72);
      color: var(--brand);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1, h2 { margin: 0 0 12px; }
    h1 { font-size: clamp(32px, 5vw, 54px); line-height: 1.04; }
    h2 { font-size: 24px; }
    p { margin: 0 0 14px; color: var(--muted); line-height: 1.66; }
    .nav, .row-actions { display: flex; flex-wrap: wrap; gap: 12px; }
    .nav { margin-top: 18px; }
    .nav a, .button, button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      background: var(--brand);
      color: #fff;
      padding: 12px 18px;
      font: inherit;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
    }
    .secondary { background: rgba(23,33,43,0.08) !important; color: var(--text) !important; }
    .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 18px; }
    .span-12 { grid-column: span 12; }
    .span-8 { grid-column: span 8; }
    .span-6 { grid-column: span 6; }
    .span-4 { grid-column: span 4; }
    .card { padding: 22px; }
    .metric { display: grid; gap: 6px; }
    .metric strong { font-size: 28px; line-height: 1; }
    .flash { padding: 14px 16px; border-radius: 16px; margin-bottom: 16px; }
    .flash.success { background: rgba(15,123,108,0.12); color: #0c5b50; }
    .flash.error { background: rgba(180,35,24,0.1); color: #7a1d15; }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 6px; font-size: 14px; font-weight: 600; }
    input {
      width: 100%;
      border-radius: 14px;
      border: 1px solid rgba(23,33,43,0.14);
      padding: 12px 14px;
      background: rgba(255,255,255,0.92);
      font: inherit;
    }
    code, pre { font-family: var(--mono); }
    pre {
      margin: 0;
      padding: 16px;
      border-radius: 18px;
      background: #15202b;
      color: #edf4fa;
      overflow: auto;
      font-size: 13px;
      line-height: 1.55;
    }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td {
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid rgba(23,33,43,0.08);
      vertical-align: top;
    }
    .tag {
      display: inline-block;
      padding: 4px 10px;
      margin: 0 8px 8px 0;
      border-radius: 999px;
      background: rgba(15,123,108,0.1);
      color: var(--accent);
      font-size: 13px;
      font-weight: 700;
    }
    .muted { color: var(--muted); }
    .subtle { margin-top: 6px; font-size: 13px; color: var(--muted); }
    .footer { margin-top: 24px; font-size: 13px; color: var(--muted); }
    @media (max-width: 900px) { .span-8, .span-6, .span-4 { grid-column: span 12; } }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="eyebrow">${escapeHtml(subtitle || "EdgeOne 版临时邮箱网关")}</div>
      <h1>${escapeHtml(title)}</h1>
      ${nav ? `<div class="nav">${nav}</div>` : ""}
    </section>
    ${body}
    <div class="footer">EdgeOne Edge Functions + KV Storage 版本，入口已收敛为单函数部署。</div>
  </main>
</body>
</html>`;
}

function formatDateTime(timestamp) {
  if (!timestamp) return "—";
  try {
    return new Date(timestamp).toLocaleString("zh-CN", { hour12: false });
  } catch {
    return "—";
  }
}

async function buildStats(kv, providers) {
  const keys = await listApiKeys(kv);
  return {
    activeApiKeys: keys.filter((record) => record.status === "active").length,
    totalUpstreamCalls: await getNumberMetric(kv, keyForMetric("upstream_calls_total")),
    todayUpstreamCalls: await getNumberMetric(kv, keyForMetricDay("upstream_calls", utcDayStamp())),
    providers: Object.keys(providers),
    defaultProvider: "",
  };
}

function renderDocsPage(context, providers, stats) {
  const providerTags = Object.values(providers).map((provider) => `<span class="tag">${escapeHtml(provider.name)}</span>`).join("");
  const defaultProvider = stats.defaultProvider || "";
  const body = `
    <section class="grid">
      <div class="card span-4"><div class="metric"><span class="muted">已启用 Provider</span><strong>${Object.keys(providers).length}</strong><span class="subtle">默认值：${escapeHtml(defaultProvider || "未配置")}</span></div></div>
      <div class="card span-4"><div class="metric"><span class="muted">活跃 API Keys</span><strong>${stats.activeApiKeys}</strong><span class="subtle">通过后台创建与禁用</span></div></div>
      <div class="card span-4"><div class="metric"><span class="muted">累计上游调用</span><strong>${stats.totalUpstreamCalls}</strong><span class="subtle">今日：${stats.todayUpstreamCalls}</span></div></div>
      <div class="card span-8">
        <h2>项目说明</h2>
        <p>这个版本专门为 EdgeOne Pages 重构，入口位于 <code>edge-functions/[[default]].js</code>。原来的 Deno 多服务架构被收敛成一个 Edge Function，管理页、文档页和 API 都在同一个函数里完成。</p>
        <p>当前 EdgeOne 版本内置 provider：</p>
        <div>${providerTags || '<span class="tag">未配置</span>'}</div>
        <p class="subtle"><code>linshiyouxiang</code> 也已迁移到 EdgeOne 版，当前实现使用字符串解析替代 Deno DOM。</p>
      </div>
      <div class="card span-4">
        <h2>认证</h2>
        <p>所有 API 请求都需要 <code>Authorization: Bearer &lt;api-key&gt;</code>。先登录后台创建 key，再调用接口。</p>
        <p class="subtle">后台地址：<code>/admin/login</code></p>
      </div>
      <div class="card span-6">
        <h2>生成邮箱</h2>
        <pre>curl -X POST "$BASE_URL/api/generate-email" \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"provider":"${escapeHtml(defaultProvider || "mailtm")}","prefix":"demo"}'</pre>
      </div>
      <div class="card span-6">
        <h2>查询邮件列表</h2>
        <pre>curl "$BASE_URL/api/emails?email=demo@example.com" \\
  -H "Authorization: Bearer $API_KEY"</pre>
      </div>
      <div class="card span-6">
        <h2>读取单封邮件</h2>
        <pre>curl "$BASE_URL/api/email/&lt;mailId&gt;?email=demo@example.com" \\
  -H "Authorization: Bearer $API_KEY"</pre>
      </div>
      <div class="card span-6">
        <h2>清空邮箱</h2>
        <pre>curl -X DELETE "$BASE_URL/api/emails/clear?email=demo@example.com" \\
  -H "Authorization: Bearer $API_KEY"</pre>
      </div>
      <div class="card span-12">
        <h2>接口概览</h2>
        <table>
          <thead><tr><th>方法</th><th>路径</th><th>说明</th></tr></thead>
          <tbody>
            <tr><td>GET / POST</td><td>/api/generate-email</td><td>生成临时邮箱，可传 provider / prefix / domain</td></tr>
            <tr><td>GET</td><td>/api/emails</td><td>读取邮箱列表，必须传 email</td></tr>
            <tr><td>GET</td><td>/api/email/:id</td><td>读取单封邮件，建议传 email</td></tr>
            <tr><td>DELETE</td><td>/api/email/:id</td><td>删除单封邮件</td></tr>
            <tr><td>DELETE</td><td>/api/emails/clear</td><td>清空当前邮箱</td></tr>
            <tr><td>GET</td><td>/api/stats</td><td>读取 provider 与调用统计</td></tr>
          </tbody>
        </table>
      </div>
    </section>`;
  return renderLayout({
    title: "Temporary Mail API",
    subtitle: "EdgeOne 部署文档",
    nav: '<a href="/docs">文档</a><a class="secondary" href="/admin/login">管理后台</a>',
    body,
  });
}

function renderLoginPage(errorMessage) {
  const flash = errorMessage ? `<div class="flash error">${escapeHtml(errorMessage)}</div>` : "";
  const body = `
    <section class="grid">
      <div class="card span-6">
        <h2>登录后台</h2>
        <p>后台用于创建和禁用 API Key。EdgeOne 版本默认只保留最核心的运维能力，provider 配置通过环境变量完成。</p>
        ${flash}
        <form method="post" action="/admin/login">
          <label>管理员密码
            <input type="password" name="password" placeholder="输入 ADMIN_PASSWORD" required />
          </label>
          <button type="submit">登录</button>
        </form>
      </div>
      <div class="card span-6">
        <h2>部署提示</h2>
        <p>在 EdgeOne Pages 控制台启用 KV Storage，并把变量名绑定为 <code>${KV_BINDING_NAME}</code>。</p>
        <p>然后设置 <code>ADMIN_PASSWORD</code>、<code>ADMIN_COOKIE_SECRET</code>、<code>ENABLED_PROVIDERS</code>、<code>DEFAULT_PROVIDER</code> 等环境变量。</p>
      </div>
    </section>`;
  return renderLayout({
    title: "后台登录",
    subtitle: "Admin Login",
    nav: '<a href="/docs">返回文档</a>',
    body,
  });
}

function renderAdminPage({ keys, createdKey, flash, providers, stats, defaultProvider }) {
  const flashHtml = flash ? `<div class="flash ${escapeHtml(flash.tone)}">${escapeHtml(flash.message)}</div>` : "";
  const revealHtml = createdKey
    ? `<div class="flash success"><strong>新 API Key</strong><div class="subtle">只显示这一次，请马上保存。</div><pre>${escapeHtml(createdKey.rawKey)}</pre></div>`
    : "";
  const rows = keys.length
    ? keys.map((record) => `
      <tr>
        <td>${escapeHtml(record.id)}</td>
        <td>${escapeHtml(record.label)}</td>
        <td>${escapeHtml(record.status)}</td>
        <td>${escapeHtml(formatDateTime(record.createdAt))}</td>
        <td>
          <div class="row-actions">
            <form method="post" action="/admin/keys/${encodeURIComponent(record.id)}/toggle"><button class="secondary" type="submit">${record.status === "active" ? "禁用" : "启用"}</button></form>
            <form method="post" action="/admin/keys/${encodeURIComponent(record.id)}/delete" onsubmit="return confirm('确认删除这个 API Key 吗？');"><button type="submit">删除</button></form>
          </div>
        </td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="muted">还没有 API Key。</td></tr>`;
  const providerTags = providers.map((provider) => `<span class="tag">${escapeHtml(provider.name)} · ${escapeHtml(provider.type)}</span>`).join("");
  const providerRows = providers.length
    ? providers.map((provider) => `
      <tr>
        <td>${escapeHtml(provider.name)}</td>
        <td>${escapeHtml(provider.type)}</td>
        <td>${escapeHtml(provider.target)}</td>
        <td>${provider.isDefault ? "是" : "否"}</td>
        <td>
          <div class="row-actions">
            <form method="post" action="/admin/providers/default">
              <input type="hidden" name="name" value="${escapeHtml(provider.name)}" />
              <button class="secondary" type="submit">设为默认</button>
            </form>
            <form method="post" action="/admin/providers/${encodeURIComponent(provider.name)}/toggle">
              <button class="secondary" type="submit">${provider.disabled ? "启用" : "禁用"}</button>
            </form>
            <form method="post" action="/admin/providers/test">
              <input type="hidden" name="name" value="${escapeHtml(provider.name)}" />
              <button class="secondary" type="submit">测试</button>
            </form>
            ${provider.type === "remote"
              ? `<form method="post" action="/admin/providers/${encodeURIComponent(provider.name)}/edit">
                  <input type="hidden" name="name" value="${escapeHtml(provider.name)}" />
                  <input type="hidden" name="url" value="${escapeHtml(provider.target)}" />
                  <button class="secondary" type="submit">更新</button>
                </form>
                <form method="post" action="/admin/providers/${encodeURIComponent(provider.name)}/delete" onsubmit="return confirm('确认删除这个 Provider 吗？');"><button type="submit">删除</button></form>`
              : ""}
          </div>
        </td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="muted">还没有 Provider。</td></tr>`;
  const body = `
    <section class="grid">
      <div class="card span-4"><div class="metric"><span class="muted">活跃 API Keys</span><strong>${stats.activeApiKeys}</strong><span class="subtle">可随时禁用或删除</span></div></div>
      <div class="card span-4"><div class="metric"><span class="muted">默认 Provider</span><strong>${escapeHtml(defaultProvider || "未配置")}</strong><span class="subtle">${providerTags || "未启用 provider"}</span></div></div>
      <div class="card span-4"><div class="metric"><span class="muted">累计上游调用</span><strong>${stats.totalUpstreamCalls}</strong><span class="subtle">今日：${stats.todayUpstreamCalls}</span></div></div>
      <div class="card span-4">
        <h2>创建 API Key</h2>
        ${flashHtml}
        ${revealHtml}
        <form method="post" action="/admin/keys">
          <label>标签
            <input type="text" name="label" placeholder="例如：edgeone-smoke" required />
          </label>
          <button type="submit">创建</button>
        </form>
      </div>
      <div class="card span-8">
        <h2>当前 API Keys</h2>
        <table>
          <thead><tr><th>ID</th><th>标签</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="card span-12">
        <h2>动态 Provider</h2>
        <p>这里可以新增一个远程 provider URL。它只需要实现与原项目 provider 相同的统一接口。</p>
        <form method="post" action="/admin/providers">
          <label>Provider 名称
            <input type="text" name="name" placeholder="例如：legacy" required />
          </label>
          <label>Provider URL
            <input type="text" name="url" placeholder="https://example.com/provider" required />
          </label>
          <button type="submit">新增远程 Provider</button>
        </form>
        <div style="height:16px"></div>
        <h3>远程 Provider 鉴权</h3>
        <form method="post" action="/admin/provider-secret">
          <label>PROVIDER_SECRET
            <input type="text" name="value" placeholder="留空表示删除" />
          </label>
          <div class="row-actions">
            <button type="submit">保存密钥</button>
            <button class="secondary" type="submit" name="intent" value="delete">删除密钥</button>
          </div>
        </form>
        <div style="height:16px"></div>
        <table>
          <thead><tr><th>名称</th><th>类型</th><th>目标</th><th>默认</th><th>操作</th></tr></thead>
          <tbody>${providerRows}</tbody>
        </table>
      </div>
    </section>`;
  return renderLayout({
    title: "管理后台",
    subtitle: "Admin Console",
    nav: '<a href="/docs">文档</a><form method="post" action="/admin/logout" style="display:inline-flex"><button class="secondary" type="submit">退出登录</button></form>',
    body,
  });
}

function renderErrorPage(status, message) {
  return renderLayout({
    title: "请求失败",
    subtitle: "Error",
    nav: '<a href="/docs">回到文档</a>',
    body: `<section class="grid"><div class="card span-12"><h2>${escapeHtml(String(status))}</h2><p>${escapeHtml(message)}</p></div></section>`,
  });
}

function parseJsonBodyRequest(request) {
  const contentType = request.headers.get("content-type") ?? "";
  return contentType.includes("application/json");
}

async function handleApi(context, kv, state, url, providers) {
  await authenticateApiRequest(kv, context.request);
  const defaultProvider = await getDefaultProviderName(kv, context, providers);
  const providerSecret = (await resolveProviderSecret(kv, context)).value;
  const path = url.pathname;

  if ((context.request.method === "GET" || context.request.method === "POST") && path === "/api/generate-email") {
    const payload = context.request.method === "POST" && parseJsonBodyRequest(context.request)
      ? await context.request.json().catch(() => ({}))
      : {
        provider: url.searchParams.get("provider") || undefined,
        prefix: url.searchParams.get("prefix") || undefined,
        domain: url.searchParams.get("domain") || undefined,
      };
    const providerName = typeof payload.provider === "string" && providers[payload.provider.toLowerCase()]
      ? payload.provider.toLowerCase()
      : defaultProvider;
    const provider = providers[providerName];
    if (!provider) throw new HttpError(400, `Unsupported provider: ${providerName}`);
    const data = provider.kind === "remote"
      ? await remoteGenerateEmail(kv, state, provider, payload, providerSecret)
      : provider.name === "linshiyouxiang"
      ? await linshiGenerateEmail(kv, state, provider, payload)
      : await hydraGenerateEmail(kv, state, provider, payload);
    return jsonResponse(200, data);
  }

  if (context.request.method === "GET" && path === "/api/emails") {
    const email = url.searchParams.get("email");
    if (!email) throw new HttpError(400, "email is required.");
    const provider = await resolveProviderForMailbox(kv, providers, email, url.searchParams.get("provider"));
    if (!provider) throw new HttpError(404, "No provider session found for this email.");
    const data = provider.kind === "remote"
      ? await remoteListEmails(kv, state, provider, email, providerSecret)
      : provider.name === "linshiyouxiang"
      ? await linshiListEmails(kv, state, provider, email)
      : await hydraListEmails(kv, state, provider, email);
    return jsonResponse(200, data);
  }

  if (context.request.method === "DELETE" && path === "/api/emails/clear") {
    const email = url.searchParams.get("email");
    if (!email) throw new HttpError(400, "email is required.");
    const provider = await resolveProviderForMailbox(kv, providers, email, url.searchParams.get("provider"));
    if (!provider) throw new HttpError(404, "No provider session found for this email.");
    const data = provider.kind === "remote"
      ? await remoteClearEmails(kv, state, provider, email, providerSecret)
      : provider.name === "linshiyouxiang"
      ? await linshiClearEmails(kv, state, provider, email)
      : await hydraClearEmails(kv, state, provider, email);
    return jsonResponse(200, data);
  }

  if (context.request.method === "GET" && path === "/api/stats") {
    return jsonResponse(200, await buildStats(kv, providers));
  }

  const mailMatch = path.match(/^\/api\/email\/([^/]+)$/);
  if (mailMatch && context.request.method === "GET") {
    const target = await resolveMailRouteTarget(
      kv,
      providers,
      decodeURIComponent(mailMatch[1]),
      url.searchParams.get("email"),
      url.searchParams.get("provider"),
    );
    const data = target.provider.kind === "remote"
      ? await remoteGetEmail(kv, state, target.provider, target.email, decodeURIComponent(mailMatch[1]), providerSecret)
      : target.provider.name === "linshiyouxiang"
      ? await linshiGetEmail(kv, state, target.provider, target.email, decodeURIComponent(mailMatch[1]))
      : await hydraGetEmail(kv, state, target.provider, target.email, decodeURIComponent(mailMatch[1]));
    return jsonResponse(200, data);
  }
  if (mailMatch && context.request.method === "DELETE") {
    const target = await resolveMailRouteTarget(
      kv,
      providers,
      decodeURIComponent(mailMatch[1]),
      url.searchParams.get("email"),
      url.searchParams.get("provider"),
    );
    const data = target.provider.kind === "remote"
      ? await remoteDeleteEmail(kv, state, target.provider, target.email, decodeURIComponent(mailMatch[1]), providerSecret)
      : target.provider.name === "linshiyouxiang"
      ? await linshiDeleteEmail(kv, state, target.provider, target.email, decodeURIComponent(mailMatch[1]))
      : await hydraDeleteEmail(kv, state, target.provider, target.email, decodeURIComponent(mailMatch[1]));
    return jsonResponse(200, data);
  }

  return jsonResponse(404, null, "API endpoint not found.");
}

async function handleAdmin(context, kv, url, providers) {
  const secureCookie = url.protocol === "https:";
  if (context.request.method === "GET" && url.pathname === "/admin/login") {
    return htmlResponse(200, renderLoginPage(""));
  }
  if (context.request.method === "POST" && url.pathname === "/admin/login") {
    assertAdminConfigured(context);
    requireSameOrigin(context.request, url);
    const form = await context.request.formData();
    const password = String(form.get("password") ?? "");
    if (password !== env(context, "ADMIN_PASSWORD")) {
      return htmlResponse(403, renderLoginPage("密码错误。"));
    }
    const token = await signAdminSession(env(context, "ADMIN_COOKIE_SECRET"), {
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SEC,
    });
    return redirectResponse("/admin", 303, {
      "set-cookie": buildCookie("tmpmail_admin", token, {
        path: "/",
        httpOnly: true,
        sameSite: "Strict",
        secure: secureCookie,
        maxAge: SESSION_TTL_SEC,
      }),
      "cache-control": "no-store",
    });
  }
  if (context.request.method === "POST" && url.pathname === "/admin/logout") {
    requireSameOrigin(context.request, url);
    return redirectResponse("/admin/login", 303, {
      "set-cookie": clearCookie("tmpmail_admin", secureCookie),
      "cache-control": "no-store",
    });
  }

  try {
    await requireAdmin(context, context.request);
  } catch {
    return redirectResponse("/admin/login", 303, { "cache-control": "no-store" });
  }

  if (context.request.method === "GET" && url.pathname === "/admin") {
    const providerEntries = await listProviderEntries(kv, context, providers);
    const stats = await buildStats(kv, providers);
    stats.defaultProvider = await getDefaultProviderName(kv, context, providers);
    return htmlResponse(200, renderAdminPage({
      keys: await listApiKeys(kv),
      createdKey: null,
      flash: null,
      providers: providerEntries,
      stats,
      defaultProvider: stats.defaultProvider,
    }));
  }

  if (context.request.method === "POST" && url.pathname === "/admin/keys") {
    requireSameOrigin(context.request, url);
    const form = await context.request.formData();
    const label = String(form.get("label") ?? "").trim();
    if (!label) throw new HttpError(400, "标签不能为空。");
    const created = await createApiKey(kv, label);
    const providerEntries = await listProviderEntries(kv, context, providers);
    const stats = await buildStats(kv, providers);
    stats.defaultProvider = await getDefaultProviderName(kv, context, providers);
    return htmlResponse(200, renderAdminPage({
      keys: await listApiKeys(kv),
      createdKey: { rawKey: created.rawKey },
      flash: { tone: "success", message: "API Key 创建成功。" },
      providers: providerEntries,
      stats,
      defaultProvider: stats.defaultProvider,
    }), { "cache-control": "no-store" });
  }

  if (context.request.method === "POST" && url.pathname === "/admin/providers") {
    requireSameOrigin(context.request, url);
    const form = await context.request.formData();
    const name = normalizeProviderName(String(form.get("name") ?? ""));
    const providerUrl = normalizeProviderUrl(String(form.get("url") ?? ""));
    if (providers[name] && providers[name].kind !== "remote") {
      throw new HttpError(400, "内置 provider 不能被远程配置覆盖。");
    }
    await kvPutJson(kv, keyForProviderConfig(name), {
      name,
      url: providerUrl,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  const editProviderMatch = url.pathname.match(/^\/admin\/providers\/([^/]+)\/edit$/);
  if (context.request.method === "POST" && editProviderMatch) {
    requireSameOrigin(context.request, url);
    const currentName = decodeURIComponent(editProviderMatch[1]);
    const form = await context.request.formData();
    const nextName = normalizeProviderName(String(form.get("name") ?? currentName));
    const nextUrl = normalizeProviderUrl(String(form.get("url") ?? ""));
    const providerEntries = await listProviderEntries(kv, context, providers);
    const current = providerEntries.find((provider) => provider.name === currentName);
    if (!current || current.type !== "remote") {
      throw new HttpError(404, "只允许编辑远程 provider。");
    }
    if (currentName !== nextName) {
      const targetExists = providerEntries.find((provider) => provider.name === nextName);
      if (targetExists) throw new HttpError(400, "目标 provider 名称已存在。");
      const disabledConfig = await getResolvedConfigValue(kv, context, providerDisabledConfigKey(currentName), "");
      await kvDelete(kv, keyForProviderConfig(currentName));
      if (disabledConfig.source === "kv") {
        await deleteConfigValue(kv, providerDisabledConfigKey(currentName));
        if (parseConfigBoolean(disabledConfig.value)) {
          await setConfigValue(kv, providerDisabledConfigKey(nextName), "1");
        }
      }
      const defaultProvider = await getDefaultProviderName(kv, context, await assembleAllProviders(context, kv));
      if (defaultProvider === currentName) {
        await setConfigValue(kv, "DEFAULT_PROVIDER", nextName);
      }
    }
    await kvPutJson(kv, keyForProviderConfig(nextName), {
      name: nextName,
      url: nextUrl,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  const deleteProviderMatch = url.pathname.match(/^\/admin\/providers\/([^/]+)\/delete$/);
  if (context.request.method === "POST" && deleteProviderMatch) {
    requireSameOrigin(context.request, url);
    const name = decodeURIComponent(deleteProviderMatch[1]);
    const allProviders = await assembleAllProviders(context, kv);
    const provider = allProviders[name];
    if (!provider || provider.kind !== "remote") {
      throw new HttpError(404, "只允许删除远程 provider。");
    }
    await kvDelete(kv, keyForProviderConfig(name));
    await deleteConfigValue(kv, providerDisabledConfigKey(name));
    const currentDefault = await getDefaultProviderName(kv, context, providers);
    if (currentDefault === name) {
      await deleteConfigValue(kv, "DEFAULT_PROVIDER");
    }
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  if (context.request.method === "POST" && url.pathname === "/admin/providers/default") {
    requireSameOrigin(context.request, url);
    const form = await context.request.formData();
    const name = normalizeProviderName(String(form.get("name") ?? ""));
    const allProviders = await assembleAllProviders(context, kv);
    if (!allProviders[name]) throw new HttpError(404, "Provider 不存在。");
    if (allProviders[name].disabled) throw new HttpError(400, "不能将已禁用的 provider 设为默认。");
    await setConfigValue(kv, "DEFAULT_PROVIDER", name);
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  const toggleProviderMatch = url.pathname.match(/^\/admin\/providers\/([^/]+)\/toggle$/);
  if (context.request.method === "POST" && toggleProviderMatch) {
    requireSameOrigin(context.request, url);
    const name = decodeURIComponent(toggleProviderMatch[1]);
    const allProviders = await assembleAllProviders(context, kv);
    const provider = allProviders[name];
    if (!provider) throw new HttpError(404, "Provider 不存在。");
    if (provider.disableLocked) throw new HttpError(400, "该 provider 的禁用状态被环境变量锁定。");
    const nextDisabled = !provider.disabled;
    if (nextDisabled) {
      const defaultProvider = await getDefaultProviderName(kv, context, allProviders);
      if (defaultProvider === name) {
        const remaining = Object.values(allProviders).filter((row) => row.name !== name && !row.disabled);
        if (remaining.length > 0) {
          await setConfigValue(kv, "DEFAULT_PROVIDER", remaining[0].name);
        } else {
          await deleteConfigValue(kv, "DEFAULT_PROVIDER");
        }
      }
      await setConfigValue(kv, providerDisabledConfigKey(name), "1");
    } else {
      await deleteConfigValue(kv, providerDisabledConfigKey(name));
    }
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  if (context.request.method === "POST" && url.pathname === "/admin/provider-secret") {
    requireSameOrigin(context.request, url);
    const form = await context.request.formData();
    const resolved = await resolveProviderSecret(kv, context);
    if (resolved.locked) throw new HttpError(400, "PROVIDER_SECRET 被环境变量锁定。");
    const intent = String(form.get("intent") ?? "save");
    if (intent === "delete") {
      await deleteConfigValue(kv, "PROVIDER_SECRET");
    } else {
      await setConfigValue(kv, "PROVIDER_SECRET", String(form.get("value") ?? "").trim());
    }
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  if (context.request.method === "POST" && url.pathname === "/admin/providers/test") {
    requireSameOrigin(context.request, url);
    const form = await context.request.formData();
    const name = normalizeProviderName(String(form.get("name") ?? ""));
    const allProviders = await assembleAllProviders(context, kv);
    const provider = allProviders[name];
    if (!provider) throw new HttpError(404, "Provider 不存在。");
    const testState = { upstreamCalls: 0 };
    const providerSecret = (await resolveProviderSecret(kv, context)).value;
    const result = await testProviderConnection(testState, provider, providerSecret);
    const providerEntries = await listProviderEntries(kv, context, providers);
    const stats = await buildStats(kv, providers);
    stats.defaultProvider = await getDefaultProviderName(kv, context, providers);
    return htmlResponse(200, renderAdminPage({
      keys: await listApiKeys(kv),
      createdKey: null,
      flash: {
        tone: result.ok ? "success" : "error",
        message: result.ok
          ? `Provider ${name} 测试成功${result.email ? `，邮箱：${result.email}` : ""}`
          : `Provider ${name} 测试失败：${result.error || result.status}`,
      },
      providers: providerEntries,
      stats,
      defaultProvider: stats.defaultProvider,
    }), { "cache-control": "no-store" });
  }

  const toggleMatch = url.pathname.match(/^\/admin\/keys\/([^/]+)\/toggle$/);
  if (context.request.method === "POST" && toggleMatch) {
    requireSameOrigin(context.request, url);
    const id = decodeURIComponent(toggleMatch[1]);
    const record = await kvGetJson(kv, keyForApiKey(id));
    if (!record) throw new HttpError(404, "API Key 不存在。");
    await updateApiKeyStatus(kv, id, record.status === "active" ? "disabled" : "active");
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  const deleteMatch = url.pathname.match(/^\/admin\/keys\/([^/]+)\/delete$/);
  if (context.request.method === "POST" && deleteMatch) {
    requireSameOrigin(context.request, url);
    await deleteApiKey(kv, decodeURIComponent(deleteMatch[1]));
    return redirectResponse("/admin", 303, { "cache-control": "no-store" });
  }

  return htmlResponse(404, renderErrorPage(404, "后台页面不存在。"));
}

async function handleRequest(context) {
  const kv = getKv();
  const url = new URL(context.request.url);
  const providers = await assembleProviders(context, kv);
  const state = { upstreamCalls: 0 };
  let response;
  try {
    if (!Object.keys(providers).length) throw new HttpError(500, "没有启用任何 provider，请检查 ENABLED_PROVIDERS。");
    if (context.request.method === "GET" && url.pathname === "/") {
      response = redirectResponse("/docs");
    } else if (context.request.method === "GET" && url.pathname === "/healthz") {
      response = jsonResponse(200, { ok: true, providers: Object.keys(providers) });
    } else if (context.request.method === "GET" && url.pathname === "/docs") {
      const stats = await buildStats(kv, providers);
      stats.defaultProvider = await getDefaultProviderName(kv, context, providers);
      response = htmlResponse(200, renderDocsPage(context, providers, stats));
    } else if (url.pathname.startsWith("/admin")) {
      response = await handleAdmin(context, kv, url, providers);
    } else if (url.pathname.startsWith("/api/")) {
      response = await handleApi(context, kv, state, url, providers);
    } else {
      response = htmlResponse(404, renderErrorPage(404, `未匹配到路由：${url.pathname}`));
    }
  } catch (error) {
    if (error instanceof HttpError) {
      response = url.pathname.startsWith("/api/")
        ? jsonResponse(error.status, null, error.message)
        : htmlResponse(error.status, renderErrorPage(error.status, error.message));
    } else {
      console.error(JSON.stringify({
        level: "error",
        route: `${context.request.method} ${url.pathname}`,
        error: error instanceof Error ? error.stack : String(error),
      }));
      response = url.pathname.startsWith("/api/")
        ? jsonResponse(500, null, "Internal server error.")
        : htmlResponse(500, renderErrorPage(500, "服务发生未预期错误。"));
    }
  }
  if (state.upstreamCalls > 0 && context.waitUntil) {
    context.waitUntil(persistUpstreamMetrics(kv, state.upstreamCalls));
  } else if (state.upstreamCalls > 0) {
    await persistUpstreamMetrics(kv, state.upstreamCalls);
  }
  return response;
}

export async function onRequest(context) {
  return await handleRequest(context);
}
