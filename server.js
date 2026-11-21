'use strict';
/**
 * API de la pâtisserie — Express + Postgres (Supabase) + FedaPay.
 * Hébergement : Render (Root Directory = backend, Build = npm install, Start = node server.js).
 * Les tables sont créées automatiquement au démarrage.
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const multer = require('multer');
const Redis = require('ioredis');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

const env = process.env;
const PORT = Number(env.PORT) || 3000;
const IS_PROD = env.NODE_ENV === 'production';
/** Le mode test des codes SMS (debug_code) est IGNORÉ en production : il permettrait de se connecter au compte de n'importe qui. */
const OTP_DEBUG = env.OTP_DEBUG === 'true' && !IS_PROD;
const JWT_SECRET = env.JWT_SECRET || '';
if (JWT_SECRET.length < 32) {
  console.error('❌ JWT_SECRET (32 caractères minimum) est obligatoire.');
  process.exit(1);
}
if (!env.DATABASE_URL) {
  console.error('❌ DATABASE_URL est obligatoire (chaîne de connexion Supabase).');
  process.exit(1);
}

const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 8,
});
// ── Temps réel (SSE) : chaque écriture sur les tables suivies prévient les applis connectées.
// Le message ne contient AUCUNE donnée : chaque appli recharge ce qu'elle a le droit de voir.
const sseClients = new Set();
const sseTimers = new Map();
function emitChange(table) {
  if (sseTimers.has(table)) return;
  sseTimers.set(table, setTimeout(() => {
    sseTimers.delete(table);
    const msg = `event: change\ndata: ${JSON.stringify({ t: table, at: Date.now() })}\n\n`;
    for (const c of sseClients) {
      try { c.write(msg); } catch (_) { sseClients.delete(c); }
    }
  }, 120));
}
const MUTATES = /^\s*(?:insert\s+into|update|delete\s+from)\s+(orders|products|categories|shop_settings|couriers)\b/i;
const q = async (text, params) => {
  const r = await pool.query(text, params);
  const m = typeof text === 'string' ? MUTATES.exec(text) : null;
  if (m) emitChange(m[1].toLowerCase());
  return r;
};

// ── Redis (Upstash) : cache du catalogue, positions des livreurs, météo. Repli en mémoire si indisponible.
let redis = null;
if (env.REDIS_URL) {
  redis = new Redis(env.REDIS_URL, { maxRetriesPerRequest: 2, enableOfflineQueue: false });
  redis.on('error', (e) => console.error('[Redis]', e.message));
}
const memKv = new Map();
const redisReady = () => redis && redis.status === 'ready';
async function kvGet(key) {
  try {
    if (redisReady()) {
      const v = await redis.get(key);
      return v ? JSON.parse(v) : null;
    }
  } catch (_) { /* repli mémoire */ }
  const m = memKv.get(key);
  return m && m.exp > Date.now() ? m.value : null;
}
async function kvSet(key, value, ttlSec) {
  try {
    if (redisReady()) { await redis.set(key, JSON.stringify(value), 'EX', ttlSec); return; }
  } catch (_) { /* repli mémoire */ }
  memKv.set(key, { value, exp: Date.now() + ttlSec * 1000 });
}
async function kvDel(...keys) {
  keys.forEach((k) => memKv.delete(k));
  try { if (redisReady() && keys.length) await redis.del(...keys); } catch (_) { /* ignoré */ }
}
async function cached(key, ttl, fn) {
  const hit = await kvGet(key);
  if (hit) return hit;
  const val = await fn();
  await kvSet(key, val, ttl);
  return val;
}
const bustCatalog = () => kvDel('c:categories', 'c:products', 'c:settings');

// ── Utilitaires ──────────────────────────────────────────────────────────────
const httpErr = (status, message, extra = {}) => Object.assign(new Error(message), { status, code: extra.code, retry_after: extra.retry_after });
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const digits = (s) => String(s || '').replace(/\D/g, '');
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s));
const int = (v, d = 0) => {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : d;
};
const bool = (v, d = false) => (v === true || v === 'true' || v === '1' ? true : v === false || v === 'false' || v === '0' ? false : d);
const hashOtp = (code) => crypto.createHash('sha256').update(`${code}:${JWT_SECRET}`).digest('hex');

const LANGS = ['fr', 'en', 'es', 'pt', 'ar', 'zh', 'ee', 'ha', 'yo', 'kab'];
const CURRENCIES = ['XOF', 'XAF', 'GHS', 'NGN', 'GNF', 'USD', 'EUR', 'GBP', 'JPY', 'CNY', 'CAD', 'CHF', 'MAD'];
/** Taux indicatifs (1 unité = X FCFA) : la propriétaire les corrige dans Réglages. */
const DEFAULT_RATES = { XOF: 1, XAF: 1, GHS: 55, NGN: 0.4, GNF: 0.07, USD: 600, EUR: 655.957, GBP: 770, JPY: 4, CNY: 85, CAD: 440, CHF: 700, MAD: 60 };
const num2 = (v) => Math.round((Number(v) || 0) * 100) / 100;
/** Convertit un prix (dans la devise du produit) en FCFA selon les taux de la propriétaire. */
function toXof(amount, cur, s) {
  const custom = s.rates && typeof s.rates === 'object' ? Number(s.rates[cur]) : NaN;
  const legacy = cur === 'USD' ? Number(s.rate_usd) : cur === 'EUR' ? Number(s.rate_eur) : cur === 'GBP' ? Number(s.rate_gbp) : NaN;
  const rate = [custom, legacy, DEFAULT_RATES[cur], 1].find((x) => Number.isFinite(x) && x > 0);
  return Math.round((Number(amount) || 0) * rate);
}
const rad = (d) => (d * Math.PI) / 180;
function haversineKm(lat1, lng1, lat2, lng2) {
  const a = Math.sin(rad(lat2 - lat1) / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(rad(lng2 - lng1) / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
const OSRM = (env.OSRM_BASE || 'https://router.project-osrm.org').replace(/\/$/, '');
/** Distance et durée par la route (OSRM) ; repli : distance à vol d'oiseau × 1,25. */
async function roadRoute(lat1, lng1, lat2, lng2) {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 6000);
    const r = await fetch(`${OSRM}/route/v1/driving/${lng1},${lat1};${lng2},${lat2}?overview=false`, { signal: ctl.signal });
    clearTimeout(t);
    const j = await r.json();
    const rt = j.routes && j.routes[0];
    if (rt) return { km: rt.distance / 1000, min: rt.duration / 60 };
  } catch (_) { /* repli */ }
  const km = haversineKm(lat1, lng1, lat2, lng2) * 1.25;
  return { km, min: (km / 30) * 60 };
}
async function deliveryInfo(settings, lat, lng) {
  let km = null;
  let min = null;
  if (settings.shop_lat != null && settings.shop_lng != null) {
    const r = await roadRoute(settings.shop_lat, settings.shop_lng, lat, lng);
    km = Math.round(r.km * 100) / 100;
    min = Math.round(r.min);
  }
  // Formule horokilométrique : prix = prise en charge + distance × tarif/km + durée × tarif/min + frais fixes
  const base = settings.delivery_fee || 0;
  const distance = km != null ? km * (settings.delivery_per_km || 0) : 0;
  const time = min != null ? min * (settings.delivery_per_min || 0) : 0;
  const extra = settings.delivery_extra || 0;
  const fee = Math.round((base + distance + time + extra) / 5) * 5;
  return { km, min, fee, breakdown: { base, distance: Math.round(distance), time: Math.round(time), extra } };
}

const STATUSES = ['pending', 'confirmed', 'preparing', 'ready', 'out_for_delivery', 'completed', 'cancelled', 'quote_pending', 'quoted'];

// ── Base de données : création automatique des tables ────────────────────────
async function seedResponsable() {
  if (!env.ADMIN_PHONE) return;
  const ap = digits(env.ADMIN_PHONE);
  if (ap.length < 8) return;
  await q(
    `INSERT INTO users (phone, name, role)
     VALUES ($1, 'Responsable', 'admin')
     ON CONFLICT (phone) DO UPDATE SET role = 'admin'`,
    [ap],
  );
  console.log('[seed] Responsable pré-enregistré : +' + ap);
}

async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      phone text UNIQUE NOT NULL,
      name text NOT NULL DEFAULT '',
      role text NOT NULL DEFAULT 'client',
      created_at timestamptz NOT NULL DEFAULT now()
    );

    ALTER TABLE users ADD COLUMN IF NOT EXISTS email text;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS lang text DEFAULT 'fr';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_payment text DEFAULT 'cash';
    -- rôles : client (acheteur) | admin (responsable) | courier (livreur)
    DO $$ BEGIN
      ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
      ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('client','admin','courier'));
    EXCEPTION WHEN others THEN NULL;
    END $$;
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email)) WHERE email IS NOT NULL AND email <> '';

    CREATE TABLE IF NOT EXISTS otp_requests (
      phone text NOT NULL,
      requested_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS otp_requests_phone_time ON otp_requests (phone, requested_at DESC);

    CREATE TABLE IF NOT EXISTS otp_codes (
      phone text PRIMARY KEY,
      code_hash text NOT NULL,
      expires_at timestamptz NOT NULL,
      tries int NOT NULL DEFAULT 0,
      last_sent timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS categories (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      emoji text NOT NULL DEFAULT '🍰',
      sort int NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS products (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      description text NOT NULL DEFAULT '',
      category_id uuid REFERENCES categories(id) ON DELETE SET NULL,
      price int NOT NULL DEFAULT 0,
      sizes jsonb NOT NULL DEFAULT '[]'::jsonb,
      image_url text,
      emoji text NOT NULL DEFAULT '🍰',
      is_available boolean NOT NULL DEFAULT true,
      is_featured boolean NOT NULL DEFAULT false,
      prep_hours int NOT NULL DEFAULT 24,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS shop_settings (
      id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      shop_name text NOT NULL DEFAULT 'Ma Pâtisserie',
      is_open boolean NOT NULL DEFAULT true,
      delivery_fee int NOT NULL DEFAULT 1000,
      min_lead_hours int NOT NULL DEFAULT 6,
      online_payment boolean NOT NULL DEFAULT false,
      whatsapp text NOT NULL DEFAULT '',
      opening_hours text NOT NULL DEFAULT 'Lun - Sam : 8h - 19h',
      address text NOT NULL DEFAULT ''
    );
    INSERT INTO shop_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

    CREATE SEQUENCE IF NOT EXISTS order_seq START 1001;
    CREATE TABLE IF NOT EXISTS orders (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      code text UNIQUE NOT NULL DEFAULT ('CMD-' || nextval('order_seq')::text),
      user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      customer_name text NOT NULL DEFAULT '',
      phone text NOT NULL DEFAULT '',
      type text NOT NULL DEFAULT 'pickup' CHECK (type IN ('pickup','delivery')),
      address text NOT NULL DEFAULT '',
      scheduled_at timestamptz NOT NULL,
      payment_method text NOT NULL DEFAULT 'cash' CHECK (payment_method IN ('cash','online')),
      payment_ref text NOT NULL DEFAULT '',
      payment_status text NOT NULL DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','paid')),
      status text NOT NULL DEFAULT 'pending',
      total int NOT NULL DEFAULT 0,
      delivery_fee int NOT NULL DEFAULT 0,
      note text NOT NULL DEFAULT '',
      items jsonb NOT NULL DEFAULT '[]'::jsonb,
      is_custom boolean NOT NULL DEFAULT false,
      custom_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_provider text NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS lang text NOT NULL DEFAULT 'fr';
    ALTER TABLE categories ADD COLUMN IF NOT EXISTS image_url text;
    ALTER TABLE products ADD COLUMN IF NOT EXISTS currency text NOT NULL DEFAULT 'XOF';
    ALTER TABLE products ALTER COLUMN price TYPE double precision;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS rate_usd double precision NOT NULL DEFAULT 600;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS rate_eur double precision NOT NULL DEFAULT 655.957;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS rate_gbp double precision NOT NULL DEFAULT 770;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS shop_lat double precision;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS shop_lng double precision;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS delivery_per_km int NOT NULL DEFAULT 0;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS delivery_max_km int NOT NULL DEFAULT 0;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS delivery_per_min int NOT NULL DEFAULT 0;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS delivery_extra int NOT NULL DEFAULT 0;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS rates jsonb NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS duration_min int;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_override boolean NOT NULL DEFAULT false;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_override_note text NOT NULL DEFAULT '';
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_lat double precision;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_lng double precision;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivery_code text NOT NULL DEFAULT '';
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS distance_km double precision;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS courier_id uuid REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS assigned_at timestamptz;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_at timestamptz;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_lat double precision;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS delivered_lng double precision;
    CREATE TABLE IF NOT EXISTS couriers (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      phone text UNIQUE NOT NULL,
      name text NOT NULL DEFAULT '',
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS device_tokens (
      token text PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      platform text NOT NULL DEFAULT 'android',
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_channel text NOT NULL DEFAULT '';
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS allow_card boolean NOT NULL DEFAULT true;
    ALTER TABLE shop_settings ADD COLUMN IF NOT EXISTS allow_mobile_money boolean NOT NULL DEFAULT true;
    CREATE INDEX IF NOT EXISTS orders_user_idx ON orders(user_id, created_at DESC);

    -- Sécurité Supabase : l'application ne parle jamais directement à la base (uniquement ce serveur).
    -- RLS activé sans règle = l'API publique de Supabase ne peut rien lire ni écrire dans ces tables.
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE otp_codes ENABLE ROW LEVEL SECURITY;
    ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
    ALTER TABLE products ENABLE ROW LEVEL SECURITY;
    ALTER TABLE shop_settings ENABLE ROW LEVEL SECURITY;
    ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
    ALTER TABLE couriers ENABLE ROW LEVEL SECURITY;
    ALTER TABLE device_tokens ENABLE ROW LEVEL SECURITY;
  `);
}

// ── SMS (Vonage) ─────────────────────────────────────────────────────────────
async function sendSms(phone, text) {
  const key = env.VONAGE_API_KEY;
  const secret = env.VONAGE_API_SECRET;
  if (!key || !secret) {
    if (IS_PROD && !OTP_DEBUG) {
      throw httpErr(503, 'Envoi de SMS non configuré sur le serveur (VONAGE_API_KEY / VONAGE_API_SECRET).');
    }
    console.log(`[SMS — mode développement] +${phone} : ${text}`);
    return { mode: 'dev' };
  }
  // Expéditeur : alpha-numérique (max 11) ou numéro. Certains pays (GH, TG…)
  // rejettent les alpha non enregistrés → on retente avec le numéro Vonage si fourni.
  const fromCandidates = [
    env.VONAGE_FROM,
    env.VONAGE_FROM_NUMBER,
    'Patisserie',
  ].filter(Boolean);

  let lastErr = null;
  for (const from of fromCandidates) {
    try {
      const r = await fetch('https://rest.nexmo.com/sms/json', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          api_key: key,
          api_secret: secret,
          to: phone,
          from: String(from).slice(0, 11),
          text,
          type: 'unicode',
        }),
      });
      const j = await r.json().catch(() => ({}));
      const m = j && j.messages && j.messages[0];
      if (m && m.status === '0') {
        console.log(`[SMS] OK → +${phone} (from=${from}, id=${m['message-id'] || '?'})`);
        return { mode: 'vonage', messageId: m['message-id'] };
      }
      lastErr = m || j;
      console.error('[SMS] tentative échouée from=', from, m || j);
    } catch (e) {
      lastErr = { error: e.message };
      console.error('[SMS] réseau', e.message);
    }
  }
  console.error('[SMS] échec final :', lastErr);
  // En OTP_DEBUG on n'interrompt pas : le code reste utilisable via debug_code
  if (OTP_DEBUG) return { mode: 'failed_debug', error: lastErr };
  throw httpErr(502, 'Le SMS n’a pas pu être envoyé. Réessayez dans un instant.');
}

const SMS_TEXT = {
  quoted: (o) => `Patisserie : votre devis ${o.code} est prêt (${o.total} FCFA). Ouvrez l'application pour répondre.`,
  ready: (o) => `Patisserie : votre commande ${o.code} est prête${o.type === 'delivery' ? ' et va partir en livraison' : ' à retirer'}.`,
  out_for_delivery: (o) => `Patisserie : votre commande ${o.code} est en route.`,
};
function notifyStatus(order) {
  if (env.SMS_NOTIFICATIONS !== 'true' || !SMS_TEXT[order.status]) return;
  sendSms(digits(order.phone), SMS_TEXT[order.status](order)).catch(() => {});
}

// ── Photos (Supabase Storage) ────────────────────────────────────────────────
const BUCKET = env.SUPABASE_BUCKET || 'patisserie';
const sb = env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;

async function ensureBucket() {
  if (!sb) {
    console.warn('⚠️  Photos : SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY absents → l’ajout de photos sera refusé.');
    return;
  }
  const { error } = await sb.storage.createBucket(BUCKET, { public: true });
  if (error && !/already exists|duplicate/i.test(error.message)) console.error('[Storage]', error.message);
}

function sniffMime(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return ['image/jpeg', 'jpg'];
  if (buf.slice(1, 4).toString('latin1') === 'PNG') return ['image/png', 'png'];
  if (buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') return ['image/webp', 'webp'];
  return null;
}

async function storeImage(buf, folder) {
  if (!sb) throw httpErr(503, 'Stockage des photos non configuré sur le serveur.');
  const kind = sniffMime(buf);
  if (!kind) throw httpErr(400, 'Photo non reconnue : envoyez une image JPG, PNG ou WEBP.');
  const path = `${folder}/${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${kind[1]}`;
  const { error } = await sb.storage.from(BUCKET).upload(path, buf, { contentType: kind[0], upsert: false });
  if (error) throw httpErr(502, `Envoi de la photo impossible : ${error.message}`);
  return sb.storage.from(BUCKET).getPublicUrl(path).data.publicUrl;
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024, files: 1 } });

// ── Application ──────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '200kb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 600, standardHeaders: true, legacyHeaders: false }));
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Trop de tentatives, réessayez dans quelques minutes.' }),
});

app.get('/', (_req, res) => res.json({ name: 'patisserie-api', ok: true }));
app.get('/health', wrap(async (_req, res) => {
  await q('SELECT 1');
  res.json({ ok: true });
}));

// ── Authentification par téléphone (code SMS) ────────────────────────────────
const auth = wrap(async (req, _res, next) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) throw httpErr(401, 'Connexion requise.');
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (_) {
    throw httpErr(401, 'Session expirée, reconnectez-vous.');
  }
  const { rows } = await q('SELECT id, phone, name, role, lang, email, preferred_payment FROM users WHERE id=$1', [payload.sub]);
  if (!rows[0]) throw httpErr(401, 'Compte introuvable.');
  req.user = await publicUser(rows[0]);
  next();
});
/** Rôle réel : propriétaire, livreur (numéro pré-enregistré par la propriétaire) ou client. */
async function publicUser(row) {
  const c = await q('SELECT 1 FROM couriers WHERE phone=$1 AND active', [row.phone]);
  const role = row.role === 'admin' ? 'admin' : c.rowCount ? 'courier' : 'client';
  return { id: row.id, phone: row.phone, name: row.name, role, lang: row.lang || 'fr', email: row.email || '', preferred_payment: row.preferred_payment || 'cash' };
}
const courierOnly = (req, _res, next) => (req.user && (req.user.role === 'courier' || req.user.role === 'admin') ? next() : next(httpErr(403, 'Réservé aux livreurs enregistrés.', { code: 'err_courier_only' })));
const adminOnly = (req, _res, next) => (req.user && req.user.role === 'admin' ? next() : next(httpErr(403, 'Réservé à la propriétaire.')));

app.post('/auth/request-otp', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  if (phone.length < 8 || phone.length > 15) {
    throw httpErr(400, 'Numéro de téléphone invalide.', { code: 'err_phone_invalid' });
  }
  const prev = (await q('SELECT last_sent FROM otp_codes WHERE phone=$1', [phone])).rows[0];
  if (prev) {
    const wait = 60 - Math.floor((Date.now() - new Date(prev.last_sent).getTime()) / 1000);
    if (wait > 0) {
      throw httpErr(429, 'Patientez avant de redemander un code.', { code: 'err_otp_wait', retry_after: wait });
    }
  }
  const hourCount = (await q(
    "SELECT COUNT(*)::int AS n FROM otp_requests WHERE phone=$1 AND requested_at > now() - interval '1 hour'",
    [phone],
  )).rows[0].n;
  if (hourCount >= 5) {
    throw httpErr(429, 'Trop de demandes de code. Réessayez dans une heure.', { code: 'err_otp_limit', retry_after: 3600 });
  }
  await q('INSERT INTO otp_requests (phone) VALUES ($1)', [phone]);

  const code = String(crypto.randomInt(100000, 1000000));
  await q(
    `INSERT INTO otp_codes (phone, code_hash, expires_at, tries, last_sent)
     VALUES ($1, $2, now() + interval '5 minutes', 0, now())
     ON CONFLICT (phone) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, tries = 0, last_sent = now()`,
    [phone, hashOtp(code)],
  );
  const appHash = String(req.body.app_hash || '').trim();
  const withHash = /^[A-Za-z0-9+/=]{11}$/.test(appHash);
  const brand = env.SMS_BRAND || 'Patisserie';
  const text = withHash
    ? `<#> ${brand}: code ${code}
${appHash}`
    : `${brand}: votre code est ${code}. Valide 5 min.`;
  const smsResult = await sendSms(phone, text.replace('\\n', '\n'));
  const payload = { ok: true, retry_after: 60, expires_in: 300 };
  if (OTP_DEBUG) {
    payload.debug_code = code;
    payload.sms = smsResult || null;
    console.log(`[OTP_DEBUG] +${phone} code=${code}`);
  }
  res.json(payload);
}));

app.post('/auth/verify-otp', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  const code = String(req.body.code || '').trim();
  const o = (await q('SELECT * FROM otp_codes WHERE phone=$1', [phone])).rows[0];
  if (!o || new Date(o.expires_at) < new Date()) {
    throw httpErr(400, 'Code expiré : demandez-en un nouveau.', { code: 'err_otp_expired' });
  }
  if (o.tries >= 5) {
    throw httpErr(429, 'Trop d’essais : demandez un nouveau code.', { code: 'err_otp_tries' });
  }
  if (o.code_hash !== hashOtp(code)) {
    await q('UPDATE otp_codes SET tries = tries + 1 WHERE phone=$1', [phone]);
    throw httpErr(400, 'Code incorrect.', { code: 'err_otp_wrong' });
  }
  await q('DELETE FROM otp_codes WHERE phone=$1', [phone]);

  const isAdmin = !!env.ADMIN_PHONE && digits(env.ADMIN_PHONE) === phone;
  const name = String(req.body.name || '').trim().slice(0, 60);
  let email = String(req.body.email || '').trim().toLowerCase().slice(0, 120);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw httpErr(400, 'Adresse e-mail invalide.', { code: 'err_email_invalid' });
  }
  if (!email) email = null;

  if (email) {
    const taken = (await q(
      'SELECT id FROM users WHERE lower(email)=lower($1) AND phone <> $2 LIMIT 1',
      [email, phone],
    )).rows[0];
    if (taken) throw httpErr(409, 'Cet e-mail est déjà utilisé.', { code: 'err_email_exists' });
  }

  const user = (await q(
    `INSERT INTO users (phone, name, role, email) VALUES ($1, $2, $3, $4)
     ON CONFLICT (phone) DO UPDATE SET
       role = CASE WHEN $5::boolean THEN 'admin' ELSE users.role END,
       name = CASE WHEN users.name = '' AND $2 <> '' THEN $2 ELSE users.name END,
       email = CASE WHEN $4::text IS NOT NULL THEN $4 ELSE users.email END
     RETURNING id, phone, name, role, lang, email`,
    [phone, name, isAdmin ? 'admin' : 'client', email, isAdmin],
  )).rows[0];
  const lang = String(req.body.lang || '');
  if (LANGS.includes(lang) && lang !== user.lang) {
    await q('UPDATE users SET lang=$1 WHERE id=$2', [lang, user.id]);
    user.lang = lang;
  }
  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, user: await publicUser(user) });
}));


// ── Inscription / connexion par mot de passe (3 profils) ─────────────────────
const ROLES_PUBLIC = ['client', 'admin', 'courier'];

app.post('/auth/register', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  const name = String(req.body.name || '').trim().slice(0, 60);
  const email = String(req.body.email || '').trim().toLowerCase().slice(0, 120);
  const password = String(req.body.password || '');
  const roleReq = String(req.body.role || 'client');
  const preferredPayment = String(req.body.preferred_payment || 'cash');

  if (phone.length < 8 || phone.length > 15) throw httpErr(400, 'Numéro de téléphone invalide.', { code: 'err_phone_invalid' });
  if (!name) throw httpErr(400, 'Prénom requis.', { code: 'err_name_required' });
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw httpErr(400, 'Adresse e-mail invalide.', { code: 'err_email_invalid' });
  if (password.length < 6) throw httpErr(400, 'Mot de passe trop court (6 caractères min.).', { code: 'err_password_min' });
  if (!ROLES_PUBLIC.includes(roleReq)) throw httpErr(400, 'Rôle invalide.', { code: 'err_invalid_role' });

  let role = 'client';
  if (roleReq === 'admin') {
    if (!env.ADMIN_PHONE || digits(env.ADMIN_PHONE) !== phone) {
      throw httpErr(403, 'Ce numéro n’est pas autorisé comme responsable.', { code: 'err_admin_phone' });
    }
    role = 'admin';
  } else if (roleReq === 'courier') {
    const c = (await q('SELECT 1 FROM couriers WHERE phone=$1 AND active', [phone])).rows[0];
    if (!c) throw httpErr(403, 'Ce numéro n’est pas enregistré comme livreur. Demandez à la responsable.', { code: 'err_courier_phone' });
    role = 'courier';
  } else {
    const reserved = (!!env.ADMIN_PHONE && digits(env.ADMIN_PHONE) === phone)
      || (await q('SELECT 1 FROM couriers WHERE phone=$1 AND active', [phone])).rowCount > 0;
    if (reserved) throw httpErr(403, 'Ce numéro correspond à un autre profil.', { code: 'err_role_mismatch' });
  }

  const existing = (await q('SELECT id, password_hash FROM users WHERE phone=$1', [phone])).rows[0];
  if (existing && existing.password_hash) {
    throw httpErr(409, 'Un compte existe déjà avec ce numéro. Connectez-vous.', { code: 'err_phone_exists' });
  }
  const emailTaken = (await q(
    'SELECT id FROM users WHERE lower(email)=lower($1) AND phone <> $2 LIMIT 1',
    [email, phone],
  )).rows[0];
  if (emailTaken) throw httpErr(409, 'Cet e-mail est déjà utilisé.', { code: 'err_email_exists' });

  const hash = await bcrypt.hash(password, 10);
  const pay = ['cash', 'online', 'mobile_money', 'card'].includes(preferredPayment) ? preferredPayment : 'cash';

  const user = (await q(
    `INSERT INTO users (phone, name, role, email, password_hash, preferred_payment)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (phone) DO UPDATE SET
       name = EXCLUDED.name,
       role = EXCLUDED.role,
       email = EXCLUDED.email,
       password_hash = EXCLUDED.password_hash,
       preferred_payment = EXCLUDED.preferred_payment
     RETURNING id, phone, name, role, lang, email, preferred_payment`,
    [phone, name, role, email, hash, pay],
  )).rows[0];

  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, user: await publicUser(user) });
}));

app.post('/auth/login', otpLimiter, wrap(async (req, res) => {
  const login = String(req.body.login || req.body.phone || req.body.email || '').trim();
  const password = String(req.body.password || '');
  if (!login || password.length < 1) throw httpErr(400, 'Identifiant et mot de passe requis.', { code: 'err_login_fields' });

  const phone = digits(login);
  let row;
  if (phone.length >= 8 && !login.includes('@')) {
    row = (await q('SELECT * FROM users WHERE phone=$1', [phone])).rows[0];
  } else {
    row = (await q('SELECT * FROM users WHERE lower(email)=lower($1)', [login.toLowerCase()])).rows[0];
  }
  if (!row || !row.password_hash) {
    throw httpErr(401, 'Identifiants incorrects.', { code: 'err_bad_credentials' });
  }
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) throw httpErr(401, 'Identifiants incorrects.', { code: 'err_bad_credentials' });

  const user = await publicUser(row);
  const wanted = String(req.body.role || '');
  if (wanted && user.role !== wanted) {
    throw httpErr(403, 'Ce compte n’a pas ce profil.', { code: 'err_role_mismatch' });
  }
  const token = jwt.sign({ sub: row.id }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, user });
}));

app.get('/me', auth, (req, res) => res.json(req.user));
app.patch('/me', auth, wrap(async (req, res) => {
  const sets = [];
  const vals = [];
  if (req.body.name !== undefined) {
    const name = String(req.body.name || '').trim().slice(0, 60);
    if (!name) throw httpErr(400, 'Prénom requis.', { code: 'err_name_required' });
    vals.push(name);
    sets.push(`name=$${vals.length}`);
  }
  if (req.body.email !== undefined) {
    let email = String(req.body.email || '').trim().toLowerCase().slice(0, 120);
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw httpErr(400, 'Adresse e-mail invalide.', { code: 'err_email_invalid' });
    }
    if (!email) email = null;
    if (email) {
      const taken = (await q(
        'SELECT id FROM users WHERE lower(email)=lower($1) AND id <> $2 LIMIT 1',
        [email, req.user.id],
      )).rows[0];
      if (taken) throw httpErr(409, 'Cet e-mail est déjà utilisé.', { code: 'err_email_exists' });
    }
    vals.push(email);
    sets.push(`email=$${vals.length}`);
  }
  if (req.body.lang !== undefined) {
    const l = String(req.body.lang);
    if (!LANGS.includes(l)) throw httpErr(400, 'Langue inconnue.', { code: 'err_lang_unknown' });
    vals.push(l);
    sets.push(`lang=$${vals.length}`);
  }
  if (!sets.length) throw httpErr(400, 'Rien à modifier.', { code: 'err_nothing' });
  vals.push(req.user.id);
  const { rows } = await q(`UPDATE users SET ${sets.join(', ')} WHERE id=$${vals.length} RETURNING id, phone, name, role, lang, email`, vals);
  res.json(await publicUser(rows[0]));
}));

// Jeton de notification de l'appareil (Firebase Cloud Messaging)
app.post('/me/device-token', auth, wrap(async (req, res) => {
  const t = String(req.body.token || '').trim();
  if (t.length < 20 || t.length > 4096) throw httpErr(400, 'Jeton invalide.');
  await q(
    `INSERT INTO device_tokens (token, user_id, platform, updated_at) VALUES ($1,$2,$3,now())
     ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id, platform = EXCLUDED.platform, updated_at = now()`,
    [t, req.user.id, String(req.body.platform || 'android').slice(0, 20)],
  );
  res.json({ ok: true });
}));
app.post('/me/device-token/remove', auth, wrap(async (req, res) => {
  await q('DELETE FROM device_tokens WHERE token=$1 AND user_id=$2', [String(req.body.token || ''), req.user.id]);
  res.json({ ok: true });
}));

// ── Catalogue (public) ───────────────────────────────────────────────────────
app.get('/categories', wrap(async (_req, res) => {
  res.json(await cached('c:categories', 60, async () => (await q('SELECT id, name, emoji, sort, image_url FROM categories ORDER BY sort, name')).rows));
}));
app.get('/products', wrap(async (_req, res) => {
  res.json(await cached('c:products', 60, async () => (await q(
    `SELECT id, name, description, category_id, price, currency, sizes, image_url, emoji, is_available, is_featured, prep_hours
       FROM products ORDER BY created_at`,
  )).rows));
}));
const getSettings = async () => (await q('SELECT * FROM shop_settings WHERE id=1')).rows[0];
app.get('/settings', wrap(async (_req, res) => {
  res.json(await cached('c:settings', 30, async () => {
    const s = await getSettings();
    delete s.id;
    s.payment_providers = enabledProviders(); // ex. ['flutterwave','paystack'] (clés présentes sur le serveur)
    const d = deliveryStatus(s);
    s.delivery_available = d.ok;
    s.delivery_reason = d.reason;
    return s;
  }));
}));

// Météo gratuite (Open-Meteo) au point de la boutique, mise en cache 10 min
app.get('/weather', wrap(async (_req, res) => {
  const st = await getSettings();
  if (st.shop_lat == null || st.shop_lng == null) return res.json({ available: false });
  const w = await cached('c:weather', 600, async () => {
    try {
      const r = await fetch(`${env.WEATHER_BASE || 'https://api.open-meteo.com'}/v1/forecast?latitude=${st.shop_lat}&longitude=${st.shop_lng}&current=temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m,is_day&timezone=auto`);
      const j = await r.json();
      const c = j.current;
      if (!c) return { available: false };
      return { available: true, temp: c.temperature_2m, feels: c.apparent_temperature, humidity: c.relative_humidity_2m, code: c.weather_code, wind: c.wind_speed_10m, is_day: c.is_day === 1 };
    } catch (_) { return { available: false }; }
  });
  res.json(w);
}));

/** La livraison n'est proposée que si tout est prêt : position de la boutique, tarif, paiement en ligne.
 *  Sinon un client irait jusqu'au bout pour rien, ou la livraison serait gratuite par erreur. */
function deliveryStatus(st) {
  const tariff = [st.delivery_fee, st.delivery_per_km, st.delivery_per_min, st.delivery_extra].some((v) => Number(v) > 0);
  if (st.shop_lat == null || st.shop_lng == null) return { ok: false, reason: 'Livraison momentanément indisponible. Choisissez le retrait en boutique.' };
  if (!tariff) return { ok: false, reason: 'Livraison momentanément indisponible. Choisissez le retrait en boutique.' };
  if (!(st.online_payment && enabledProviders().length > 0 && (st.allow_card || st.allow_mobile_money))) {
    return { ok: false, reason: 'Livraison momentanément indisponible (paiement en ligne non activé). Choisissez le retrait en boutique.' };
  }
  return { ok: true, reason: '' };
}
const RATE_EXEMPT = ['XOF', 'XAF', 'EUR']; // FCFA et euro sont liés à parité fixe : pas de taux à saisir
async function assertRateKnown(currency) {
  if (RATE_EXEMPT.includes(currency)) return;
  const st = await getSettings();
  const r = st.rates && Number(st.rates[currency]);
  if (!(r > 0)) throw httpErr(400, `Définissez d’abord le taux de change ${currency} → FCFA dans Réglages.`, { code: 'err_rate_missing' });
}

// Estimation de la livraison : distance par la route, durée, frais, zone (public : le tarif n'a rien de secret)
const geoLimiter = rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false });
app.post('/delivery/quote', geoLimiter, wrap(async (req, res) => {
  const lat = Number(req.body.lat);
  const lng = Number(req.body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) throw httpErr(400, 'Position invalide.');
  const st = await getSettings();
  const avail = deliveryStatus(st);
  if (!avail.ok) throw httpErr(409, avail.reason, { code: 'err_delivery_unavailable' });
  const info = await deliveryInfo(st, lat, lng);
  const within = !(st.delivery_max_km > 0 && info.km != null && info.km > st.delivery_max_km);
  res.json({ distance_km: info.km, duration_min: info.min, fee: info.fee, breakdown: info.breakdown, currency: 'XOF', max_km: st.delivery_max_km, within_zone: within });
}));

// Recherche d'adresse / lieu (Photon puis Nominatim : gratuit, sans clé) et adresse d'un point
const GEO_UA = { 'User-Agent': `patisserie-app/1.0 (${env.GEO_CONTACT || 'contact@patisserie.app'})`, 'Accept-Language': 'fr,en' };
const geoCache = new Map();
const geoGet = (k) => { const h = geoCache.get(k); return h && Date.now() - h.at < 6 * 3600 * 1000 ? h.v : null; };
const geoSet = (k, v) => { if (geoCache.size > 800) geoCache.delete(geoCache.keys().next().value); geoCache.set(k, { at: Date.now(), v }); return v; };
async function fetchJson(url, ms = 7000) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { headers: GEO_UA, signal: ctl.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } finally { clearTimeout(timer); }
}
const validCoord = (lat, lng) => lat !== undefined && lng !== undefined && lat !== '' && lng !== ''
  && Number.isFinite(Number(lat)) && Number.isFinite(Number(lng)) && Math.abs(Number(lat)) <= 90 && Math.abs(Number(lng)) <= 180;

app.get('/geo/search', geoLimiter, wrap(async (req, res) => {
  const text = String(req.query.q || '').trim().slice(0, 120);
  if (text.length < 3) return res.json([]);
  const bias = validCoord(req.query.lat, req.query.lng) ? `&lat=${Number(req.query.lat)}&lon=${Number(req.query.lng)}` : '';
  const key = `s:${text.toLowerCase()}:${bias ? Number(req.query.lat).toFixed(1) + Number(req.query.lng).toFixed(1) : ''}`;
  const hit = geoGet(key);
  if (hit) return res.json(hit);
  let out = [];
  try {
    const j = await fetchJson(`https://photon.komoot.io/api/?q=${encodeURIComponent(text)}&limit=8${bias}`);
    out = (j.features || []).map((f) => {
      const p = f.properties || {};
      const [lng, lat] = f.geometry.coordinates;
      const label = [p.name, p.street && `${p.street}${p.housenumber ? ' ' + p.housenumber : ''}`, p.city || p.town || p.village, p.state, p.country]
        .filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(', ');
      return { label, lat, lng };
    });
  } catch (_) {
    try {
      const j = await fetchJson(`https://nominatim.openstreetmap.org/search?format=jsonv2&limit=8&q=${encodeURIComponent(text)}`);
      out = (j || []).map((p) => ({ label: p.display_name, lat: Number(p.lat), lng: Number(p.lon) }));
    } catch (_e) { throw httpErr(503, 'Recherche indisponible.'); }
  }
  res.json(geoSet(key, out));
}));

app.get('/geo/reverse', geoLimiter, wrap(async (req, res) => {
  if (!validCoord(req.query.lat, req.query.lng)) throw httpErr(400, 'Position invalide.');
  const lat = Number(req.query.lat);
  const lng = Number(req.query.lng);
  const key = `r:${lat.toFixed(4)}:${lng.toFixed(4)}`;
  const hit = geoGet(key);
  if (hit) return res.json(hit);
  let label = '';
  try {
    const j = await fetchJson(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=18&lat=${lat}&lon=${lng}`);
    label = String(j.display_name || '').split(',').slice(0, 3).join(',').trim();
  } catch (_) { /* pas d'adresse : l'appli affichera les coordonnées */ }
  res.json(geoSet(key, { label }));
}));

// Flux temps réel (public : il ne transporte aucune donnée, seulement « quelque chose a changé ») : l'appli reste connectée et se recharge dès qu'une commande, un produit ou un réglage change.
app.get('/events', (req, res) => {
  if (sseClients.size >= 2000) return res.status(503).end();
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n: connecté\n\n');
  sseClients.add(res);
  const beat = setInterval(() => { try { res.write(': ping\n\n'); } catch (_) { /* fermé */ } }, 20000);
  req.on('close', () => { clearInterval(beat); sseClients.delete(res); });
});

// ── Commandes (client) ───────────────────────────────────────────────────────
const ordersLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Trop de commandes en peu de temps. Réessayez plus tard.' } });
app.post('/orders', auth, ordersLimiter, wrap(async (req, res) => {
  const b = req.body || {};
  const pendingCount = (await q(`SELECT COUNT(*)::int AS n FROM orders WHERE user_id=$1 AND status IN ('pending','quote_pending') AND payment_status='unpaid' AND created_at > now() - interval '24 hours'`, [req.user.id])).rows[0].n;
  if (pendingCount >= 5) throw httpErr(429, 'Vous avez déjà plusieurs commandes en attente. Payez ou annulez-en une avant d’en créer une nouvelle.');
  const type = b.type === 'delivery' ? 'delivery' : 'pickup';
  const address = String(b.address || '').trim().slice(0, 300);
  if (type === 'delivery' && address.length < 5) throw httpErr(400, 'Indiquez l’adresse de livraison.');
  const when = new Date(b.scheduled_at);
  if (Number.isNaN(when.getTime())) throw httpErr(400, 'Date et heure invalides.');
  const settings = await getSettings();
  const note = String(b.note || '').trim().slice(0, 500);
  const isCustom = b.is_custom === true;
  let dLat = null;
  let dLng = null;
  if (type === 'delivery') {
    const present = (v) => v !== null && v !== undefined && v !== '';
    dLat = present(b.delivery_lat) ? Number(b.delivery_lat) : NaN;
    dLng = present(b.delivery_lng) ? Number(b.delivery_lng) : NaN;
    if (!Number.isFinite(dLat) || !Number.isFinite(dLng) || Math.abs(dLat) > 90 || Math.abs(dLng) > 180) {
      throw httpErr(400, 'Indiquez la position de livraison sur la carte.');
    }
  }

  const items = [];
  let subtotal = 0;
  let status = 'pending';
  const customDetails = {};
  let leadHours = settings.min_lead_hours;

  if (isCustom) {
    // Gâteau sur mesure : pas de prix, la pâtisserie répond avec un devis.
    const d = b.custom_details && typeof b.custom_details === 'object' ? b.custom_details : {};
    for (const [k, v] of Object.entries(d)) customDetails[String(k).slice(0, 60)] = String(v == null ? '' : v).slice(0, 500);
    items.push({ name: `Gâteau sur mesure${customDetails.Occasion ? ` · ${customDetails.Occasion}` : ''}`, size: '', qty: 1, unit_price: 0, note: '', emoji: '🎂' });
    status = 'quote_pending';
    leadHours = 24;
  } else {
    const raw = Array.isArray(b.items) ? b.items : [];
    if (raw.length < 1 || raw.length > 40) throw httpErr(400, 'Panier vide ou trop grand.');
    const ids = raw.map((i) => String(i.product_id)).filter(isUuid);
    const found = (await q('SELECT * FROM products WHERE id = ANY($1::uuid[])', [ids])).rows;
    const byId = new Map(found.map((p) => [p.id, p]));
    for (const i of raw) {
      const p = byId.get(String(i.product_id));
      if (!p) throw httpErr(400, 'Un produit du panier n’existe plus.');
      if (!p.is_available) throw httpErr(400, `« ${p.name} » n’est plus disponible.`);
      const qty = int(i.qty, 0);
      if (qty < 1 || qty > 50) throw httpErr(400, 'Quantité invalide.');
      let unit = toXof(p.price, p.currency, settings);
      let sizeLabel = '';
      if (Array.isArray(p.sizes) && p.sizes.length) {
        const s = p.sizes.find((x) => x.label === String(i.size));
        if (!s) throw httpErr(400, `Taille invalide pour « ${p.name} ».`);
        unit = toXof(s.price, p.currency, settings);
        sizeLabel = s.label;
      }
      leadHours = Math.max(leadHours, p.prep_hours);
      subtotal += unit * qty;
      items.push({ name: p.name, size: sizeLabel, qty, unit_price: unit, note: String(i.note || '').slice(0, 200), emoji: p.emoji });
    }
  }

  if (when.getTime() < Date.now() + leadHours * 3600 * 1000 - 5 * 60 * 1000) {
    throw httpErr(400, `Délai minimum non respecté : commande possible à partir de ${leadHours} h.`);
  }
  let fee = 0;
  let distanceKm = null;
  let durationMin = null;
  if (type === 'delivery') {
    const avail = deliveryStatus(settings);
    if (!avail.ok) throw httpErr(409, avail.reason, { code: 'err_delivery_unavailable' });
    const info = await deliveryInfo(settings, dLat, dLng);
    distanceKm = info.km;
    if (settings.delivery_max_km > 0 && info.km != null && info.km > settings.delivery_max_km) {
      throw httpErr(400, `Hors zone de livraison (${settings.delivery_max_km} km maximum).`);
    }
    fee = info.fee;
    durationMin = info.min;
    // L'acheteur a accepté un tarif précis : s'il a changé entre-temps, il doit le revalider.
    if (b.accepted_fee !== undefined && b.accepted_fee !== null && Number(b.accepted_fee) !== fee) {
      throw httpErr(409, `Le tarif de livraison a changé (${fee} FCFA). Validez le nouveau tarif.`, { code: 'err_fee_changed' });
    }
  }
  const total = isCustom ? 0 : subtotal + fee;
  const wantsOnline = b.payment_method === 'online' && settings.online_payment && !isCustom
    && enabledProviders().length > 0 && (settings.allow_card || settings.allow_mobile_money);
  const paymentMethod = wantsOnline ? 'online' : 'cash';
  const paymentProvider = wantsOnline && enabledProviders().includes(b.payment_provider) ? b.payment_provider : '';
  const paymentChannel = wantsOnline && channelAllowed(String(b.payment_channel), settings) ? String(b.payment_channel) : '';
  // Le livreur ne manipule jamais d'argent : une livraison se paie en ligne.
  if (type === 'delivery' && !wantsOnline && !isCustom) {
    throw httpErr(400, 'La livraison se paie en ligne : le livreur ne manipule jamais d’argent.');
  }
  const deliveryCode = type === 'delivery' ? String(crypto.randomInt(1000, 10000)) : '';

  const { rows } = await q(
    `INSERT INTO orders (user_id, customer_name, phone, type, address, scheduled_at, payment_method, payment_provider, payment_channel, status, total, delivery_fee, note, items, is_custom, custom_details, delivery_lat, delivery_lng, delivery_code, distance_km, duration_min)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16::jsonb,$17,$18,$19,$20,$21) RETURNING *`,
    [req.user.id, req.user.name || 'Client', req.user.phone, type, type === 'delivery' ? address : '', when.toISOString(),
      paymentMethod, paymentProvider, paymentChannel, status, total, isCustom ? 0 : fee, note, JSON.stringify(items), isCustom, JSON.stringify(customDetails),
      dLat, dLng, deliveryCode, distanceKm, durationMin],
  );
  const created = rows[0];
  pushAdmins(isCustom ? 'a_custom' : 'a_new', orderVars(created), { type: 'order', order_id: created.id });
  res.status(201).json(created);
}));

app.get('/orders/mine', auth, wrap(async (req, res) => {
  res.json((await q('SELECT * FROM orders WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id])).rows);
}));

app.post('/orders/:id/accept-quote', auth, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Commande introuvable.');
  const { rows } = await q(
    `UPDATE orders SET status='confirmed', updated_at=now() WHERE id=$1 AND user_id=$2 AND status='quoted' RETURNING *`,
    [req.params.id, req.user.id],
  );
  if (!rows[0]) throw httpErr(400, 'Aucun devis à accepter pour cette commande.');
  pushAdmins('a_quote_accepted', orderVars(rows[0]), { type: 'order', order_id: rows[0].id });
  res.json(rows[0]);
}));

app.post('/orders/:id/cancel', auth, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Commande introuvable.');
  const { rows } = await q(
    `UPDATE orders SET status='cancelled', updated_at=now()
      WHERE id=$1 AND user_id=$2 AND status IN ('pending','quote_pending','quoted') AND payment_status='unpaid' RETURNING *`,
    [req.params.id, req.user.id],
  );
  if (!rows[0]) throw httpErr(400, 'Cette commande ne peut plus être annulée. Contactez la pâtisserie.');
  pushAdmins('a_cancelled', orderVars(rows[0]), { type: 'order', order_id: rows[0].id });
  res.json(rows[0]);
}));

app.post('/uploads/reference', auth, upload.single('image'), wrap(async (req, res) => {
  if (!req.file) throw httpErr(400, 'Aucune image reçue.');
  res.json({ url: await storeImage(req.file.buffer, `references/${req.user.id}`) });
}));

// ── Paiement en ligne : Flutterwave et Paystack ──────────────────────────────
// Les fournisseurs actifs sont ceux dont la clé secrète est définie sur le serveur.
// Le montant vient TOUJOURS de la base de données ; chaque paiement est vérifié auprès du fournisseur.
const PUBLIC_URL = (env.PUBLIC_URL || env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const PAY_CURRENCY = (env.PAYMENT_CURRENCY || 'XOF').toUpperCase();
const FLW_BASE = env.FLUTTERWAVE_BASE || 'https://api.flutterwave.com/v3';
const PSK_BASE = env.PAYSTACK_BASE || 'https://api.paystack.co';
// Paystack compte en « sous-unité » (×100) ; modifiable si votre devise l'exige.
const PSK_MULT = Math.max(1, int(env.PAYSTACK_AMOUNT_MULTIPLIER, 100));
const flwCurrency = () => (env.FLUTTERWAVE_CURRENCY || PAY_CURRENCY).toUpperCase();
const pskCurrency = () => (env.PAYSTACK_CURRENCY || PAY_CURRENCY).toUpperCase();

const enabledProviders = () => [env.FLUTTERWAVE_SECRET_KEY ? 'flutterwave' : null, env.PAYSTACK_SECRET_KEY ? 'paystack' : null].filter(Boolean);
const channelAllowed = (c, st) => (c === 'card' && !!st.allow_card) || (c === 'mobile_money' && !!st.allow_mobile_money);
// Flutterwave : option « mobile money » selon la devise (XOF/XAF = zone franc).
const FLW_MM = { XOF: 'mobilemoneyfranco', XAF: 'mobilemoneyfranco', GHS: 'mobilemoneyghana', RWF: 'mobilemoneyrwanda', UGX: 'mobilemoneyuganda', ZMW: 'mobilemoneyzambia', KES: 'mpesa' };
const flwOptions = (channel) => (channel === 'card' ? 'card' : channel === 'mobile_money' ? (env.FLUTTERWAVE_MOBILE_OPTION || FLW_MM[flwCurrency()] || 'mobilemoneyfranco') : undefined);
const pskChannels = (channel) => (channel === 'card' ? ['card'] : channel === 'mobile_money' ? ['mobile_money'] : undefined);
const emailFor = (user) => `client${digits(user.phone)}@${env.PAYMENT_EMAIL_DOMAIN || 'clients.patisserie.app'}`;
const flwHeaders = () => ({ Authorization: `Bearer ${env.FLUTTERWAVE_SECRET_KEY}`, 'Content-Type': 'application/json' });
const pskHeaders = () => ({ Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`, 'Content-Type': 'application/json' });
const jsonOf = (r) => r.json().catch(() => ({}));

async function startFlutterwave(order, user, shopName, channel) {
  const ref = `PAT-${order.code}-${Date.now()}`;
  const r = await fetch(`${FLW_BASE}/payments`, {
    method: 'POST',
    headers: flwHeaders(),
    body: JSON.stringify({
      tx_ref: ref,
      amount: order.total,
      currency: flwCurrency(),
      redirect_url: `${PUBLIC_URL}/pay/return`,
      payment_options: flwOptions(channel),
      customer: { email: emailFor(user), phonenumber: digits(order.phone), name: order.customer_name || 'Client' },
      customizations: { title: shopName, description: `Commande ${order.code}` },
      meta: { order_id: order.id, code: order.code },
    }),
  });
  const j = await jsonOf(r);
  const link = j && j.data && j.data.link;
  if (!r.ok || j.status !== 'success' || !link) throw httpErr(502, (j && j.message) || 'Flutterwave a refusé la transaction.');
  return { ref, url: link };
}

async function startPaystack(order, user, channel) {
  const ref = `PAT-${order.code}-${Date.now()}`;
  const r = await fetch(`${PSK_BASE}/transaction/initialize`, {
    method: 'POST',
    headers: pskHeaders(),
    body: JSON.stringify({
      email: emailFor(user),
      amount: order.total * PSK_MULT,
      currency: pskCurrency(),
      reference: ref,
      callback_url: `${PUBLIC_URL}/pay/return`,
      channels: pskChannels(channel),
      metadata: { order_id: order.id, code: order.code, customer: order.customer_name },
    }),
  });
  const j = await jsonOf(r);
  const url = j && j.data && j.data.authorization_url;
  if (!r.ok || j.status !== true || !url) throw httpErr(502, (j && j.message) || 'Paystack a refusé la transaction.');
  return { ref, url };
}

async function checkFlutterwave(order) {
  const r = await fetch(`${FLW_BASE}/transactions/verify_by_reference?tx_ref=${encodeURIComponent(order.payment_ref)}`, { headers: flwHeaders() });
  const j = await jsonOf(r);
  if (r.status === 404) return { paid: false, status: 'pending' };
  if (!r.ok) throw httpErr(502, (j && j.message) || 'Flutterwave injoignable.');
  const d = j.data || {};
  const paid = j.status === 'success' && d.status === 'successful' && Number(d.amount) >= order.total && String(d.currency).toUpperCase() === flwCurrency();
  return { paid, status: d.status };
}

async function checkPaystack(order) {
  const r = await fetch(`${PSK_BASE}/transaction/verify/${encodeURIComponent(order.payment_ref)}`, { headers: pskHeaders() });
  const j = await jsonOf(r);
  if (r.status === 404) return { paid: false, status: 'pending' };
  if (!r.ok) throw httpErr(502, (j && j.message) || 'Paystack injoignable.');
  const d = j.data || {};
  const paid = j.status === true && d.status === 'success' && Number(d.amount) >= order.total * PSK_MULT && String(d.currency).toUpperCase() === pskCurrency();
  return { paid, status: d.status };
}

/** Interroge le fournisseur et marque la commande payée si la transaction est confirmée (montant et devise identiques). */
async function confirmIfPaid(order) {
  if (!order.payment_ref || !order.payment_provider) return { paid: false, status: 'none' };
  let res;
  if (order.payment_provider === 'flutterwave' && env.FLUTTERWAVE_SECRET_KEY) res = await checkFlutterwave(order);
  else if (order.payment_provider === 'paystack' && env.PAYSTACK_SECRET_KEY) res = await checkPaystack(order);
  else throw httpErr(503, 'Fournisseur de paiement non configuré sur le serveur.');
  if (res.paid) {
    await q(
      `UPDATE orders SET payment_status='paid', status = CASE WHEN status='pending' THEN 'confirmed' ELSE status END, updated_at=now() WHERE id=$1`,
      [order.id],
    );
    pushUser(order.user_id, 'paid', orderVars(order), { type: 'order', order_id: order.id });
    pushAdmins('a_paid', orderVars(order), { type: 'order', order_id: order.id });
  }
  return res;
}

app.post('/orders/:id/pay', auth, wrap(async (req, res) => {
  const providers = enabledProviders();
  if (!providers.length) throw httpErr(503, 'Paiement en ligne non configuré sur le serveur.');
  if (!isUuid(req.params.id)) throw httpErr(404, 'Commande introuvable.');
  const order = (await q('SELECT * FROM orders WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id])).rows[0];
  if (!order) throw httpErr(404, 'Commande introuvable.');
  if (order.payment_status === 'paid') throw httpErr(400, 'Cette commande est déjà payée.');
  if (['cancelled', 'quote_pending', 'quoted'].includes(order.status)) throw httpErr(400, 'Cette commande ne peut pas être payée pour le moment.');
  if (!(order.total > 0)) throw httpErr(400, 'Montant invalide.');
  const settings = await getSettings();
  if (!settings.online_payment) throw httpErr(400, 'Le paiement en ligne n’est pas activé.');

  const wanted = String((req.body && req.body.provider) || order.payment_provider || '');
  const provider = providers.includes(wanted) ? wanted : providers.length === 1 ? providers[0] : null;
  if (!provider) throw httpErr(400, 'Choisissez un moyen de paiement (Flutterwave ou Paystack).');

  if (!settings.allow_card && !settings.allow_mobile_money) throw httpErr(400, 'Aucun moyen de paiement en ligne n’est activé.');
  const askedChannel = String((req.body && req.body.channel) || order.payment_channel || '');
  if (askedChannel && !channelAllowed(askedChannel, settings)) {
    throw httpErr(400, askedChannel === 'card' ? 'Le paiement par carte bancaire n’est pas activé.' : 'Le paiement par Mobile Money n’est pas activé.');
  }
  const channel = askedChannel;

  const started = provider === 'flutterwave'
    ? await startFlutterwave(order, req.user, settings.shop_name, channel)
    : await startPaystack(order, req.user, channel);
  await q(`UPDATE orders SET payment_method='online', payment_provider=$1, payment_channel=$2, payment_ref=$3, updated_at=now() WHERE id=$4`, [provider, channel, started.ref, order.id]);
  res.json({ url: started.url, provider, channel, reference: started.ref });
}));

app.post('/orders/:id/verify-payment', auth, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Commande introuvable.');
  const order = (await q('SELECT * FROM orders WHERE id=$1', [req.params.id])).rows[0];
  if (!order || (order.user_id !== req.user.id && req.user.role !== 'admin')) throw httpErr(404, 'Commande introuvable.');
  if (order.payment_status === 'paid') return res.json({ paid: true, status: 'paid' });
  return res.json(await confirmIfPaid(order));
}));

// Webhooks : on ne croit jamais le contenu reçu, on interroge le fournisseur avec la clé secrète.
async function handleWebhook(provider, ref) {
  if (!ref) return;
  const order = (await q('SELECT * FROM orders WHERE payment_ref=$1 AND payment_provider=$2', [String(ref), provider])).rows[0];
  if (order && order.payment_status !== 'paid') await confirmIfPaid(order);
}

app.post('/webhooks/flutterwave', wrap(async (req, res) => {
  const secretHash = env.FLUTTERWAVE_WEBHOOK_HASH;
  if (secretHash && req.headers['verif-hash'] !== secretHash) return res.status(401).send('signature invalide');
  try {
    const d = (req.body && req.body.data) || {};
    await handleWebhook('flutterwave', d.tx_ref || (req.body && req.body.tx_ref));
  } catch (e) {
    console.error('[webhook Flutterwave]', e.message);
  }
  return res.status(200).send('ok');
}));

app.post('/webhooks/paystack', wrap(async (req, res) => {
  const sig = req.headers['x-paystack-signature'];
  if (env.PAYSTACK_SECRET_KEY && sig) {
    const expected = crypto.createHmac('sha512', env.PAYSTACK_SECRET_KEY).update(req.rawBody || Buffer.from('')).digest('hex');
    if (sig !== expected) return res.status(401).send('signature invalide');
  }
  try {
    const d = (req.body && req.body.data) || {};
    await handleWebhook('paystack', d.reference);
  } catch (e) {
    console.error('[webhook Paystack]', e.message);
  }
  return res.status(200).send('ok');
}));

// Page affichée au client après le paiement (il revient ensuite dans l'application).
app.get('/pay/return', (_req, res) => {
  res.type('html').send(`<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Paiement</title>
<style>body{font-family:system-ui,sans-serif;background:#fff7f3;color:#3b2a2e;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;text-align:center}
.c{max-width:340px;padding:28px}h1{font-size:22px}p{color:#8a7478;line-height:1.5}</style></head>
<body><div class="c"><div style="font-size:56px">🧁</div><h1>Merci !</h1><p>Votre paiement est en cours de confirmation.<br>Revenez dans l’application : votre commande se met à jour automatiquement.</p></div></body></html>`);
});

// ── Espace propriétaire ──────────────────────────────────────────────────────
const admin = express.Router();
admin.use(auth, adminOnly);
admin.use((req, res, next) => {
  if (req.method !== 'GET') res.on('finish', () => bustCatalog());
  next();
});

admin.get('/orders', wrap(async (_req, res) => {
  res.json((await q('SELECT * FROM orders ORDER BY created_at DESC LIMIT 500')).rows);
}));

admin.patch('/orders/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Commande introuvable.');
  const cur = (await q('SELECT * FROM orders WHERE id=$1', [req.params.id])).rows[0];
  if (!cur) throw httpErr(404, 'Commande introuvable.');
  const sets = [];
  const vals = [];
  const add = (col, v) => { vals.push(v); sets.push(`${col}=$${vals.length}`); };
  const b = req.body || {};
  if (b.status !== undefined) {
    if (!STATUSES.includes(b.status)) throw httpErr(400, 'Statut invalide.');
    add('status', b.status);
  }
  if (b.total !== undefined) {
    const t = int(b.total, -1);
    if (t < 0) throw httpErr(400, 'Montant invalide.');
    add('total', t);
  }
  if (b.payment_status !== undefined) {
    if (!['paid', 'unpaid'].includes(b.payment_status)) throw httpErr(400, 'Statut de paiement invalide.');
    add('payment_status', b.payment_status);
  }
  if (!sets.length) throw httpErr(400, 'Rien à modifier.');
  const finalStatus = b.status !== undefined ? b.status : cur.status;
  const finalTotal = b.total !== undefined ? int(b.total) : cur.total;
  if (finalStatus === 'quoted' && finalTotal <= 0) throw httpErr(400, 'Indiquez un prix pour envoyer le devis.');
  const finalPaid = b.payment_status !== undefined ? b.payment_status === 'paid' : cur.payment_status === 'paid';
  if (cur.type === 'delivery' && ['ready', 'out_for_delivery'].includes(finalStatus) && !finalPaid) {
    throw httpErr(400, 'Une commande à livrer doit être payée en ligne avant de partir.');
  }
  sets.push('updated_at=now()');
  vals.push(req.params.id);
  const { rows } = await q(`UPDATE orders SET ${sets.join(', ')} WHERE id=$${vals.length} RETURNING *`, vals);
  const o = rows[0];
  if (b.status !== undefined && b.status !== cur.status) {
    notifyStatus(o);
    const ev = statusEvent(o);
    if (ev) pushUser(o.user_id, ev, orderVars(o), { type: 'order', order_id: o.id });
    if (o.status === 'ready' && o.courier_id) pushUser(o.courier_id, 'courier_ready', orderVars(o), { type: 'delivery', order_id: o.id });
  }
  res.json(o);
}));

// Catégories (= « grands noms » avec leur image) — envoi multipart possible
admin.post('/categories', upload.single('image'), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) throw httpErr(400, 'Nom requis.');
  const emoji = (String(req.body.emoji || '🍰').trim() || '🍰').slice(0, 8);
  const image = req.file ? await storeImage(req.file.buffer, 'categories') : null;
  const { rows } = await q('INSERT INTO categories (name, emoji, sort, image_url) VALUES ($1,$2,$3,$4) RETURNING *', [name, emoji, int(req.body.sort, 0), image]);
  res.status(201).json(rows[0]);
}));
admin.patch('/categories/:id', upload.single('image'), wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Catégorie introuvable.');
  const cur = (await q('SELECT image_url FROM categories WHERE id=$1', [req.params.id])).rows[0];
  if (!cur) throw httpErr(404, 'Catégorie introuvable.');
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) throw httpErr(400, 'Nom requis.');
  const emoji = (String(req.body.emoji || '🍰').trim() || '🍰').slice(0, 8);
  let image = cur.image_url;
  if (req.file) image = await storeImage(req.file.buffer, 'categories');
  else if (bool(req.body.remove_image)) image = null;
  const { rows } = await q('UPDATE categories SET name=$1, emoji=$2, sort=$3, image_url=$4 WHERE id=$5 RETURNING *', [name, emoji, int(req.body.sort, 0), image, req.params.id]);
  res.json(rows[0]);
}));
admin.delete('/categories/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Catégorie introuvable.');
  await q('DELETE FROM categories WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// Produits
function parseProduct(body) {
  const name = String(body.name || '').trim();
  if (!name) throw httpErr(400, 'Donnez un nom au produit.');
  let sizes = [];
  if (body.sizes) {
    try { sizes = JSON.parse(body.sizes); } catch (_) { throw httpErr(400, 'Tailles invalides.'); }
  }
  if (!Array.isArray(sizes)) throw httpErr(400, 'Tailles invalides.');
  sizes = sizes
    .map((s) => ({ label: String(s.label || '').trim().slice(0, 40), price: num2(s.price) }))
    .filter((s) => s.label && s.price > 0)
    .slice(0, 12);
  const price = Math.max(0, num2(body.price));
  const currency = CURRENCIES.includes(String(body.currency)) ? String(body.currency) : 'XOF';
  if (!sizes.length && price <= 0) throw httpErr(400, 'Indiquez un prix ou au moins une taille.');
  return {
    name: name.slice(0, 120),
    description: String(body.description || '').slice(0, 1000),
    category_id: isUuid(body.category_id) ? body.category_id : null,
    price,
    currency,
    sizes,
    emoji: (String(body.emoji || '🍰').trim() || '🍰').slice(0, 8),
    is_available: bool(body.is_available, true),
    is_featured: bool(body.is_featured, false),
    prep_hours: Math.min(720, Math.max(0, int(body.prep_hours, 24))),
  };
}

admin.post('/products', upload.single('image'), wrap(async (req, res) => {
  const p = parseProduct(req.body);
  await assertRateKnown(p.currency);
  const image = req.file ? await storeImage(req.file.buffer, 'products') : null;
  const { rows } = await q(
    `INSERT INTO products (name, description, category_id, price, currency, sizes, image_url, emoji, is_available, is_featured, prep_hours)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11) RETURNING *`,
    [p.name, p.description, p.category_id, p.price, p.currency, JSON.stringify(p.sizes), image, p.emoji, p.is_available, p.is_featured, p.prep_hours],
  );
  res.status(201).json(rows[0]);
}));

admin.patch('/products/:id', upload.single('image'), wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Produit introuvable.');
  const cur = (await q('SELECT image_url FROM products WHERE id=$1', [req.params.id])).rows[0];
  if (!cur) throw httpErr(404, 'Produit introuvable.');
  const p = parseProduct(req.body);
  await assertRateKnown(p.currency);
  let image = cur.image_url;
  if (req.file) image = await storeImage(req.file.buffer, 'products');
  else if (bool(req.body.remove_image)) image = null;
  const { rows } = await q(
    `UPDATE products SET name=$1, description=$2, category_id=$3, price=$4, currency=$5, sizes=$6::jsonb, image_url=$7, emoji=$8,
       is_available=$9, is_featured=$10, prep_hours=$11 WHERE id=$12 RETURNING *`,
    [p.name, p.description, p.category_id, p.price, p.currency, JSON.stringify(p.sizes), image, p.emoji, p.is_available, p.is_featured, p.prep_hours, req.params.id],
  );
  res.json(rows[0]);
}));

admin.delete('/products/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Produit introuvable.');
  await q('DELETE FROM products WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// Réglages
function cleanRates(input, prev) {
  const out = { ...(prev && typeof prev === 'object' ? prev : {}) };
  for (const c of CURRENCIES) {
    const n = Number(input[c]);
    if (Number.isFinite(n) && n > 0 && n < 1e9) out[c] = n;
  }
  return out;
}
admin.patch('/settings', wrap(async (req, res) => {
  const b = req.body || {};
  const cur = await getSettings();
  const pos = (v, d) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
  const coord = (v, d, max) => { if (v === null || v === '') return null; const n = Number(v); return Number.isFinite(n) && Math.abs(n) <= max ? n : d; };
  const next = {
    shop_name: b.shop_name !== undefined ? (String(b.shop_name).trim().slice(0, 80) || cur.shop_name) : cur.shop_name,
    is_open: b.is_open !== undefined ? bool(b.is_open, cur.is_open) : cur.is_open,
    delivery_fee: b.delivery_fee !== undefined ? Math.max(0, int(b.delivery_fee, cur.delivery_fee)) : cur.delivery_fee,
    delivery_per_km: b.delivery_per_km !== undefined ? Math.max(0, int(b.delivery_per_km, cur.delivery_per_km)) : cur.delivery_per_km,
    delivery_per_min: b.delivery_per_min !== undefined ? Math.max(0, int(b.delivery_per_min, cur.delivery_per_min)) : cur.delivery_per_min,
    delivery_extra: b.delivery_extra !== undefined ? Math.max(0, int(b.delivery_extra, cur.delivery_extra)) : cur.delivery_extra,
    rates: b.rates && typeof b.rates === 'object' ? cleanRates(b.rates, cur.rates) : cur.rates,
    delivery_max_km: b.delivery_max_km !== undefined ? Math.max(0, int(b.delivery_max_km, cur.delivery_max_km)) : cur.delivery_max_km,
    min_lead_hours: b.min_lead_hours !== undefined ? Math.min(720, Math.max(0, int(b.min_lead_hours, cur.min_lead_hours))) : cur.min_lead_hours,
    online_payment: b.online_payment !== undefined ? bool(b.online_payment, cur.online_payment) : cur.online_payment,
    allow_card: b.allow_card !== undefined ? bool(b.allow_card, cur.allow_card) : cur.allow_card,
    allow_mobile_money: b.allow_mobile_money !== undefined ? bool(b.allow_mobile_money, cur.allow_mobile_money) : cur.allow_mobile_money,
    rate_usd: b.rate_usd !== undefined ? pos(b.rate_usd, cur.rate_usd) : cur.rate_usd,
    rate_eur: b.rate_eur !== undefined ? pos(b.rate_eur, cur.rate_eur) : cur.rate_eur,
    rate_gbp: b.rate_gbp !== undefined ? pos(b.rate_gbp, cur.rate_gbp) : cur.rate_gbp,
    shop_lat: b.shop_lat !== undefined ? coord(b.shop_lat, cur.shop_lat, 90) : cur.shop_lat,
    shop_lng: b.shop_lng !== undefined ? coord(b.shop_lng, cur.shop_lng, 180) : cur.shop_lng,
    whatsapp: b.whatsapp !== undefined ? String(b.whatsapp).trim().slice(0, 30) : cur.whatsapp,
    opening_hours: b.opening_hours !== undefined ? String(b.opening_hours).trim().slice(0, 120) : cur.opening_hours,
    address: b.address !== undefined ? String(b.address).trim().slice(0, 200) : cur.address,
  };
  await q(
    `UPDATE shop_settings SET shop_name=$1, is_open=$2, delivery_fee=$3, delivery_per_km=$4, delivery_max_km=$5, min_lead_hours=$6,
       online_payment=$7, allow_card=$8, allow_mobile_money=$9, rate_usd=$10, rate_eur=$11, rate_gbp=$12, shop_lat=$13, shop_lng=$14,
       whatsapp=$15, opening_hours=$16, address=$17, delivery_per_min=$18, delivery_extra=$19, rates=$20::jsonb WHERE id=1`,
    [next.shop_name, next.is_open, next.delivery_fee, next.delivery_per_km, next.delivery_max_km, next.min_lead_hours, next.online_payment,
      next.allow_card, next.allow_mobile_money, next.rate_usd, next.rate_eur, next.rate_gbp, next.shop_lat, next.shop_lng,
      next.whatsapp, next.opening_hours, next.address, next.delivery_per_min, next.delivery_extra, JSON.stringify(next.rates || {})],
  );
  await kvDel('c:weather', 'c:settings');
  res.json(next);
}));

// Livreurs : numéros pré-enregistrés par la propriétaire (seuls ces numéros deviennent livreurs)
admin.get('/couriers', wrap(async (_req, res) => {
  res.json((await q(
    `SELECT u.id, c.phone, COALESCE(NULLIF(c.name,''), u.name) AS name, c.active
       FROM couriers c LEFT JOIN users u ON u.phone = c.phone ORDER BY c.created_at`,
  )).rows);
}));
admin.post('/couriers', wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  if (phone.length < 8 || phone.length > 15) throw httpErr(400, 'Numéro de téléphone invalide.');
  const name = String(req.body.name || '').trim().slice(0, 60);
  await q('INSERT INTO couriers (phone, name) VALUES ($1,$2) ON CONFLICT (phone) DO UPDATE SET name = EXCLUDED.name, active = true', [phone, name]);
  await q('INSERT INTO users (phone, name) VALUES ($1,$2) ON CONFLICT (phone) DO NOTHING', [phone, name]);
  const row = (await q(`SELECT u.id, c.phone, COALESCE(NULLIF(c.name,''), u.name) AS name, c.active FROM couriers c JOIN users u ON u.phone=c.phone WHERE c.phone=$1`, [phone])).rows[0];
  res.status(201).json(row);
}));
admin.patch('/couriers/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livreur introuvable.');
  const u = (await q('SELECT phone FROM users WHERE id=$1', [req.params.id])).rows[0];
  if (!u) throw httpErr(404, 'Livreur introuvable.');
  if (req.body.active !== undefined) await q('UPDATE couriers SET active=$1 WHERE phone=$2', [bool(req.body.active, true), u.phone]);
  if (req.body.name !== undefined) await q('UPDATE couriers SET name=$1 WHERE phone=$2', [String(req.body.name).trim().slice(0, 60), u.phone]);
  res.json({ ok: true });
}));
admin.delete('/couriers/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livreur introuvable.');
  await q('DELETE FROM couriers WHERE phone = (SELECT phone FROM users WHERE id=$1)', [req.params.id]);
  res.json({ ok: true });
}));

// Affecter une commande à livrer à un livreur (la commande doit être payée en ligne)
admin.post('/orders/:id/assign', wrap(async (req, res) => {
  if (!isUuid(req.params.id) || !isUuid(req.body.courier_id)) throw httpErr(400, 'Données invalides.');
  const o = (await q('SELECT * FROM orders WHERE id=$1', [req.params.id])).rows[0];
  if (!o) throw httpErr(404, 'Commande introuvable.');
  if (o.type !== 'delivery') throw httpErr(400, 'Cette commande est à retirer en boutique.');
  if (o.payment_status !== 'paid') throw httpErr(400, 'Une commande à livrer doit être payée en ligne avant d’être confiée à un livreur.');
  if (['completed', 'cancelled'].includes(o.status)) throw httpErr(400, 'Commande déjà clôturée.');
  const c = (await q('SELECT u.id FROM users u JOIN couriers c ON c.phone=u.phone AND c.active WHERE u.id=$1', [req.body.courier_id])).rows[0];
  if (!c) throw httpErr(400, 'Livreur inconnu ou désactivé.');
  const { rows } = await q('UPDATE orders SET courier_id=$1, assigned_at=now(), updated_at=now() WHERE id=$2 RETURNING *', [c.id, o.id]);
  pushUser(c.id, 'courier_new', orderVars(rows[0]), { type: 'delivery', order_id: o.id });
  res.json(rows[0]);
}));
// Code de livraison oublié : la responsable peut le renvoyer par SMS au client, ou valider la remise sans code.
const deliveryOrder = async (id) => {
  if (!isUuid(id)) throw httpErr(404, 'Commande introuvable.');
  const o = (await q('SELECT * FROM orders WHERE id=$1', [id])).rows[0];
  if (!o) throw httpErr(404, 'Commande introuvable.');
  if (o.type !== 'delivery' || !['ready', 'out_for_delivery'].includes(o.status)) throw httpErr(400, 'Cette commande n’est pas en cours de livraison.');
  return o;
};
admin.post('/orders/:id/delivery-code/sms', wrap(async (req, res) => {
  const o = await deliveryOrder(req.params.id);
  await sendSms(digits(o.phone), `Patisserie : votre code de livraison pour ${o.code} est ${o.delivery_code}. Donnez-le uniquement au livreur, à la remise.`);
  await kvDel(`dcode:${o.id}`); // remet à zéro les essais du livreur
  res.json({ ok: true });
}));
admin.post('/orders/:id/force-complete', wrap(async (req, res) => {
  const o = await deliveryOrder(req.params.id);
  if (o.status !== 'out_for_delivery') throw httpErr(400, 'La livraison doit être en route pour être validée sans code.');
  if (o.payment_status !== 'paid') throw httpErr(400, 'Commande non payée : validation impossible.');
  const reason = String((req.body && req.body.reason) || '').trim().slice(0, 300);
  if (reason.length < 5) throw httpErr(400, 'Indiquez le motif (ex. : client joint par téléphone, code perdu).');
  const { rows } = await q(`UPDATE orders SET status='completed', delivered_at=now(), delivery_override=true, delivery_override_note=$2, updated_at=now() WHERE id=$1 RETURNING *`, [o.id, reason]);
  await kvDel(`dcode:${o.id}`);
  console.log(`[Livraison] ${o.code} validée SANS code par la responsable. Motif : ${reason}`);
  pushUser(o.user_id, 'delivered', orderVars(rows[0]), { type: 'order', order_id: o.id });
  res.json(rows[0]);
}));
app.use('/admin', admin);

// ── Livreur : liste, démarrage, position en direct, fin de livraison ──────────
const courierView = (o) => ({
  id: o.id, code: o.code, status: o.status, customer_name: o.customer_name, phone: o.phone, address: o.address,
  delivery_lat: o.delivery_lat, delivery_lng: o.delivery_lng, scheduled_at: o.scheduled_at, note: o.note,
  distance_km: o.distance_km, assigned_at: o.assigned_at,
  items: (o.items || []).map((i) => ({ name: i.name, size: i.size, qty: i.qty, note: i.note, emoji: i.emoji })),
}); // jamais de prix ni de code de livraison pour le livreur

app.get('/courier/deliveries', auth, courierOnly, wrap(async (req, res) => {
  const { rows } = await q(
    `SELECT * FROM orders WHERE courier_id=$1 AND status IN ('ready','out_for_delivery') ORDER BY scheduled_at`,
    [req.user.id],
  );
  res.json(rows.map(courierView));
}));

app.post('/courier/deliveries/:id/start', auth, courierOnly, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livraison introuvable.');
  const { rows } = await q(
    `UPDATE orders SET status='out_for_delivery', updated_at=now() WHERE id=$1 AND courier_id=$2 AND status='ready' RETURNING *`,
    [req.params.id, req.user.id],
  );
  if (!rows[0]) throw httpErr(400, 'Cette livraison ne peut pas démarrer maintenant (commande pas encore prête ?).');
  pushUser(rows[0].user_id, 'out_for_delivery', orderVars(rows[0]), { type: 'order', order_id: rows[0].id });
  res.json(courierView(rows[0]));
}));


app.post('/courier/deliveries/:id/accept', auth, courierOnly, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livraison introuvable.');
  const { rows } = await q(
    `UPDATE orders SET courier_id=$2, assigned_at=COALESCE(assigned_at, now()), updated_at=now()
     WHERE id=$1 AND type='delivery' AND status IN ('ready','out_for_delivery')
       AND (courier_id IS NULL OR courier_id=$2)
     RETURNING *`,
    [req.params.id, req.user.id],
  );
  if (!rows[0]) throw httpErr(400, 'Course indisponible ou déjà prise.', { code: 'err_ride_unavailable' });
  pushAdmins('a_courier_accepted', orderVars(rows[0]), { type: 'order', order_id: rows[0].id });
  res.json(courierView(rows[0]));
}));

app.post('/courier/deliveries/:id/refuse', auth, courierOnly, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livraison introuvable.');
  const o = (await q(`SELECT * FROM orders WHERE id=$1 AND courier_id=$2 AND status IN ('ready','out_for_delivery')`, [req.params.id, req.user.id])).rows[0];
  if (!o) throw httpErr(404, 'Livraison introuvable.');
  if (o.status === 'out_for_delivery') throw httpErr(400, 'Course déjà démarrée : terminez-la avec le code client.', { code: 'err_ride_started' });
  await q(`UPDATE orders SET courier_id=NULL, assigned_at=NULL, updated_at=now() WHERE id=$1`, [o.id]);
  pushAdmins('a_courier_refused', orderVars(o), { type: 'order', order_id: o.id });
  res.json({ ok: true });
}));

// Navigation dans l'appli : itinéraire routier avec étapes (tracé + manœuvres traduites côté appli)
async function navRoute(lat1, lng1, lat2, lng2) {
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 9000);
    const r = await fetch(`${OSRM}/route/v1/driving/${lng1},${lat1};${lng2},${lat2}?overview=full&geometries=geojson&steps=true&alternatives=false&continue_straight=true`, { signal: ctl.signal });
    clearTimeout(timer);
    const j = await r.json();
    const rt = j.routes && j.routes[0];
    if (j.code === 'Ok' && rt && rt.geometry && rt.geometry.coordinates.length) {
      let pts = rt.geometry.coordinates.map(([lng, lat]) => [lat, lng]);
      if (pts.length > 1500) {
        const k = Math.ceil(pts.length / 1500);
        pts = pts.filter((_, i) => i % k === 0 || i === pts.length - 1);
      }
      const steps = [];
      for (const leg of rt.legs || []) {
        for (const s of leg.steps || []) {
          const loc = s.maneuver && s.maneuver.location;
          steps.push({
            type: (s.maneuver && s.maneuver.type) || '', modifier: (s.maneuver && s.maneuver.modifier) || '', name: s.name || '',
            distance_m: Math.round(s.distance || 0), duration_s: Math.round(s.duration || 0),
            lat: loc ? Number(loc[1]) : null, lng: loc ? Number(loc[0]) : null,
          });
        }
      }
      return { source: 'road', distance_km: Math.round(rt.distance / 100) / 10, duration_min: Math.max(1, Math.round(rt.duration / 60)), points: pts, steps };
    }
  } catch (_) { /* repli ligne droite */ }
  const km = haversineKm(lat1, lng1, lat2, lng2) * 1.25;
  return {
    source: 'estimate', distance_km: Math.round(km * 10) / 10, duration_min: Math.max(1, Math.round((km / 30) * 60)),
    points: [[lat1, lng1], [lat2, lng2]],
    steps: [
      { type: 'depart', modifier: '', name: '', distance_m: Math.round(km * 1000), duration_s: Math.round((km / 30) * 3600), lat: lat1, lng: lng1 },
      { type: 'arrive', modifier: '', name: '', distance_m: 0, duration_s: 0, lat: lat2, lng: lng2 },
    ],
  };
}
const routeLimiter = rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false });
app.post('/courier/deliveries/:id/route', auth, courierOnly, routeLimiter, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livraison introuvable.');
  const o = (await q(`SELECT * FROM orders WHERE id=$1 AND courier_id=$2 AND status IN ('ready','out_for_delivery')`, [req.params.id, req.user.id])).rows[0];
  if (!o || o.delivery_lat == null || o.delivery_lng == null) throw httpErr(404, 'Livraison introuvable.');
  let lat = Number(req.body.lat);
  let lng = Number(req.body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) {
    const st = await getSettings();
    if (st.shop_lat == null || st.shop_lng == null) throw httpErr(400, 'Position invalide.');
    lat = Number(st.shop_lat);
    lng = Number(st.shop_lng);
  }
  res.json(await navRoute(lat, lng, Number(o.delivery_lat), Number(o.delivery_lng)));
}));

app.post('/courier/location', auth, courierOnly, wrap(async (req, res) => {
  const lat = Number(req.body.lat);
  const lng = Number(req.body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) throw httpErr(400, 'Position invalide.');
  await kvSet(`courier:${req.user.id}`, { lat, lng, speed: Number(req.body.speed) || 0, heading: Number(req.body.heading) || 0, ts: Date.now() }, 180);
  res.json({ ok: true });
}));

app.post('/courier/deliveries/:id/complete', auth, courierOnly, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Livraison introuvable.');
  const o = (await q(`SELECT * FROM orders WHERE id=$1 AND courier_id=$2 AND status IN ('ready','out_for_delivery')`, [req.params.id, req.user.id])).rows[0];
  if (!o) throw httpErr(404, 'Livraison introuvable.');
  // Le client donne son code de livraison au livreur : preuve que la remise a eu lieu (5 essais maximum)
  const tries = (await kvGet(`dcode:${o.id}`)) || 0;
  if (tries >= 5) throw httpErr(429, 'Trop d’essais. Contactez la pâtisserie.', { code: 'err_code_tries' });
  if (String(req.body.code || '').trim() !== o.delivery_code) {
    await kvSet(`dcode:${o.id}`, tries + 1, 3600);
    throw httpErr(400, 'Code de livraison incorrect : demandez-le au client.', { code: 'err_code_wrong' });
  }
  const lat = Number(req.body.lat);
  const lng = Number(req.body.lng);
  const { rows } = await q(
    `UPDATE orders SET status='completed', delivered_at=now(), delivered_lat=$1, delivered_lng=$2, updated_at=now() WHERE id=$3 RETURNING *`,
    [Number.isFinite(lat) ? lat : null, Number.isFinite(lng) ? lng : null, o.id],
  );
  await kvDel(`dcode:${o.id}`);
  pushUser(o.user_id, 'delivered', orderVars(rows[0]), { type: 'order', order_id: o.id });
  pushAdmins('a_delivered', orderVars(rows[0]), { type: 'order', order_id: o.id });
  res.json({ ok: true }); // la commande disparaît de la liste du livreur (statut terminé)
}));

// Suivi en direct (client propriétaire de la commande, ou propriétaire de la boutique)
app.get('/orders/:id/tracking', auth, wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Commande introuvable.');
  const o = (await q('SELECT * FROM orders WHERE id=$1', [req.params.id])).rows[0];
  if (!o) throw httpErr(404, 'Commande introuvable.');
  const isOwner = req.user.role === 'admin';
  const isBuyer = o.user_id === req.user.id;
  const isCourier = o.courier_id === req.user.id;
  if (!isOwner && !isBuyer && !isCourier) throw httpErr(403, 'Accès refusé.');
  const settings = (await q('SELECT shop_lat, shop_lng FROM shop_settings WHERE id=1')).rows[0] || {};
  let pos = null;
  if (o.courier_id) pos = await kvGet(`courier:${o.courier_id}`);
  const out = {
    order_id: o.id,
    status: o.status,
    shop_lat: settings.shop_lat != null ? Number(settings.shop_lat) : null,
    shop_lng: settings.shop_lng != null ? Number(settings.shop_lng) : null,
    dest_lat: o.delivery_lat != null ? Number(o.delivery_lat) : null,
    dest_lng: o.delivery_lng != null ? Number(o.delivery_lng) : null,
    courier_lat: pos ? Number(pos.lat) : null,
    courier_lng: pos ? Number(pos.lng) : null,
    courier_heading: pos ? Number(pos.heading) || 0 : 0,
    courier_ts: pos ? pos.ts : null,
    // Code de livraison UNIQUEMENT pour l'acheteur (anti-chantage livreur)
    delivery_code: isBuyer && o.status !== 'completed' ? o.delivery_code : undefined,
  };
  // Distance / ETA temps réel
  if (out.courier_lat != null && out.dest_lat != null) {
    try {
      const r = await roadRoute(out.courier_lat, out.courier_lng, out.dest_lat, out.dest_lng);
      out.remaining_km = Math.round(r.km * 10) / 10;
      out.remaining_min = Math.round(r.min);
    } catch (_) {
      const km = haversineKm(out.courier_lat, out.courier_lng, out.dest_lat, out.dest_lng);
      out.remaining_km = Math.round(km * 10) / 10;
      out.remaining_min = Math.round((km / 25) * 60);
    }
  }
  res.json(out);
}));

// ── Notifications push (Firebase Cloud Messaging, API HTTP v1) ───────────────
const FCM_ENABLED = !!(env.FIREBASE_PROJECT_ID && env.FIREBASE_CLIENT_EMAIL && env.FIREBASE_PRIVATE_KEY);
const GOOGLE_TOKEN_URL = env.GOOGLE_TOKEN_URL || 'https://oauth2.googleapis.com/token';
const FCM_BASE = env.FCM_BASE || 'https://fcm.googleapis.com';
let fcmAuth = { token: null, exp: 0 };
async function fcmAccessToken() {
  if (fcmAuth.token && Date.now() < fcmAuth.exp - 60000) return fcmAuth.token;
  const now = Math.floor(Date.now() / 1000);
  const assertion = jwt.sign(
    { iss: env.FIREBASE_CLIENT_EMAIL, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: GOOGLE_TOKEN_URL, iat: now, exp: now + 3600 },
    env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    { algorithm: 'RS256' },
  );
  const r = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }),
  });
  const j = await jsonOf(r);
  if (!r.ok || !j.access_token) throw new Error((j && (j.error_description || j.error)) || 'jeton Google refusé');
  fcmAuth = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return fcmAuth.token;
}

// Textes des notifications par langue (repli : français). Variables : {code} {total} {addr} {name}
const PUSH = {
  confirmed: { fr: ['Commande confirmée ✔', '{code} a été confirmée.'], en: ['Order confirmed ✔', '{code} has been confirmed.'], es: ['Pedido confirmado ✔', '{code} ha sido confirmado.'], pt: ['Pedido confirmado ✔', '{code} foi confirmado.'], ar: ['تم تأكيد الطلب ✔', 'تم تأكيد الطلب {code}.'], zh: ['订单已确认 ✔', '订单 {code} 已确认。'], ha: ['An tabbatar da odarka ✔', 'An tabbatar da {code}.'], yo: ['A ti jẹ́rìí ìbéèrè rẹ ✔', 'A ti jẹ́rìí {code}.'] },
  preparing: { fr: ['En préparation 👩‍🍳', '{code} est en cours de préparation.'], en: ['Being prepared 👩‍🍳', '{code} is being prepared.'], es: ['En preparación 👩‍🍳', '{code} se está preparando.'], pt: ['Em preparação 👩‍🍳', '{code} está a ser preparado.'], ar: ['قيد التحضير 👩‍🍳', 'الطلب {code} قيد التحضير.'], zh: ['制作中 👩‍🍳', '订单 {code} 正在制作。'], ha: ['Ana shirya odarka 👩‍🍳', 'Ana shirya {code}.'], yo: ['À ń ṣe ìbéèrè rẹ 👩‍🍳', 'À ń ṣe {code}.'] },
  ready_pickup: { fr: ['Prête à retirer 🎂', '{code} vous attend en boutique.'], en: ['Ready for pickup 🎂', '{code} is waiting for you in the shop.'], es: ['Listo para recoger 🎂', '{code} te espera en la tienda.'], pt: ['Pronto para levantar 🎂', '{code} espera por si na loja.'], ar: ['جاهز للاستلام 🎂', 'الطلب {code} في انتظارك في المتجر.'], zh: ['可取货 🎂', '订单 {code} 已在店内等您。'], ha: ['Ya shirya, zo ka karɓa 🎂', '{code} yana jiranka a shago.'], yo: ['Ó ti ṣetán 🎂', '{code} ń dúró dè ọ́ ní ṣọ́ọ̀bù.'] },
  ready_delivery: { fr: ['Prête à partir 🚚', '{code} va être remise au livreur.'], en: ['Ready to go 🚚', '{code} will be handed to the courier.'], es: ['Listo para salir 🚚', '{code} se entregará al repartidor.'], pt: ['Pronto para sair 🚚', '{code} vai ser entregue ao estafeta.'], ar: ['جاهز للانطلاق 🚚', 'سيُسلَّم الطلب {code} إلى المندوب.'], zh: ['准备出发 🚚', '订单 {code} 即将交给配送员。'], ha: ['Ya shirya za a tafi 🚚', 'Za a ba mai kai kaya {code}.'], yo: ['Ó ti ṣetán láti jáde 🚚', 'A ó fi {code} fún olùgbéránṣẹ́.'] },
  out_for_delivery: { fr: ['En route 🚚', 'Le livreur est en chemin avec {code}.'], en: ['On the way 🚚', 'The courier is on the way with {code}.'], es: ['En camino 🚚', 'El repartidor va en camino con {code}.'], pt: ['A caminho 🚚', 'O estafeta vai a caminho com {code}.'], ar: ['في الطريق 🚚', 'المندوب في طريقه إليك بالطلب {code}.'], zh: ['配送中 🚚', '配送员正带着订单 {code} 赶来。'], ha: ['Yana kan hanya 🚚', 'Mai kai kaya yana kan hanya da {code}.'], yo: ['Ó wà lójú ọ̀nà 🚚', 'Olùgbéránṣẹ́ wà lójú ọ̀nà pẹ̀lú {code}.'] },
  completed: { fr: ['Merci ! 🧁', '{code} est terminée. Bon appétit !'], en: ['Thank you! 🧁', '{code} is complete. Enjoy!'], es: ['¡Gracias! 🧁', '{code} está completado. ¡Buen provecho!'], pt: ['Obrigado! 🧁', '{code} está concluído. Bom apetite!'], ar: ['شكرًا لك! 🧁', 'اكتمل الطلب {code}. بالهناء والشفاء!'], zh: ['谢谢！🧁', '订单 {code} 已完成，祝您好胃口！'], ha: ['Mun gode! 🧁', 'An kammala {code}. Ci abinci lafiya!'], yo: ['Ẹ ṣé! 🧁', '{code} ti parí. Ẹ jẹun dáadáa!'] },
  delivered: { fr: ['Livrée ✔', '{code} a été livrée. Bon appétit !'], en: ['Delivered ✔', '{code} has been delivered. Enjoy!'], es: ['Entregado ✔', '{code} ha sido entregado. ¡Buen provecho!'], pt: ['Entregue ✔', '{code} foi entregue. Bom apetite!'], ar: ['تم التسليم ✔', 'تم تسليم الطلب {code}. بالهناء والشفاء!'], zh: ['已送达 ✔', '订单 {code} 已送达，祝您好胃口！'], ha: ['An kawo ✔', 'An kawo {code}. Ci abinci lafiya!'], yo: ['A ti fi ránṣẹ́ ✔', 'A ti fi {code} ránṣẹ́. Ẹ jẹun dáadáa!'] },
  cancelled: { fr: ['Commande annulée', '{code} a été annulée.'], en: ['Order cancelled', '{code} has been cancelled.'], es: ['Pedido cancelado', '{code} ha sido cancelado.'], pt: ['Pedido cancelado', '{code} foi cancelado.'], ar: ['تم إلغاء الطلب', 'تم إلغاء الطلب {code}.'], zh: ['订单已取消', '订单 {code} 已取消。'], ha: ['An soke odar', 'An soke {code}.'], yo: ['A ti fagilé ìbéèrè', 'A ti fagilé {code}.'] },
  quoted: { fr: ['Votre devis est prêt 💬', '{code} : {total}. Ouvrez l’application pour répondre.'], en: ['Your quote is ready 💬', '{code}: {total}. Open the app to reply.'], es: ['Tu presupuesto está listo 💬', '{code}: {total}. Abre la app para responder.'], pt: ['O seu orçamento está pronto 💬', '{code}: {total}. Abra a aplicação para responder.'], ar: ['عرض السعر جاهز 💬', '{code}: {total}. افتح التطبيق للرد.'], zh: ['您的报价已就绪 💬', '{code}：{total}。请打开应用回复。'], ha: ['Farashin ya shirya 💬', '{code}: {total}. Bude manhajar don amsawa.'], yo: ['Iye owó ti ṣetán 💬', '{code}: {total}. Ṣí ohun èlò náà láti dáhùn.'] },
  paid: { fr: ['Paiement reçu ✔', 'Merci ! Le paiement de {code} est confirmé.'], en: ['Payment received ✔', 'Thank you! Payment for {code} is confirmed.'], es: ['Pago recibido ✔', '¡Gracias! El pago de {code} está confirmado.'], pt: ['Pagamento recebido ✔', 'Obrigado! O pagamento de {code} está confirmado.'], ar: ['تم استلام الدفع ✔', 'شكرًا! تم تأكيد دفع الطلب {code}.'], zh: ['已收到付款 ✔', '谢谢！订单 {code} 的付款已确认。'], ha: ['An karɓi biyan kuɗi ✔', 'Mun gode! An tabbatar da biyan {code}.'], yo: ['A ti gba owó rẹ ✔', 'Ẹ ṣé! A ti jẹ́rìí owó {code}.'] },
  courier_new: { fr: ['Nouvelle livraison 🚚', '{code} · {addr}'], en: ['New delivery 🚚', '{code} · {addr}'], es: ['Nueva entrega 🚚', '{code} · {addr}'], pt: ['Nova entrega 🚚', '{code} · {addr}'], ar: ['توصيلة جديدة 🚚', '{code} · {addr}'], zh: ['新的配送任务 🚚', '{code} · {addr}'], ha: ['Sabon isar da kaya 🚚', '{code} · {addr}'], yo: ['Ìfijíṣẹ́ tuntun 🚚', '{code} · {addr}'] },
  courier_ready: { fr: ['Commande prête 🎂', '{code} est prête : venez la récupérer.'], en: ['Order ready 🎂', '{code} is ready: come and pick it up.'], es: ['Pedido listo 🎂', '{code} está listo: ven a recogerlo.'], pt: ['Pedido pronto 🎂', '{code} está pronto: venha buscá-lo.'], ar: ['الطلب جاهز 🎂', 'الطلب {code} جاهز: تعال لاستلامه.'], zh: ['订单已备好 🎂', '订单 {code} 已备好，请前来取件。'], ha: ['Odar ta shirya 🎂', '{code} ta shirya: zo ka ɗauka.'], yo: ['Ìbéèrè ti ṣetán 🎂', '{code} ti ṣetán: wá gbà á.'] },
  a_new: { fr: ['Nouvelle commande 🧁', '{name} · {code} · {total}'], en: ['New order 🧁', '{name} · {code} · {total}'] },
  a_custom: { fr: ['Demande sur mesure ✨', '{name} · {code}'], en: ['Custom cake request ✨', '{name} · {code}'] },
  a_paid: { fr: ['Paiement reçu 💰', '{code} · {total}'], en: ['Payment received 💰', '{code} · {total}'] },
  a_delivered: { fr: ['Livraison terminée ✔', '{code} remise à {name} (code client confirmé).'], en: ['Delivery completed ✔', '{code} handed to {name} (customer code confirmed).'] },
  a_quote_accepted: { fr: ['Devis accepté ✔', '{code} · {total}'], en: ['Quote accepted ✔', '{code} · {total}'] },
  a_cancelled: { fr: ['Commande annulée', '{code} annulée par le client.'], en: ['Order cancelled', '{code} cancelled by the customer.'] },
};
const fmtTotal = (n) => `${Number(n || 0).toLocaleString('fr-FR').replace(/[\u202f\u00a0]/g, ' ')} FCFA`;
function orderVars(o) {
  return { code: o.code, total: fmtTotal(o.total), addr: o.address || '', name: o.customer_name || '' };
}
function statusEvent(o) {
  const m = { confirmed: 'confirmed', preparing: 'preparing', ready: o.type === 'delivery' ? 'ready_delivery' : 'ready_pickup', out_for_delivery: 'out_for_delivery', completed: o.type === 'delivery' ? 'delivered' : 'completed', cancelled: 'cancelled', quoted: 'quoted' };
  return m[o.status] || null;
}
function renderPush(ev, lang, vars) {
  const t = PUSH[ev];
  if (!t) return null;
  const pair = t[lang] || t.fr;
  const fill = (str) => str.replace(/\{(\w+)\}/g, (_m, k) => (vars[k] != null ? String(vars[k]) : ''));
  return { title: fill(pair[0]), body: fill(pair[1]) };
}

async function sendPush(userIds, event, vars, data = {}) {
  if (!FCM_ENABLED || !userIds.length) return;
  try {
    const { rows } = await q(
      `SELECT d.token, u.lang FROM device_tokens d JOIN users u ON u.id = d.user_id WHERE d.user_id = ANY($1::uuid[])`,
      [userIds],
    );
    if (!rows.length) return;
    const access = await fcmAccessToken();
    const strData = Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)]));
    for (const { token, lang } of rows) {
      const msg = renderPush(event, lang, vars);
      if (!msg) continue;
      const r = await fetch(`${FCM_BASE}/v1/projects/${env.FIREBASE_PROJECT_ID}/messages:send`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: { token, notification: { title: msg.title, body: msg.body }, data: strData, android: { priority: 'HIGH', notification: { sound: 'default' } } } }),
      });
      if (!r.ok) {
        const j = await jsonOf(r);
        const code = j && j.error && ((j.error.details && j.error.details[0] && j.error.details[0].errorCode) || j.error.status);
        if (r.status === 404 || code === 'UNREGISTERED' || code === 'NOT_FOUND') await q('DELETE FROM device_tokens WHERE token=$1', [token]);
        else console.error('[FCM]', r.status, JSON.stringify(j).slice(0, 200));
      }
    }
  } catch (e) {
    console.error('[push]', e.message);
  }
}
function pushUser(userId, event, vars, data) {
  if (userId) sendPush([userId], event, vars, data).catch(() => {});
}
function pushAdmins(event, vars, data) {
  q(`SELECT id FROM users WHERE role='admin'`).then((r) => sendPush(r.rows.map((x) => x.id), event, vars, data)).catch(() => {});
}

// ── Erreurs ──────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route introuvable.' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err && err.name === 'MulterError') {
    const big = err.code === 'LIMIT_FILE_SIZE';
    return res.status(big ? 413 : 400).json({ error: big ? 'Photo trop volumineuse (8 Mo maximum).' : 'Envoi du fichier impossible.' });
  }
  const status = err.status || 500;
  if (status >= 500) console.error(`[Erreur] ${req.method} ${req.originalUrl}`, err);
  const body = { error: status >= 500 && !err.status ? 'Erreur interne du serveur.' : err.message };
  if (err.code) body.code = err.code;
  if (err.retry_after != null) body.retry_after = err.retry_after;
  res.status(status).json(body);
});

// ── Démarrage ────────────────────────────────────────────────────────────────
(async () => {
  try {
    await migrate();
    await seedResponsable();
    await ensureBucket();
    if (!env.ADMIN_PHONE) console.warn('⚠️  ADMIN_PHONE est vide : personne ne peut s’inscrire comme responsable.');
    if (!enabledProviders().length) console.warn('⚠️  Aucune clé de paiement (Flutterwave/Paystack) : la livraison est désactivée tant que le paiement en ligne n’est pas configuré.');
    if (env.OTP_DEBUG === 'true' && IS_PROD) console.warn('⚠️  OTP_DEBUG ignoré en production (sécurité).');
    app.listen(PORT, '0.0.0.0', () => console.log(`✅ API pâtisserie démarrée sur le port ${PORT}`));
  } catch (e) {
    console.error('❌ Démarrage impossible :', e.message);
    process.exit(1);
  }
})();
