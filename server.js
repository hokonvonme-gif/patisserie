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
const multer = require('multer');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

const env = process.env;
const PORT = Number(env.PORT) || 3000;
const IS_PROD = env.NODE_ENV === 'production';
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
const q = (text, params) => pool.query(text, params);

// ── Utilitaires ──────────────────────────────────────────────────────────────
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const digits = (s) => String(s || '').replace(/\D/g, '');
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s));
const int = (v, d = 0) => {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : d;
};
const bool = (v, d = false) => (v === true || v === 'true' || v === '1' ? true : v === false || v === 'false' || v === '0' ? false : d);
const hashOtp = (code) => crypto.createHash('sha256').update(`${code}:${JWT_SECRET}`).digest('hex');

const STATUSES = ['pending', 'confirmed', 'preparing', 'ready', 'out_for_delivery', 'completed', 'cancelled', 'quote_pending', 'quoted'];

// ── Base de données : création automatique des tables ────────────────────────
async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      phone text UNIQUE NOT NULL,
      name text NOT NULL DEFAULT '',
      role text NOT NULL DEFAULT 'client' CHECK (role IN ('client','admin')),
      created_at timestamptz NOT NULL DEFAULT now()
    );

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
  `);
}

// ── SMS (Vonage) ─────────────────────────────────────────────────────────────
async function sendSms(phone, text) {
  const key = env.VONAGE_API_KEY;
  const secret = env.VONAGE_API_SECRET;
  if (!key || !secret) {
    if (IS_PROD) throw httpErr(503, 'Envoi de SMS non configuré sur le serveur (VONAGE_API_KEY / VONAGE_API_SECRET).');
    console.log(`[SMS — mode développement] +${phone} : ${text}`);
    return;
  }
  const r = await fetch('https://rest.nexmo.com/sms/json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ api_key: key, api_secret: secret, to: phone, from: env.VONAGE_FROM || 'Patisserie', text }),
  });
  const j = await r.json().catch(() => ({}));
  const m = j && j.messages && j.messages[0];
  if (!m || m.status !== '0') {
    console.error('[SMS] échec :', m);
    throw httpErr(502, 'Le SMS n’a pas pu être envoyé. Réessayez dans un instant.');
  }
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
  const { rows } = await q('SELECT id, phone, name, role FROM users WHERE id=$1', [payload.sub]);
  if (!rows[0]) throw httpErr(401, 'Compte introuvable.');
  req.user = rows[0];
  next();
});
const adminOnly = (req, _res, next) => (req.user && req.user.role === 'admin' ? next() : next(httpErr(403, 'Réservé à la propriétaire.')));

app.post('/auth/request-otp', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  if (phone.length < 8 || phone.length > 15) throw httpErr(400, 'Numéro de téléphone invalide.');
  const prev = (await q('SELECT last_sent FROM otp_codes WHERE phone=$1', [phone])).rows[0];
  if (prev && Date.now() - new Date(prev.last_sent).getTime() < 60 * 1000) {
    throw httpErr(429, 'Patientez une minute avant de redemander un code.');
  }
  const code = String(crypto.randomInt(100000, 1000000));
  await q(
    `INSERT INTO otp_codes (phone, code_hash, expires_at, tries, last_sent)
     VALUES ($1, $2, now() + interval '5 minutes', 0, now())
     ON CONFLICT (phone) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, tries = 0, last_sent = now()`,
    [phone, hashOtp(code)],
  );
  // Remplissage automatique Android : « <#> … » + empreinte de l'application en fin de message
  const appHash = String(req.body.app_hash || '').trim();
  const withHash = /^[A-Za-z0-9+/=]{11}$/.test(appHash);
  const text = `${withHash ? '<#> ' : ''}${env.SMS_BRAND || 'Patisserie'}: votre code est ${code} (valide 5 min).${withHash ? `\n${appHash}` : ''}`;
  await sendSms(phone, text);
  res.json({ ok: true });
}));

app.post('/auth/verify-otp', otpLimiter, wrap(async (req, res) => {
  const phone = digits(req.body.phone);
  const code = String(req.body.code || '').trim();
  const o = (await q('SELECT * FROM otp_codes WHERE phone=$1', [phone])).rows[0];
  if (!o || new Date(o.expires_at) < new Date()) throw httpErr(400, 'Code expiré : demandez-en un nouveau.');
  if (o.tries >= 5) throw httpErr(429, 'Trop d’essais : demandez un nouveau code.');
  if (o.code_hash !== hashOtp(code)) {
    await q('UPDATE otp_codes SET tries = tries + 1 WHERE phone=$1', [phone]);
    throw httpErr(400, 'Code incorrect.');
  }
  await q('DELETE FROM otp_codes WHERE phone=$1', [phone]);

  const isAdmin = !!env.ADMIN_PHONE && digits(env.ADMIN_PHONE) === phone;
  const name = String(req.body.name || '').trim().slice(0, 60);
  const user = (await q(
    `INSERT INTO users (phone, name, role) VALUES ($1, $2, $3)
     ON CONFLICT (phone) DO UPDATE SET
       role = CASE WHEN $4::boolean THEN 'admin' ELSE users.role END,
       name = CASE WHEN users.name = '' AND $2 <> '' THEN $2 ELSE users.name END
     RETURNING id, phone, name, role`,
    [phone, name, isAdmin ? 'admin' : 'client', isAdmin],
  )).rows[0];
  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, user });
}));

app.get('/me', auth, (req, res) => res.json(req.user));
app.patch('/me', auth, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) throw httpErr(400, 'Prénom requis.');
  const { rows } = await q('UPDATE users SET name=$1 WHERE id=$2 RETURNING id, phone, name, role', [name, req.user.id]);
  res.json(rows[0]);
}));

// ── Catalogue (public) ───────────────────────────────────────────────────────
app.get('/categories', wrap(async (_req, res) => {
  res.json((await q('SELECT id, name, emoji, sort FROM categories ORDER BY sort, name')).rows);
}));
app.get('/products', wrap(async (_req, res) => {
  res.json((await q(
    `SELECT id, name, description, category_id, price, sizes, image_url, emoji, is_available, is_featured, prep_hours
       FROM products ORDER BY created_at`,
  )).rows);
}));
const getSettings = async () => (await q('SELECT * FROM shop_settings WHERE id=1')).rows[0];
app.get('/settings', wrap(async (_req, res) => {
  const s = await getSettings();
  delete s.id;
  s.payment_providers = enabledProviders(); // ex. ['flutterwave','paystack'] (clés présentes sur le serveur)
  res.json(s);
}));

// ── Commandes (client) ───────────────────────────────────────────────────────
app.post('/orders', auth, wrap(async (req, res) => {
  const b = req.body || {};
  const type = b.type === 'delivery' ? 'delivery' : 'pickup';
  const address = String(b.address || '').trim().slice(0, 300);
  if (type === 'delivery' && address.length < 5) throw httpErr(400, 'Indiquez l’adresse de livraison.');
  const when = new Date(b.scheduled_at);
  if (Number.isNaN(when.getTime())) throw httpErr(400, 'Date et heure invalides.');
  const settings = await getSettings();
  const note = String(b.note || '').trim().slice(0, 500);
  const isCustom = b.is_custom === true;

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
      let unit = p.price;
      let sizeLabel = '';
      if (Array.isArray(p.sizes) && p.sizes.length) {
        const s = p.sizes.find((x) => x.label === String(i.size));
        if (!s) throw httpErr(400, `Taille invalide pour « ${p.name} ».`);
        unit = s.price;
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
  const fee = type === 'delivery' ? settings.delivery_fee : 0;
  const total = isCustom ? 0 : subtotal + fee;
  const wantsOnline = b.payment_method === 'online' && settings.online_payment && !isCustom
    && enabledProviders().length > 0 && (settings.allow_card || settings.allow_mobile_money);
  const paymentMethod = wantsOnline ? 'online' : 'cash';
  const paymentProvider = wantsOnline && enabledProviders().includes(b.payment_provider) ? b.payment_provider : '';
  const paymentChannel = wantsOnline && channelAllowed(String(b.payment_channel), settings) ? String(b.payment_channel) : '';

  const { rows } = await q(
    `INSERT INTO orders (user_id, customer_name, phone, type, address, scheduled_at, payment_method, payment_provider, payment_channel, status, total, delivery_fee, note, items, is_custom, custom_details)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15,$16::jsonb) RETURNING *`,
    [req.user.id, req.user.name || 'Client', req.user.phone, type, type === 'delivery' ? address : '', when.toISOString(),
      paymentMethod, paymentProvider, paymentChannel, status, total, isCustom ? 0 : fee, note, JSON.stringify(items), isCustom, JSON.stringify(customDetails)],
  );
  res.status(201).json(rows[0]);
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
  sets.push('updated_at=now()');
  vals.push(req.params.id);
  const { rows } = await q(`UPDATE orders SET ${sets.join(', ')} WHERE id=$${vals.length} RETURNING *`, vals);
  if (b.status !== undefined && b.status !== cur.status) notifyStatus(rows[0]);
  res.json(rows[0]);
}));

// Catégories
admin.post('/categories', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) throw httpErr(400, 'Nom requis.');
  const emoji = (String(req.body.emoji || '🍰').trim() || '🍰').slice(0, 8);
  const { rows } = await q('INSERT INTO categories (name, emoji, sort) VALUES ($1,$2,$3) RETURNING *', [name, emoji, int(req.body.sort, 0)]);
  res.status(201).json(rows[0]);
}));
admin.patch('/categories/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Catégorie introuvable.');
  const name = String(req.body.name || '').trim().slice(0, 60);
  if (!name) throw httpErr(400, 'Nom requis.');
  const emoji = (String(req.body.emoji || '🍰').trim() || '🍰').slice(0, 8);
  const { rows } = await q('UPDATE categories SET name=$1, emoji=$2, sort=$3 WHERE id=$4 RETURNING *', [name, emoji, int(req.body.sort, 0), req.params.id]);
  if (!rows[0]) throw httpErr(404, 'Catégorie introuvable.');
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
    .map((s) => ({ label: String(s.label || '').trim().slice(0, 40), price: int(s.price, 0) }))
    .filter((s) => s.label && s.price > 0)
    .slice(0, 12);
  const price = Math.max(0, int(body.price, 0));
  if (!sizes.length && price <= 0) throw httpErr(400, 'Indiquez un prix ou au moins une taille.');
  return {
    name: name.slice(0, 120),
    description: String(body.description || '').slice(0, 1000),
    category_id: isUuid(body.category_id) ? body.category_id : null,
    price,
    sizes,
    emoji: (String(body.emoji || '🍰').trim() || '🍰').slice(0, 8),
    is_available: bool(body.is_available, true),
    is_featured: bool(body.is_featured, false),
    prep_hours: Math.min(720, Math.max(0, int(body.prep_hours, 24))),
  };
}

admin.post('/products', upload.single('image'), wrap(async (req, res) => {
  const p = parseProduct(req.body);
  const image = req.file ? await storeImage(req.file.buffer, 'products') : null;
  const { rows } = await q(
    `INSERT INTO products (name, description, category_id, price, sizes, image_url, emoji, is_available, is_featured, prep_hours)
     VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10) RETURNING *`,
    [p.name, p.description, p.category_id, p.price, JSON.stringify(p.sizes), image, p.emoji, p.is_available, p.is_featured, p.prep_hours],
  );
  res.status(201).json(rows[0]);
}));

admin.patch('/products/:id', upload.single('image'), wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Produit introuvable.');
  const cur = (await q('SELECT image_url FROM products WHERE id=$1', [req.params.id])).rows[0];
  if (!cur) throw httpErr(404, 'Produit introuvable.');
  const p = parseProduct(req.body);
  let image = cur.image_url;
  if (req.file) image = await storeImage(req.file.buffer, 'products');
  else if (bool(req.body.remove_image)) image = null;
  const { rows } = await q(
    `UPDATE products SET name=$1, description=$2, category_id=$3, price=$4, sizes=$5::jsonb, image_url=$6, emoji=$7,
       is_available=$8, is_featured=$9, prep_hours=$10 WHERE id=$11 RETURNING *`,
    [p.name, p.description, p.category_id, p.price, JSON.stringify(p.sizes), image, p.emoji, p.is_available, p.is_featured, p.prep_hours, req.params.id],
  );
  res.json(rows[0]);
}));

admin.delete('/products/:id', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw httpErr(404, 'Produit introuvable.');
  await q('DELETE FROM products WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// Réglages
admin.patch('/settings', wrap(async (req, res) => {
  const b = req.body || {};
  const cur = await getSettings();
  const next = {
    shop_name: b.shop_name !== undefined ? (String(b.shop_name).trim().slice(0, 80) || cur.shop_name) : cur.shop_name,
    is_open: b.is_open !== undefined ? bool(b.is_open, cur.is_open) : cur.is_open,
    delivery_fee: b.delivery_fee !== undefined ? Math.max(0, int(b.delivery_fee, cur.delivery_fee)) : cur.delivery_fee,
    min_lead_hours: b.min_lead_hours !== undefined ? Math.min(720, Math.max(0, int(b.min_lead_hours, cur.min_lead_hours))) : cur.min_lead_hours,
    online_payment: b.online_payment !== undefined ? bool(b.online_payment, cur.online_payment) : cur.online_payment,
    allow_card: b.allow_card !== undefined ? bool(b.allow_card, cur.allow_card) : cur.allow_card,
    allow_mobile_money: b.allow_mobile_money !== undefined ? bool(b.allow_mobile_money, cur.allow_mobile_money) : cur.allow_mobile_money,
    whatsapp: b.whatsapp !== undefined ? String(b.whatsapp).trim().slice(0, 30) : cur.whatsapp,
    opening_hours: b.opening_hours !== undefined ? String(b.opening_hours).trim().slice(0, 120) : cur.opening_hours,
    address: b.address !== undefined ? String(b.address).trim().slice(0, 200) : cur.address,
  };
  await q(
    `UPDATE shop_settings SET shop_name=$1, is_open=$2, delivery_fee=$3, min_lead_hours=$4, online_payment=$5, allow_card=$6, allow_mobile_money=$7, whatsapp=$8, opening_hours=$9, address=$10 WHERE id=1`,
    [next.shop_name, next.is_open, next.delivery_fee, next.min_lead_hours, next.online_payment, next.allow_card, next.allow_mobile_money, next.whatsapp, next.opening_hours, next.address],
  );
  res.json(next);
}));
app.use('/admin', admin);

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
  res.status(status).json({ error: status >= 500 && !err.status ? 'Erreur interne du serveur.' : err.message });
});

// ── Démarrage ────────────────────────────────────────────────────────────────
(async () => {
  try {
    await migrate();
    await ensureBucket();
    app.listen(PORT, '0.0.0.0', () => console.log(`✅ API pâtisserie démarrée sur le port ${PORT}`));
  } catch (e) {
    console.error('❌ Démarrage impossible :', e.message);
    process.exit(1);
  }
})();
