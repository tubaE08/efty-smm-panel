import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { SmmApi } from '../lib/smmApi.js';

const SMM_API_KEY = process.env.SMM_API_KEY || '';
const SMM_API_URL = process.env.SMM_API_URL || 'https://minismm.com/api/v2';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'efty_admin_123';
const BKASH_NUMBER = process.env.BKASH_NUMBER || '01985060380';
const PRICE_MULTIPLIER = Number(process.env.PRICE_MULTIPLIER || '1');

const smm = new SmmApi(SMM_API_KEY, SMM_API_URL);

const DB_PATH = process.env.JSON_DB_PATH || path.join(process.cwd(), 'data', 'db.json');

function readDb() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
      const initial = { users: [], payments: [], orders: [] };
      fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), 'utf8');
      return initial;
    }
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      payments: Array.isArray(parsed.payments) ? parsed.payments : [],
      orders: Array.isArray(parsed.orders) ? parsed.orders : [],
    };
  } catch {
    return { users: [], payments: [], orders: [] };
  }
}

function writeDb(data) {
  try {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('JSON write error:', err.message);
  }
}

function generateAccessKey() {
  return 'EFTY-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

function calcCharge(serviceInfo, payload) {
  if (!serviceInfo || !serviceInfo.rate) return 0;
  const ratePer1000 = Number(serviceInfo.rate) * PRICE_MULTIPLIER;
  if (serviceInfo.type === 'Package' || !payload.quantity) {
    return Number(ratePer1000.toFixed(4));
  }
  const qty = Number(payload.quantity || 0);
  const runs = Number(payload.runs || 1);
  return Number(((ratePer1000 / 1000) * qty * runs).toFixed(4));
}

function isAdminAuthorized(req) {
  const token = String(req.headers['x-admin-secret'] || req.body?.adminSecret || req.query?.adminSecret || '');
  return token && token === ADMIN_SECRET;
}

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  const route = req.url.split('?')[0].replace(/^\/api/, '');

  try {
    // Public config & services
    if (req.method === 'GET' && route === '/config') {
      return res.status(200).json({
        ok: true,
        panelName: 'Efty Smm panel',
        bkashNumber: BKASH_NUMBER,
      });
    }

    if (req.method === 'GET' && route === '/services') {
      const list = await smm.services();
      if (!Array.isArray(list)) {
        return res.status(400).json({ ok: false, error: 'Failed to load services', raw: list });
      }
      const mapped = list.map((s) => ({
        ...s,
        user_rate: Number((Number(s.rate || 0) * PRICE_MULTIPLIER).toFixed(4)),
      }));
      return res.status(200).json({ ok: true, services: mapped });
    }

    // User Sign Up (awaits admin key generation & approval)
    if (req.method === 'POST' && route === '/signup') {
      const { name, emailOrPhone } = req.body || {};
      const cleanName = String(name || '').trim();
      const cleanContact = String(emailOrPhone || '').trim().toLowerCase();

      if (!cleanName || !cleanContact) {
        return res.status(400).json({ ok: false, error: 'Name and Email/Phone required' });
      }

      const db = readDb();
      const exists = db.users.find((u) => u.contact === cleanContact);
      if (exists) {
        return res.status(400).json({
          ok: false,
          error: exists.approved
            ? 'এই অ্যাকাউন্ট ইতিমধ্যে Approved আছে। দেওয়া Access Key দিয়ে Sign In করুন।'
            : 'এই অ্যাকাউন্টের রিকোয়েস্ট ইতিমধ্যে Pending আছে। অ্যাডমিন Key দিলে লগইন করতে পারবেন।',
        });
      }

      const newUser = {
        id: db.users.length ? Math.max(...db.users.map((u) => u.id)) + 1 : 1,
        name: cleanName,
        contact: cleanContact,
        accessKey: null,
        approved: false,
        balance: 0,
        createdAt: new Date().toISOString(),
      };

      db.users.push(newUser);
      writeDb(db);

      return res.status(200).json({
        ok: true,
        message: 'অ্যাকাউন্ট রিকোয়েস্ট জমা হয়েছে। অ্যাডমিন Access Key জেনারেট করে Approve করলে সেই Key দিয়ে Sign In করতে পারবেন।',
      });
    }

    // User Sign In (strictly requires approved Access Key)
    if (req.method === 'POST' && route === '/login') {
      const { accessKey } = req.body || {};
      const key = String(accessKey || '').trim().toUpperCase();
      if (!key) {
        return res.status(400).json({ ok: false, error: 'Access Key দিন' });
      }

      const db = readDb();
      const user = db.users.find((u) => u.accessKey === key);
      if (!user) {
        return res.status(401).json({ ok: false, error: 'ভুল Access Key! অ্যাডমিনের দেওয়া সঠিক Key দিন।' });
      }
      if (!user.approved) {
        return res.status(403).json({ ok: false, error: 'আপনার অ্যাকাউন্ট এখনো Approved হয়নি।' });
      }

      return res.status(200).json({
        ok: true,
        user: {
          id: user.id,
          name: user.name,
          contact: user.contact,
          balance: Number(user.balance || 0),
        },
      });
    }

    // Authenticated user dashboard data
    if (req.method === 'GET' && route === '/user/dashboard') {
      const key = String(req.query.accessKey || '').trim().toUpperCase();
      const db = readDb();
      const user = db.users.find((u) => u.accessKey === key && u.approved);
      if (!user) {
        return res.status(401).json({ ok: false, error: 'Unauthorized Access Key' });
      }

      const orders = db.orders.filter((o) => o.userId === user.id).slice().reverse();
      const payments = db.payments.filter((p) => p.userId === user.id).slice().reverse();

      return res.status(200).json({
        ok: true,
        bkashNumber: BKASH_NUMBER,
        user: {
          id: user.id,
          name: user.name,
          contact: user.contact,
          balance: Number(user.balance || 0),
        },
        orders,
        payments,
      });
    }

    // Submit bKash TrxID deposit
    if (req.method === 'POST' && route === '/user/deposit') {
      const { accessKey, amount, trxId } = req.body || {};
      const key = String(accessKey || '').trim().toUpperCase();
      const numAmt = Number(amount);
      const cleanTrx = String(trxId || '').trim().toUpperCase();

      const db = readDb();
      const user = db.users.find((u) => u.accessKey === key && u.approved);
      if (!user) return res.status(401).json({ ok: false, error: 'Unauthorized' });
      if (!numAmt || numAmt <= 0 || cleanTrx.length < 5) {
        return res.status(400).json({ ok: false, error: 'সঠিক Amount ও bKash TrxID দিন' });
      }
      if (db.payments.some((p) => p.trxId === cleanTrx)) {
        return res.status(400).json({ ok: false, error: 'এই TrxID ইতিমধ্যে ব্যবহার করা হয়েছে' });
      }

      const payment = {
        id: db.payments.length ? Math.max(...db.payments.map((p) => p.id)) + 1 : 1,
        userId: user.id,
        userName: user.name,
        trxId: cleanTrx,
        amount: numAmt,
        status: 'pending',
        createdAt: new Date().toISOString(),
      };

      db.payments.push(payment);
      writeDb(db);

      return res.status(200).json({ ok: true, payment });
    }

    // Place SMM Order (deducts user balance & calls MiniSMM API v2)
    if (req.method === 'POST' && route === '/user/order') {
      const { accessKey, orderPayload } = req.body || {};
      const key = String(accessKey || '').trim().toUpperCase();
      const db = readDb();
      const userIndex = db.users.findIndex((u) => u.accessKey === key && u.approved);
      if (userIndex === -1) return res.status(401).json({ ok: false, error: 'Unauthorized' });

      const user = db.users[userIndex];
      const payload = orderPayload || {};
      const serviceId = Number(payload.service);
      if (!serviceId) return res.status(400).json({ ok: false, error: 'Service ID প্রয়োজন' });

      const allServices = await smm.services();
      const serviceInfo = Array.isArray(allServices)
        ? allServices.find((s) => Number(s.service) === serviceId)
        : null;
      if (!serviceInfo) return res.status(404).json({ ok: false, error: 'Service পাওয়া যায়নি' });

      if (payload.quantity !== undefined && payload.quantity !== '') {
        const qty = Number(payload.quantity);
        if (qty < Number(serviceInfo.min) || qty > Number(serviceInfo.max)) {
          return res.status(400).json({
            ok: false,
            error: `Quantity ${serviceInfo.min} থেকে ${serviceInfo.max}-এর মধ্যে হতে হবে`,
          });
        }
      }

      const charge = calcCharge(serviceInfo, payload);
      if (Number(user.balance) < charge) {
        return res.status(400).json({
          ok: false,
          error: `অপর্যাপ্ত ব্যালেন্স! প্রয়োজন: ${charge}, আপনার ব্যালেন্স: ${Number(user.balance).toFixed(2)}`,
        });
      }

      const apiRes = await smm.order(payload);
      if (!apiRes || !apiRes.order) {
        return res.status(400).json({ ok: false, error: apiRes?.error || 'SMM Order ব্যর্থ হয়েছে', raw: apiRes });
      }

      user.balance = Number((Number(user.balance) - charge).toFixed(4));
      db.users[userIndex] = user;

      const orderRecord = {
        id: db.orders.length ? Math.max(...db.orders.map((o) => o.id)) + 1 : 1,
        userId: user.id,
        userName: user.name,
        smmOrderId: Number(apiRes.order),
        serviceId,
        serviceName: serviceInfo.name,
        link: payload.link || payload.username || '-',
        quantity: payload.quantity ? Number(payload.quantity) : null,
        charge,
        status: 'Submitted',
        createdAt: new Date().toISOString(),
      };

      db.orders.push(orderRecord);
      writeDb(db);

      return res.status(200).json({
        ok: true,
        order: orderRecord,
        apiResponse: apiRes,
        balance: user.balance,
      });
    }

    // User / Admin order tools (status, multiStatus, refill, multiRefill, refillStatus, multiRefillStatus, cancel)
    if (req.method === 'POST' && route === '/smm/action') {
      const { accessKey, adminSecret, smmAction, target } = req.body || {};
      const db = readDb();
      const validUser = db.users.some((u) => u.accessKey === String(accessKey || '').trim().toUpperCase() && u.approved);
      const validAdmin = String(adminSecret || '') === ADMIN_SECRET;

      if (!validUser && !validAdmin) {
        return res.status(401).json({ ok: false, error: 'Unauthorized' });
      }

      let data;
      const listTarget = String(target || '').split(',').map((s) => s.trim()).filter(Boolean);

      if (smmAction === 'status') data = await smm.status(Number(target));
      else if (smmAction === 'multiStatus') data = await smm.multiStatus(listTarget);
      else if (smmAction === 'refill') data = await smm.refill(Number(target));
      else if (smmAction === 'multiRefill') data = await smm.multiRefill(listTarget);
      else if (smmAction === 'refillStatus') data = await smm.refillStatus(Number(target));
      else if (smmAction === 'multiRefillStatus') data = await smm.multiRefillStatus(listTarget);
      else if (smmAction === 'cancel') data = await smm.cancel(listTarget);
      else return res.status(400).json({ ok: false, error: 'Invalid SMM action' });

      return res.status(200).json({ ok: true, data });
    }

    // Admin Routes
    if (route.startsWith('/admin')) {
      if (!isAdminAuthorized(req)) {
        return res.status(401).json({ ok: false, error: 'Invalid Admin Secret' });
      }

      const db = readDb();

      if (req.method === 'GET' && route === '/admin/dashboard') {
        const providerBalance = await smm.balance().catch(() => null);
        return res.status(200).json({
          ok: true,
          bkashNumber: BKASH_NUMBER,
          providerBalance,
          users: db.users.slice().reverse(),
          payments: db.payments.slice().reverse(),
          orders: db.orders.slice().reverse(),
        });
      }

      if (req.method === 'POST' && route === '/admin/approve-user') {
        const userId = Number(req.body?.userId);
        const idx = db.users.findIndex((u) => u.id === userId);
        if (idx === -1) return res.status(404).json({ ok: false, error: 'User not found' });

        if (!db.users[idx].accessKey) {
          db.users[idx].accessKey = generateAccessKey();
        }
        db.users[idx].approved = true;
        writeDb(db);

        return res.status(200).json({ ok: true, user: db.users[idx] });
      }

      if (req.method === 'POST' && route === '/admin/revoke-user') {
        const userId = Number(req.body?.userId);
        const idx = db.users.findIndex((u) => u.id === userId);
        if (idx === -1) return res.status(404).json({ ok: false, error: 'User not found' });

        db.users[idx].approved = false;
        writeDb(db);

        return res.status(200).json({ ok: true, user: db.users[idx] });
      }

      if (req.method === 'POST' && route === '/admin/add-balance') {
        const userId = Number(req.body?.userId);
        const amount = Number(req.body?.amount);
        const idx = db.users.findIndex((u) => u.id === userId);
        if (idx === -1) return res.status(404).json({ ok: false, error: 'User not found' });
        if (Number.isNaN(amount) || amount === 0) {
          return res.status(400).json({ ok: false, error: 'Valid amount required' });
        }

        const nextBal = Number((Number(db.users[idx].balance || 0) + amount).toFixed(4));
        if (nextBal < 0) return res.status(400).json({ ok: false, error: 'Balance cannot be negative' });

        db.users[idx].balance = nextBal;
        writeDb(db);

        return res.status(200).json({ ok: true, user: db.users[idx] });
      }

      if (req.method === 'POST' && route === '/admin/payment-decision') {
        const paymentId = Number(req.body?.paymentId);
        const decision = String(req.body?.decision || '');

        const pIdx = db.payments.findIndex((p) => p.id === paymentId);
        if (pIdx === -1) return res.status(404).json({ ok: false, error: 'Payment not found' });
        if (db.payments[pIdx].status !== 'pending') {
          return res.status(400).json({ ok: false, error: 'Already processed' });
        }

        if (decision === 'approve') {
          const uIdx = db.users.findIndex((u) => u.id === db.payments[pIdx].userId);
          if (uIdx === -1) return res.status(404).json({ ok: false, error: 'User not found' });

          db.payments[pIdx].status = 'approved';
          db.payments[pIdx].reviewedAt = new Date().toISOString();
          db.users[uIdx].balance = Number(
            (Number(db.users[uIdx].balance || 0) + Number(db.payments[pIdx].amount)).toFixed(4)
          );
          writeDb(db);

          return res.status(200).json({ ok: true, user: db.users[uIdx] });
        }

        if (decision === 'reject') {
          db.payments[pIdx].status = 'rejected';
          db.payments[pIdx].reviewedAt = new Date().toISOString();
          writeDb(db);
          return res.status(200).json({ ok: true });
        }

        return res.status(400).json({ ok: false, error: 'Invalid decision' });
      }
    }

    return res.status(404).json({ ok: false, error: 'Not found' });
  } catch (err) {
    console.error('API error:', err);
    return res.status(500).json({ ok: false, error: err.message });
  }
}
