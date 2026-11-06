// Bolas payments — Firebase Cloud Functions (2nd gen). The Razorpay SECRET lives only here, as a Firebase secret — never in a web page.
const { onCall, onRequest, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const admin = require('firebase-admin');
const { verifySignature, verifyWebhook, extendUntil } = require('./lib/pay');

admin.initializeApp();
const db = admin.firestore(), FV = admin.firestore.FieldValue;
const REGION = 'asia-south1';
const KEY_ID = 'rzp_live_TvOpaVqyVuth9l';                       // the public Key ID (safe to show in the page)
const KEY_SECRET = defineSecret('RAZORPAY_KEY_SECRET');          // firebase functions:secrets:set RAZORPAY_KEY_SECRET
const WEBHOOK_SECRET = defineSecret('RAZORPAY_WEBHOOK_SECRET');  // firebase functions:secrets:set RAZORPAY_WEBHOOK_SECRET

// 1) The customer taps Pay → the price comes from the owner's setting in Firestore (the customer cannot change it) → a Razorpay order is created
exports.createOrder = onCall({ region: REGION, secrets: [KEY_SECRET] }, async req => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Please sign in first.');
  const uid = req.auth.uid, pr = await db.doc('pricing/' + uid).get();
  if (!pr.exists || pr.data().required !== true) throw new HttpsError('failed-precondition', 'No payment is needed on your account.');
  const p = pr.data(), paise = Math.round(Number(p.amount) * 100), days = Math.max(1, Math.round(Number(p.days) || 30));
  if (!(paise >= 100)) throw new HttpsError('failed-precondition', 'The owner has not set a valid price yet.');
  const res = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Basic ' + Buffer.from(KEY_ID + ':' + KEY_SECRET.value()).toString('base64') },
    body: JSON.stringify({ amount: paise, currency: 'INR', receipt: ('r_' + uid.slice(0, 12) + '_' + Date.now()).slice(0, 40), notes: { uid, days: String(days) } })
  });
  const o = await res.json();
  if (!res.ok) throw new HttpsError('internal', (o.error && o.error.description) || 'Razorpay could not create the order.');
  await db.doc('payments/' + o.id).set({ uid, email: req.auth.token.email || '', name: req.auth.token.name || '', amount: paise / 100, days, status: 'created', orderId: o.id, createdAt: FV.serverTimestamp() });
  return { orderId: o.id, amount: o.amount, currency: o.currency, keyId: KEY_ID, days };
});

// Marks an order paid and extends the customer's access — only once, even if both the page and the webhook report it
async function applyPayment(orderId, paymentId, source) {
  const pref = db.doc('payments/' + orderId);
  return db.runTransaction(async tx => {
    const pay = await tx.get(pref); if (!pay.exists) return null;
    const d = pay.data(); if (d.status === 'paid') return d;
    const sref = db.doc('subscriptions/' + d.uid), sub = await tx.get(sref);
    const until = extendUntil(sub.exists ? sub.data().paidUntil : 0, Date.now(), d.days);
    tx.set(sref, { paidUntil: until, lastPaymentId: paymentId, lastPaidAt: FV.serverTimestamp(), lastAmount: d.amount, days: d.days }, { merge: true });
    tx.update(pref, { status: 'paid', paymentId, paidAt: FV.serverTimestamp(), source });
    return { ...d, paidUntil: until };
  });
}

// 2) Razorpay Checkout returns → the signature is checked here, with the secret, before access is given
exports.verifyPayment = onCall({ region: REGION, secrets: [KEY_SECRET] }, async req => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Please sign in first.');
  const { razorpay_order_id: oid, razorpay_payment_id: pid, razorpay_signature: sig } = req.data || {};
  if (!verifySignature(oid, pid, sig, KEY_SECRET.value())) throw new HttpsError('permission-denied', 'The payment could not be verified.');
  const pay = await db.doc('payments/' + oid).get();
  if (!pay.exists || pay.data().uid !== req.auth.uid) throw new HttpsError('permission-denied', 'This payment does not belong to your account.');
  const r = await applyPayment(oid, pid, 'checkout');
  return { paidUntil: r && r.paidUntil };
});

// 3) Safety net: Razorpay tells us by itself, so access still turns on if the customer closed the page right after paying
exports.razorpayWebhook = onRequest({ region: REGION, secrets: [WEBHOOK_SECRET] }, async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();
  if (!verifyWebhook(req.rawBody, req.get('x-razorpay-signature'), WEBHOOK_SECRET.value())) return res.status(400).send('bad signature');
  const ev = req.body || {}, pe = ev.payload && ev.payload.payment && ev.payload.payment.entity;
  if ((ev.event === 'payment.captured' || ev.event === 'order.paid') && pe && pe.order_id) await applyPayment(pe.order_id, pe.id, 'webhook');
  res.json({ ok: true });
});
