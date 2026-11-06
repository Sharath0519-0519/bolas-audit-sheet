// Pure helpers (no Firebase needed) so they can be tested on their own.
const crypto = require('crypto');
const hmac = (secret, data) => crypto.createHmac('sha256', secret).update(data).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || '')); return x.length === y.length && crypto.timingSafeEqual(x, y); };

// Razorpay Checkout result: signature = HMAC_SHA256(order_id + "|" + payment_id, key_secret)
exports.verifySignature = (orderId, paymentId, signature, secret) =>
  !!(orderId && paymentId && signature && secret) && safeEq(hmac(secret, orderId + '|' + paymentId), signature);

// Razorpay webhook: signature = HMAC_SHA256(raw request body, webhook_secret)
exports.verifyWebhook = (rawBody, signature, secret) =>
  !!(rawBody && signature && secret) && safeEq(hmac(secret, rawBody), signature);

// New expiry (milliseconds): paying early adds to the time that is left, paying late starts from today
exports.extendUntil = (currentUntilMs, nowMs, days) => Math.max(Number(currentUntilMs) || 0, nowMs) + Math.round(days) * 86400000;
