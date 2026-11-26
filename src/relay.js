import { createHmac, timingSafeEqual } from 'node:crypto';
import { config } from './config.js';
import { apnsConfigured, sendApns } from './apns.js';

/**
 * APNs relay for the Cloudflare Worker, which cannot open HTTP/2 connections.
 * POST /apns { env, token, payload } with header x-relay-secret → { status, body } from Apple.
 */
const same = (a, b) => {
  const h = (s) => createHmac('sha256', 'seeli-relay').update(String(s)).digest();
  return timingSafeEqual(h(a), h(b));
};

export default async function relayRoutes(app) {
  app.get('/v1/health', async () => ({ ok: true, relay: true, apns: apnsConfigured() }));

  app.post('/apns', async (req, reply) => {
    if (!config.pushRelaySecret || !same(req.headers['x-relay-secret'] || '', config.pushRelaySecret)) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    if (!apnsConfigured()) return reply.code(503).send({ error: 'apns_not_configured' });
    const { env, token, payload } = req.body || {};
    if (!/^[0-9a-f]{64,200}$/.test(String(token)) || typeof payload !== 'object' || !payload) {
      return reply.code(400).send({ error: 'bad_request' });
    }
    const res = await sendApns(env === 'sandbox' ? 'sandbox' : 'production', token, payload);
    return { status: res.status, body: res.body || '' };
  });
}
