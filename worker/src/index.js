import { Hono } from 'hono';
import { loadEnv } from './config.js';
import { api } from './routes.js';
import { admin } from './admin.js';
import { runBackup } from './backup.js';

const app = new Hono();
app.route('/', admin);
app.route('/v1', api);
app.notFound((c) => c.json({ error: 'not_found' }, 404));
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: 'server_error' }, 500);
});

export default {
  fetch(request, env, ctx) {
    loadEnv(env, ctx);
    return app.fetch(request, env, ctx);
  },
  // Cron trigger (wrangler.jsonc): 02:00 Vietnam time every day.
  async scheduled(event, env, ctx) {
    loadEnv(env, ctx);
    await runBackup(env);
  },
};
