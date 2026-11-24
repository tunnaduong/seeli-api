import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import { config } from './config.js';
import routes from './routes.js';
import adminRoutes from './admin.js';

export function buildApp(opts = {}) {
  const app = Fastify({
    logger: opts.logger ?? { level: process.env.LOG_LEVEL || 'info' },
    trustProxy: true, // behind aaPanel's nginx
    bodyLimit: 1024 * 1024,
  });
  app.register(multipart, { limits: { fileSize: config.maxPhotoBytes, files: 1, fields: 10 } });
  app.register(routes, { prefix: '/v1' });
  app.register(adminRoutes);
  app.setErrorHandler((err, req, reply) => {
    if (err.code === 'FST_REQ_FILE_TOO_LARGE') return reply.code(413).send({ error: 'photo_too_large' });
    if (err.statusCode && err.statusCode < 500) return reply.code(err.statusCode).send({ error: err.code || 'bad_request' });
    req.log.error(err);
    return reply.code(500).send({ error: 'server_error' });
  });
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = buildApp();
  app.listen({ port: config.port, host: config.host }).catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => app.close().then(() => process.exit(0)));
}
