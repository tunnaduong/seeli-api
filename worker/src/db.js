import { bindings } from './config.js';

/** D1 helpers with the same shape as the old node:sqlite ones, but async. */
const stmt = (sql, p) => bindings.DB.prepare(sql).bind(...p.map((v) => (v === undefined ? null : v)));

export const one = (sql, ...p) => stmt(sql, p).first();
export const all = async (sql, ...p) => (await stmt(sql, p).all()).results;
export const run = async (sql, ...p) => {
  const r = await stmt(sql, p).run();
  return { changes: r.meta?.changes ?? 0 };
};

/** Several writes applied atomically (D1 has no interactive transactions). Each item: [sql, ...params]. */
export const batch = (items) => bindings.DB.batch(items.map(([sql, ...p]) => stmt(sql, p)));
