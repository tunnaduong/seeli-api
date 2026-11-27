/**
 * Daily backup, run by the cron trigger at 02:00 Vietnam time (19:00 UTC).
 *  - D1: every table is written as JSON to  daily/<YYYY-MM-DD>/db/<table>.json  (kept 30 days).
 *  - R2: every photo is copied once to      photos/<userId>/<momentId>.jpg       (mirror, kept).
 * Deleting an account in the app does NOT delete its backup copies.
 */
const KEEP_DAYS = 30;

export async function runBackup(env) {
  const day = new Date().toISOString().slice(0, 10);
  const report = { day, tables: {}, photosCopied: 0, photosSkipped: 0, pruned: [] };

  // 1. Database snapshot.
  const tables = (await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'd1_%'",
  ).all()).results.map((r) => r.name);
  for (const t of tables) {
    const rows = (await env.DB.prepare(`SELECT * FROM "${t}"`).all()).results;
    await env.BACKUP.put(`daily/${day}/db/${t}.json`, JSON.stringify(rows), {
      httpMetadata: { contentType: 'application/json' },
    });
    report.tables[t] = rows.length;
  }
  await env.BACKUP.put(`daily/${day}/manifest.json`, JSON.stringify({ day, tables: report.tables, at: new Date().toISOString() }), {
    httpMetadata: { contentType: 'application/json' },
  });

  // 2. Photo mirror: copy only objects not yet backed up.
  let cursor;
  do {
    const page = await env.PHOTOS.list({ cursor });
    for (const o of page.objects) {
      const dest = `photos/${o.key}`;
      if (await env.BACKUP.head(dest)) { report.photosSkipped++; continue; }
      const obj = await env.PHOTOS.get(o.key);
      if (!obj) continue;
      await env.BACKUP.put(dest, obj.body, { httpMetadata: obj.httpMetadata });
      report.photosCopied++;
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);

  // 3. Drop database snapshots older than KEEP_DAYS.
  const cutoff = Date.now() - KEEP_DAYS * 86400000;
  const dirs = await env.BACKUP.list({ prefix: 'daily/', delimiter: '/' });
  for (const p of dirs.delimitedPrefixes) {
    const d = Date.parse(p.slice('daily/'.length, -1));
    if (!Number.isNaN(d) && d < cutoff) {
      let c;
      do {
        const page = await env.BACKUP.list({ prefix: p, cursor: c });
        if (page.objects.length) await env.BACKUP.delete(page.objects.map((o) => o.key));
        c = page.truncated ? page.cursor : undefined;
      } while (c);
      report.pruned.push(p);
    }
  }

  console.log('backup_done', JSON.stringify(report));
  return report;
}
