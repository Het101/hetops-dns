// Backups for the SQLite database: a nightly online snapshot, a restore drill on every
// snapshot (open it, integrity_check, compare row counts with the live database), rotation,
// and an optional offsite copy to any S3-compatible bucket. A snapshot that fails the drill
// is reported as a failed backup, never trusted.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const TABLES = ['users', 'alerts', 'history']; // alerts holds the Domain Watch watches

function stamp(d = new Date()) { return d.toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '-'); }

async function snapshot(db, dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `hetops-${stamp()}.db`);
  await db.backup(file); // consistent copy while the app keeps writing
  return file;
}

// The restore drill: is this file a database we could actually restore from?
function verify(file, liveDb, tables = TABLES) {
  const snap = new Database(file, { readonly: true, fileMustExist: true });
  try {
    const integrity = snap.pragma('integrity_check', { simple: true });
    const counts = {};
    let match = true;
    for (const t of tables) {
      const has = snap.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(t);
      if (!has) continue;
      const n = snap.prepare(`SELECT COUNT(*) AS n FROM "${t}"`).get().n;
      counts[t] = n;
      // Rows written between the snapshot and this check are fine; fewer rows in the live
      // database than in the snapshot would mean the snapshot is not of this database.
      if (liveDb && liveDb.prepare(`SELECT COUNT(*) AS n FROM "${t}"`).get().n < n) match = false;
    }
    return { ok: integrity === 'ok' && match, integrity, counts };
  } finally { snap.close(); }
}

function rotate(dir, keep) {
  const files = fs.readdirSync(dir).filter((f) => /^hetops-\d{8}-\d{6}\.db$/.test(f)).sort();
  const gone = files.slice(0, Math.max(0, files.length - keep));
  for (const f of gone) fs.unlinkSync(path.join(dir, f));
  return gone;
}

// ── Minimal AWS Signature V4, enough for one S3 PUT ─────────────
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
function signV4({ method, url, headers, payloadHash, accessKeyId, secretAccessKey, region, service, amzDate }) {
  const u = new URL(url);
  const date = amzDate.slice(0, 8);
  const h = Object.fromEntries(Object.entries({ ...headers, host: u.host, 'x-amz-date': amzDate }).map(([k, v]) => [k.toLowerCase(), String(v).trim()]));
  const names = Object.keys(h).sort();
  const canonicalHeaders = names.map((k) => `${k}:${h[k]}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalPath = u.pathname.split('/').map((s) => encodeURIComponent(decodeURIComponent(s))).join('/');
  const canonicalRequest = [method, canonicalPath, u.searchParams.toString(), canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonicalRequest)].join('\n');
  const kSigning = hmac(hmac(hmac(hmac(`AWS4${secretAccessKey}`, date), region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(toSign).digest('hex');
  return { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`, signature };
}

async function uploadS3(file, env, fetchImpl = fetch) {
  const body = fs.readFileSync(file);
  const key = `${(env.S3_PREFIX || 'hetops-dns/').replace(/^\/+/, '')}${path.basename(file)}`;
  const url = `${env.S3_ENDPOINT.replace(/\/+$/, '')}/${env.S3_BUCKET}/${key}`;
  const payloadHash = sha256(body);
  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
  const { signature, host, ...headers } = signV4({
    method: 'PUT', url, headers: { 'x-amz-content-sha256': payloadHash, 'content-type': 'application/vnd.sqlite3' },
    payloadHash, accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY,
    region: env.S3_REGION || 'auto', service: 's3', amzDate,
  });
  const res = await fetchImpl(url, { method: 'PUT', headers, body });
  if (!res.ok) throw new Error(`offsite upload failed: HTTP ${res.status}`);
  return key;
}

function createBackups({ db, dbPath, env = process.env, log = console, fetchImpl = fetch }) {
  const dir = env.BACKUP_DIR || path.join(path.dirname(dbPath), 'backups');
  const keep = Number(env.BACKUP_KEEP) || 14;
  const offsite = !!(env.S3_ENDPOINT && env.S3_BUCKET && env.S3_ACCESS_KEY_ID && env.S3_SECRET_ACCESS_KEY);
  // The last result is kept next to the snapshots, so a restart doesn't report "no backup" for the
  // ten minutes before the first run (which uptime monitors read as a failed backup).
  const stateFile = path.join(dir, 'last-backup.json');
  let last = null;
  try { last = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { /* no backup yet */ }
  const remember = () => { try { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(stateFile, JSON.stringify(last)); } catch (e) { log.error(`[backup] could not save status: ${e.message}`); } };

  async function run() {
    const started = Date.now();
    try {
      const file = await snapshot(db, dir);
      const drill = verify(file, db);
      if (!drill.ok) throw new Error(`restore drill failed: integrity ${drill.integrity}`);
      let remote = null;
      if (offsite) remote = await uploadS3(file, env, fetchImpl);
      rotate(dir, keep);
      last = { at: new Date().toISOString(), ok: true, file: path.basename(file), bytes: fs.statSync(file).size, counts: drill.counts, offsite: remote ? 'uploaded' : 'not configured', ms: Date.now() - started };
      log.info(`[backup] ${last.file} ${last.bytes} bytes, drill ok, offsite ${last.offsite}`);
    } catch (err) {
      last = { at: new Date().toISOString(), ok: false, error: err.message, offsite: offsite ? 'failed' : 'not configured' };
      log.error(`[backup] failed: ${err.message}`);
    }
    remember();
    return last;
  }
  return { run, status: () => last, dir, offsite };
}

module.exports = { createBackups, snapshot, verify, rotate, signV4, uploadS3 };
