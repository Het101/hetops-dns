# Backups and restore

The app backs up its SQLite database itself (`backup.js`):

- **When:** 10 minutes after start, then every 24 hours.
- **What:** an online snapshot (`db.backup`) into `BACKUP_DIR` (default `/app/data/backups`, on the data volume), named `hetops-YYYYMMDD-HHMMSS.db`. The newest `BACKUP_KEEP` (default 14) are kept.
- **Restore drill on every snapshot:** the snapshot is opened read-only, `PRAGMA integrity_check` must return `ok`, and its row counts are compared with the live database. A snapshot that fails is reported as a failed backup.
- **Offsite:** when all four of `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` are set (and optionally `S3_REGION`, default `auto`; `S3_PREFIX`, default `hetops-dns/`), each snapshot is also uploaded to that S3-compatible bucket (Cloudflare R2, Oracle Object Storage, AWS S3). Local snapshots live on the same disk as the database, so without offsite they protect against bad migrations and mistakes, not against losing the machine.
- **Status:** `GET /api/health` includes `backup: { at, ok, bytes, offsite, error }`.

## Restoring

1. Pick a snapshot: newest in `/app/data/backups`, or download one from the bucket.
2. Stop the app in Coolify (so nothing writes while you swap the file).
3. In the data volume, move `hetops.db`, `hetops.db-wal` and `hetops.db-shm` aside, and copy the snapshot to `hetops.db`.
4. Start the app and check `GET /api/health` and a sign-in.

A snapshot is a complete database on its own (no WAL needed), so step 3 is a single file copy.
