import { mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const dataDir = resolve(process.env.DATA_DIR || './data');
mkdirSync(join(dataDir, 'photos'), { recursive: true });

if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET must be set in production');
}

export const config = {
  port: Number(process.env.PORT || 8790),
  host: process.env.HOST || '0.0.0.0',
  dataDir,
  dbPath: process.env.DB_PATH || join(dataDir, 'seeli.db'),
  photoDir: join(dataDir, 'photos'),
  secret: process.env.JWT_SECRET || 'dev-only-secret-change-me',
  // "About 30 days": random between these bounds so the reunion feels unexpected.
  revealMinDays: Number(process.env.REVEAL_MIN_DAYS || 27),
  revealMaxDays: Number(process.env.REVEAL_MAX_DAYS || 37),
  // Lets the app's demo mode bring photos back after ~1 minute. Set false at launch.
  allowDemo: (process.env.ALLOW_DEMO ?? 'true') === 'true',
  maxPhotoBytes: Number(process.env.MAX_PHOTO_MB || 8) * 1024 * 1024,
  photoUrlTtlSec: 60 * 60,
  // Sign in with Apple: accepted "aud" values (the iOS bundle ID).
  appleAudiences: (process.env.APPLE_AUDIENCES || 'com.tunnaduong.seeli').split(',').map((s) => s.trim()).filter(Boolean),
  // Sign in with Apple key (.p8) for token exchange + revocation on account deletion.
  appleTeamId: process.env.APPLE_TEAM_ID || '',
  appleKeyId: process.env.APPLE_KEY_ID || '',
  appleKeyPath: process.env.APPLE_KEY_PATH || '',
  // Push notifications (APNs). A .p8 key with "Apple Push Notifications service" enabled.
  // Empty key ID = pushes are skipped. Team ID falls back to APPLE_TEAM_ID.
  apnsKeyId: process.env.APNS_KEY_ID || '',
  apnsKeyPath: process.env.APNS_KEY_PATH || '',
  apnsTopic: process.env.APNS_TOPIC || 'com.tunnaduong.seeli',
  // Firebase service-account JSON for Android push (FCM HTTP v1).
  fcmServiceAccountPath: process.env.FCM_SERVICE_ACCOUNT_PATH || '',
  // Google Sign-In: OAuth client IDs (iOS client) whose ID tokens we accept. Empty = Google login disabled.
  googleClientIds: (process.env.GOOGLE_CLIENT_IDS || '').split(',').map((s) => s.trim()).filter(Boolean),
  // Auth attempts per IP per minute.
  authRateLimit: Number(process.env.AUTH_RATE_LIMIT || 10),
  // Admin page password (/admin). Empty = admin page disabled.
  adminPassword: process.env.ADMIN_PASSWORD || '',
  adminSessionHours: 12,
  // Public base URL used in photo links (e.g. https://seeli-api.example.com).
  publicUrl: (process.env.PUBLIC_URL || '').replace(/\/$/, ''),
};
