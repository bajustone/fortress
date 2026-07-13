/**
 * CI-ready check utilities for Fortress projects (P1-10).
 *
 * Wraps the drift detectors and manifests Fortress already builds for
 * itself so consumer apps can wire them into their own CI pipeline. The
 * functions are framework-agnostic — they consume a `Fortress` instance
 * and / or a `DatabaseAdapter` and return structured results suitable
 * for `expect(...)`-style assertions or printing alongside a non-zero
 * exit code.
 *
 * Re-exported from `@bajustone/fortress/testing` alongside the existing
 * `createTestAdapter` helper.
 *
 * @module
 */

import type { DatabaseAdapter } from '../adapters/database';
import type { Fortress } from '../core/fortress';
import type { RouteManifestDrift } from '../core/manifest/drift';
import type { RouteClassification, RouteManifestEntry } from '../core/manifest/route-manifest';
import type { MigrationDrift } from '../core/migrations/engine';
import type { MigrationDialect } from '../core/migrations/migrations';
import { detectRouteManifestDrift, hasRouteManifestDrift } from '../core/manifest/drift';
import { buildRouteManifest } from '../core/manifest/route-manifest';
import { detectMigrationDrift, hasMigrationDrift } from '../core/migrations/engine';

/**
 * Combined result returned by every `check*` helper.
 *
 * `ok: true` ⇒ the check passed cleanly; `messages` is informational
 * only. `ok: false` ⇒ at least one finding requires attention; the
 * messages describe what.
 */
export interface CheckResult {
  ok: boolean;
  messages: string[];
}

// ── Route manifest drift ────────────────────────────────────────────

/**
 * Run the route-manifest drift detector and return a {@link CheckResult}.
 * Suitable for CI: a non-empty {@link RouteManifestDrift} flips
 * `ok: false` and emits one message per drift category.
 */
export function checkRouteManifestDrift(
  fortress: Fortress,
): CheckResult & { drift: RouteManifestDrift } {
  const drift = detectRouteManifestDrift(fortress);
  const messages: string[] = [];
  if (drift.mountedMissingFromManifest.length > 0)
    messages.push(`Mounted routes missing from manifest: ${drift.mountedMissingFromManifest.join(', ')}`);
  if (drift.manifestMissingFromMounted.length > 0)
    messages.push(`Manifest routes missing from mounted set: ${drift.manifestMissingFromMounted.join(', ')}`);
  if (drift.rbacPermissionMismatches.length > 0) {
    messages.push(
      `RBAC permission mismatches:\n  ${drift.rbacPermissionMismatches
        .map(m => `${m.route}: expected=${m.expected ?? '(none)'} actual=${m.actual ?? '(none)'}`)
        .join('\n  ')}`,
    );
  }
  if (drift.openapiMissingFromManifest.length > 0)
    messages.push(`Routes in OpenAPI but missing from manifest: ${drift.openapiMissingFromManifest.join(', ')}`);
  if (drift.manifestMissingFromOpenapi.length > 0)
    messages.push(`Routes in manifest but missing from OpenAPI: ${drift.manifestMissingFromOpenapi.join(', ')}`);
  return { ok: !hasRouteManifestDrift(drift), drift, messages };
}

// ── Public-route allow-list ─────────────────────────────────────────

/**
 * Options for {@link checkPublicRoutes}.
 */
export interface PublicRouteCheckOptions {
  /**
   * Explicit allow-list of `'<METHOD> <path>'` entries that are *allowed*
   * to be `public` or `oauth-protocol`. Anything classified as `public`
   * but **not** on this list is reported as a finding so a stray
   * `.security('none')` on a sensitive route fails the build.
   *
   * Defaults to Fortress's own intentional public surface (auth open
   * routes + OAuth protocol endpoints) so consumers only need to add
   * their own public routes.
   */
  allow?: string[];
  /**
   * Additional classifications considered "public-equivalent" for the
   * purposes of the allow-list. Defaults to `['public', 'oauth-protocol']`
   * because OAuth protocol endpoints are reachable without a Fortress
   * session by design (the handler self-authenticates).
   */
  classifications?: RouteClassification[];
}

const DEFAULT_PUBLIC_ALLOW: readonly string[] = [
  'POST /auth/login',
  'POST /auth/register',
  'POST /auth/refresh',
  'POST /auth/logout',
  'GET /oauth/authorize',
  'POST /oauth/token',
  'POST /oauth/introspect',
  'POST /oauth/revoke',
  'GET /oauth/userinfo',
  'GET /oauth/.well-known/openid-configuration',
  'GET /oauth/.well-known/jwks.json',
];

/**
 * Assert that no Fortress-managed route is unintentionally public.
 *
 * Walks the route manifest, collects every entry classified as `public`
 * or `oauth-protocol` (configurable), and reports any entry not present
 * in the allow-list. Defaults cover Fortress's own intentional public
 * surface so consumers only need to add their own.
 */
export function checkPublicRoutes(
  fortress: Fortress,
  options: PublicRouteCheckOptions = {},
): CheckResult & { unexpected: RouteManifestEntry[] } {
  const allow = new Set([...(options.allow ?? []), ...DEFAULT_PUBLIC_ALLOW]);
  const classifications = new Set<RouteClassification>(
    options.classifications ?? ['public', 'oauth-protocol'],
  );

  const manifest = buildRouteManifest(fortress);
  const unexpected = manifest.filter(
    entry => classifications.has(entry.classification)
      && !allow.has(`${entry.method} ${entry.path}`),
  );

  const messages = unexpected.map(
    entry => `Unexpected ${entry.classification} route: ${entry.method} ${entry.path} (plugin=${entry.plugin ?? 'core'})`,
  );

  return { ok: unexpected.length === 0, unexpected, messages };
}

// ── Migration drift ─────────────────────────────────────────────────

/**
 * Run the migration drift detector and return a {@link CheckResult}.
 * Reports missing version table, pending migrations, an unknown
 * future version (DB ahead of the bundled catalog), missing
 * Fortress-owned tables, and present-but-stale tables missing columns.
 */
export async function checkMigrationDrift(
  db: DatabaseAdapter,
  dialect?: MigrationDialect,
): Promise<CheckResult & { drift: MigrationDrift }> {
  const drift = await detectMigrationDrift(db, dialect);
  const messages: string[] = [];
  if (drift.missingVersionTable)
    messages.push('Schema version table is missing — run fortress.migrateUp()');
  if (drift.pendingVersions.length > 0)
    messages.push(`Pending migrations: ${drift.pendingVersions.join(', ')}`);
  if (drift.unknownFutureVersion)
    messages.push(`Database is at version ${drift.currentVersion} but bundled catalog stops at ${drift.latestVersion}`);
  if (drift.missingTables.length > 0)
    messages.push(`Missing Fortress tables: ${drift.missingTables.join(', ')}`);
  if (drift.missingColumns.length > 0) {
    messages.push(
      `Stale Fortress tables missing columns: ${drift.missingColumns
        .map(entry => `${entry.table} (${entry.columns.join(', ')})`)
        .join('; ')}`,
    );
  }
  return { ok: !hasMigrationDrift(drift), drift, messages };
}

// ── Auth smoke-test helper ──────────────────────────────────────────

/**
 * Inputs to {@link smokeTestAuth}.
 */
export interface AuthSmokeTestOptions {
  /** Email used for the register/login round-trip. */
  email?: string;
  /** Password to register the smoke-test user with. */
  password?: string;
  /** Optional display name. */
  name?: string;
}

/**
 * End-to-end auth smoke test: register → login → me → refresh → logout.
 * Designed to run against a fortress instance backed by
 * {@link createTestAdapter} or any disposable DB. Returns a
 * {@link CheckResult} so it composes with the other checks for a single
 * CI gate.
 *
 * Calls the in-process `fortress.call.*` proxy so the full request
 * pipeline (validation, plugin middleware, RBAC, cookies) runs without
 * a network roundtrip.
 */
export async function smokeTestAuth(
  fortress: Fortress,
  options: AuthSmokeTestOptions = {},
): Promise<CheckResult> {
  const email = options.email ?? `smoke+${Date.now()}@fortress.test`;
  const password = options.password ?? 'smoke-test-password-1234564!';
  const name = options.name ?? 'Smoke Test';
  const messages: string[] = [];
  try {
    await fortress.auth.createUser({ email, password, name });
    const login = await fortress.auth.login(email, password);
    if (login.status !== 'success' || !login.accessToken)
      throw new Error(`login returned status=${login.status}`);
    const claims = await fortress.auth.verifyToken(login.accessToken);
    if (claims.sub !== login.user.id)
      throw new Error(`token sub mismatch: ${claims.sub} vs user.id ${login.user.id}`);
    if (!login.refreshToken)
      throw new Error('login did not return a refresh token');
    const refreshed = await fortress.auth.refresh(login.refreshToken);
    if (!refreshed.accessToken)
      throw new Error('refresh did not return a new access token');
    await fortress.auth.logout(refreshed.refreshToken);
    return { ok: true, messages };
  }
  catch (err) {
    messages.push(`Auth smoke test failed: ${err instanceof Error ? err.message : String(err)}`);
    return { ok: false, messages };
  }
}

// ── Convenience aggregator ──────────────────────────────────────────

/**
 * Inputs to {@link runFortressChecks}.
 */
export interface RunFortressChecksOptions {
  fortress: Fortress;
  /** Optional DB adapter for the migration check. Defaults to `fortress.config.database`. */
  db?: DatabaseAdapter;
  /** Skip the migration drift check (e.g. if you bring your own migration tool). */
  skipMigrations?: boolean;
  /** Skip the auth smoke test (e.g. in environments without a writable DB). */
  skipAuthSmokeTest?: boolean;
  /** Public-route allow-list overrides. */
  publicRoutes?: PublicRouteCheckOptions;
  /** Smoke-test overrides. */
  smokeTest?: AuthSmokeTestOptions;
}

/**
 * Aggregate result returned by {@link runFortressChecks}.
 */
export interface FortressChecksResult {
  ok: boolean;
  manifest: ReturnType<typeof checkRouteManifestDrift>;
  publicRoutes: ReturnType<typeof checkPublicRoutes>;
  migrations?: Awaited<ReturnType<typeof checkMigrationDrift>>;
  authSmokeTest?: Awaited<ReturnType<typeof smokeTestAuth>>;
  /** All non-ok messages flattened in run order. */
  messages: string[];
}

/**
 * Run every CI check Fortress ships in one shot. Suitable for a single
 * `fortress check` step in CI:
 *
 * ```ts
 * import { runFortressChecks } from '@bajustone/fortress/testing';
 *
 * const result = await runFortressChecks({ fortress });
 * if (!result.ok) {
 *   console.error(result.messages.join('\\n'));
 *   process.exit(1);
 * }
 * ```
 */
export async function runFortressChecks(
  options: RunFortressChecksOptions,
): Promise<FortressChecksResult> {
  const manifest = checkRouteManifestDrift(options.fortress);
  const publicRoutes = checkPublicRoutes(options.fortress, options.publicRoutes);
  const migrations = options.skipMigrations
    ? undefined
    : await checkMigrationDrift(options.db ?? options.fortress.config.database);
  const authSmokeTest = options.skipAuthSmokeTest
    ? undefined
    : await smokeTestAuth(options.fortress, options.smokeTest);

  const messages: string[] = [];
  if (!manifest.ok)
    messages.push(...manifest.messages.map(m => `[manifest] ${m}`));
  if (!publicRoutes.ok)
    messages.push(...publicRoutes.messages.map(m => `[public-routes] ${m}`));
  if (migrations && !migrations.ok)
    messages.push(...migrations.messages.map(m => `[migrations] ${m}`));
  if (authSmokeTest && !authSmokeTest.ok)
    messages.push(...authSmokeTest.messages.map(m => `[auth-smoke] ${m}`));

  return {
    ok: manifest.ok && publicRoutes.ok && (migrations?.ok ?? true) && (authSmokeTest?.ok ?? true),
    manifest,
    publicRoutes,
    ...(migrations ? { migrations } : {}),
    ...(authSmokeTest ? { authSmokeTest } : {}),
    messages,
  };
}
