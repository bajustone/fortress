import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig } from '../config';
import type { StoredContinuation } from '../internal-adapter';
import type { FortressPlugin, PostAuthGateDecision } from '../plugin';
import type { AuthChallenge, FortressUser, PendingReason, RequestMeta } from '../types';
import { Errors } from '../errors';
import { generateRefreshToken, hashToken } from './refresh-token';

/** Default lifetime of a pending-auth continuation (five minutes). */
export const AUTH_CONTINUATION_TTL_SECONDS = 300;

export interface PostAuthGateHold {
  challenge: AuthChallenge;
  pluginData?: Record<string, unknown>;
}

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_COOLDOWN_SECONDS = 1;

/** Persist a short-lived, hashed continuation and return only its raw bearer token. */
export async function mintAuthContinuation(
  db: DatabaseAdapter,
  userId: string,
  reason: PendingReason,
  ttlSeconds: number = AUTH_CONTINUATION_TTL_SECONDS,
  policy: { maxAttempts?: number; cooldownSeconds?: number } = {},
): Promise<AuthChallenge> {
  const { raw, hash } = await generateRefreshToken();
  const now = new Date();
  await db.create({
    model: 'auth_continuation',
    data: {
      userId,
      tokenHash: hash,
      reason,
      expiresAt: new Date(now.getTime() + ttlSeconds * 1000),
      consumedAt: null,
      failedAttempts: 0,
      lastFailedAt: null,
      invalidatedAt: null,
      maxAttempts: Math.max(1, policy.maxAttempts ?? DEFAULT_MAX_ATTEMPTS),
      cooldownSeconds: Math.max(0, policy.cooldownSeconds ?? DEFAULT_COOLDOWN_SECONDS),
      createdAt: now,
    },
  });
  return { reason, continuationToken: raw };
}

function assertUsableContinuation(record: StoredContinuation | null): StoredContinuation {
  if (!record || record.consumedAt || record.invalidatedAt || record.expiresAt <= new Date())
    throw Errors.unauthorized('Invalid or expired auth continuation');
  return record;
}

/** Inspect a continuation without consuming it, for a factor plugin's credential check. */
export async function peekAuthContinuation(
  db: DatabaseAdapter,
  continuationToken: string,
): Promise<StoredContinuation> {
  const tokenHash = await hashToken(continuationToken);
  const record = await db.findOne<StoredContinuation>({
    model: 'auth_continuation',
    where: [{ field: 'tokenHash', operator: '=', value: tokenHash }],
  });
  return assertUsableContinuation(record);
}

/** Atomically claim a continuation exactly once. */
export async function consumeAuthContinuation(
  db: DatabaseAdapter,
  continuationToken: string,
  verify?: (tx: DatabaseAdapter, continuation: StoredContinuation) => Promise<void>,
): Promise<StoredContinuation> {
  const tokenHash = await hashToken(continuationToken);
  const consumedAt = new Date();

  const outcome = await db.transaction(async (tx): Promise<
    | { ok: true; continuation: StoredContinuation }
    | { ok: false; error: unknown }
  > => {
    const existing = await tx.findOne<StoredContinuation>({
      model: 'auth_continuation',
      where: [{ field: 'tokenHash', operator: '=', value: tokenHash }],
    });
    const usable = assertUsableContinuation(existing);
    const maxAttempts = usable.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    const failedAttempts = usable.failedAttempts ?? 0;
    if (failedAttempts >= maxAttempts)
      throw Errors.unauthorized('Invalid or expired auth continuation');

    const cooldownSeconds = usable.cooldownSeconds ?? DEFAULT_COOLDOWN_SECONDS;
    if (cooldownSeconds > 0) {
      const cutoff = new Date(consumedAt.getTime() - cooldownSeconds * 1000);
      const recent = await tx.findOne<StoredContinuation>({
        model: 'auth_continuation',
        where: [
          { field: 'userId', operator: '=', value: usable.userId },
          { field: 'reason', operator: '=', value: usable.reason },
          { field: 'lastFailedAt', operator: 'gt', value: cutoff },
        ],
      });
      if (recent)
        throw Errors.unauthorized('Too many authentication attempts; try again shortly');
    }

    const record = await tx.update<StoredContinuation>({
      model: 'auth_continuation',
      where: [
        { field: 'tokenHash', operator: '=', value: tokenHash },
        { field: 'consumedAt', operator: 'isNull', value: null },
        { field: 'invalidatedAt', operator: 'isNull', value: null },
        { field: 'expiresAt', operator: 'gt', value: consumedAt },
        { field: 'failedAttempts', operator: 'lt', value: maxAttempts },
      ],
      data: { consumedAt },
    });
    if (!record)
      throw Errors.unauthorized('Invalid or expired auth continuation');

    try {
      // The row claim serializes concurrent guesses. On rejection, convert the
      // error to data so the transaction can durably release the claim and
      // increment the counter before the original error is re-thrown outside.
      await verify?.(tx, record);
      return { ok: true, continuation: record };
    }
    catch (error) {
      const nextFailedAttempts = (record.failedAttempts ?? 0) + 1;
      const released = await tx.update<StoredContinuation>({
        model: 'auth_continuation',
        where: [
          { field: 'tokenHash', operator: '=', value: tokenHash },
          { field: 'consumedAt', operator: '=', value: consumedAt },
        ],
        data: {
          consumedAt: null,
          failedAttempts: nextFailedAttempts,
          lastFailedAt: consumedAt,
          ...(nextFailedAttempts >= maxAttempts ? { invalidatedAt: consumedAt } : {}),
        },
      });
      if (!released)
        throw Errors.unauthorized('Invalid or expired auth continuation');
      return { ok: false, error };
    }
  });

  if (!outcome.ok)
    throw outcome.error;
  return outcome.continuation;
}

/** Run post-credential gates in registration order and mint the first hold. */
export async function runPostAuthGates(
  plugins: readonly FortressPlugin[],
  db: DatabaseAdapter,
  config: FortressConfig,
  user: FortressUser,
  meta: RequestMeta | undefined,
  completedReasons: readonly PendingReason[] = [],
): Promise<PostAuthGateHold | null> {
  const providers = plugins.flatMap(plugin => plugin.hooks?.postAuthGate ? [plugin.hooks.postAuthGate] : []);
  const duplicateReason = providers.find((provider, index) =>
    providers.findIndex(candidate => candidate.reason === provider.reason) !== index,
  );
  if (duplicateReason)
    throw Errors.badRequest(`Duplicate post-auth gate reason: '${duplicateReason.reason}'`);

  const resumeReason = completedReasons.at(-1);
  const resumeIndex = resumeReason == null
    ? -1
    : providers.findIndex(provider => provider.reason === resumeReason);
  if (resumeReason != null && resumeIndex < 0)
    throw Errors.unauthorized('No auth gate can resume this continuation');

  const satisfiedReasons = providers.slice(0, resumeIndex + 1).map(provider => provider.reason);
  for (const provider of providers.slice(resumeIndex + 1)) {
    const decision: PostAuthGateDecision | void = await provider.evaluate({
      db,
      config,
      meta,
      user,
      completedReasons: satisfiedReasons,
    });
    if (!decision)
      continue;

    return {
      challenge: await mintAuthContinuation(db, user.id, provider.reason, AUTH_CONTINUATION_TTL_SECONDS, {
        maxAttempts: provider.maxAttempts,
        cooldownSeconds: provider.cooldownSeconds,
      }),
      pluginData: decision.pluginData,
    };
  }
  return null;
}

/** Dispatch completion proof to the provider that created this continuation. */
export async function verifyAuthContinuation(
  plugins: readonly FortressPlugin[],
  db: DatabaseAdapter,
  config: FortressConfig,
  user: FortressUser,
  continuation: StoredContinuation,
  completion: unknown,
  meta?: RequestMeta,
): Promise<Record<string, unknown> | void> {
  const providers = plugins.flatMap((plugin) => {
    const provider = plugin.hooks?.postAuthGate;
    return provider?.reason === continuation.reason ? [provider] : [];
  });
  if (providers.length !== 1)
    throw Errors.unauthorized('No unique auth gate can complete this continuation');
  const [provider] = providers;

  return provider.verify({
    db,
    config,
    meta,
    user,
    continuation: {
      id: continuation.id,
      reason: continuation.reason,
      expiresAt: continuation.expiresAt,
    },
  }, completion);
}
