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

/** Persist a short-lived, hashed continuation and return only its raw bearer token. */
export async function mintAuthContinuation(
  db: DatabaseAdapter,
  userId: string,
  reason: PendingReason,
  ttlSeconds: number = AUTH_CONTINUATION_TTL_SECONDS,
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
      createdAt: now,
    },
  });
  return { reason, continuationToken: raw };
}

function assertUsableContinuation(record: StoredContinuation | null): StoredContinuation {
  if (!record || record.consumedAt || record.expiresAt <= new Date())
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

  return db.transaction(async (tx) => {
    const record = await tx.update<StoredContinuation>({
      model: 'auth_continuation',
      where: [
        { field: 'tokenHash', operator: '=', value: tokenHash },
        { field: 'consumedAt', operator: 'isNull', value: null },
        { field: 'expiresAt', operator: 'gt', value: consumedAt },
      ],
      data: { consumedAt },
    });
    if (!record)
      throw Errors.unauthorized('Invalid or expired auth continuation');

    // Verification runs while the claim is held. A rejected proof rolls back
    // both the claim and provider-side database mutations, allowing retry.
    await verify?.(tx, record);
    return record;
  });
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
      challenge: await mintAuthContinuation(db, user.id, provider.reason),
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
): Promise<void> {
  const providers = plugins.flatMap((plugin) => {
    const provider = plugin.hooks?.postAuthGate;
    return provider?.reason === continuation.reason ? [provider] : [];
  });
  if (providers.length !== 1)
    throw Errors.unauthorized('No unique auth gate can complete this continuation');
  const [provider] = providers;

  await provider.verify({
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
