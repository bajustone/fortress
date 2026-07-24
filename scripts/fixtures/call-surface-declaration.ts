import type { CallOptions, DatabaseAdapter, FortressPlugin } from '@bajustone/fortress';
import { createFortress, endpoint, obj, str } from '@bajustone/fortress';

type ExpectedLiteralEcho = (
  input: { message: string },
  options?: CallOptions,
) => Promise<{ echoed: string }>;

/** Compiled against package self-reference after `tsup` emits declarations. */
export function acceptsPreciseBuiltCallSurface(database: DatabaseAdapter): void {
  const literalRoutePlugin = {
    name: 'declaration-literal-route',
    routes: {
      declarationLiteralEcho: endpoint('POST', '/declaration/literal-echo')
        .security('none')
        .body(obj({ message: str() }, 'message'))
        .response(200, 'Echo response', obj({ echoed: str() }, 'echoed'))
        .handler('declarationLiteralEcho')
        .build(),
    },
  } as const satisfies FortressPlugin;
  const noRoutePlugin = { name: 'declaration-no-route' } as const satisfies FortressPlugin;
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [literalRoutePlugin, noRoutePlugin] as const,
  });

  const loginResult: Promise<{
    status: 'success';
    user: {
      id: string;
      email: string;
      name: string;
      isActive: boolean;
      emailVerified?: boolean;
      createdAt: string;
      updatedAt: string;
    };
    method: 'password' | 'refresh' | 'two-factor' | 'webauthn' | 'magic-link' | 'impersonation';
    accessToken: string;
    refreshToken: string;
    pluginData?: Record<string, unknown>;
  } | {
    status: 'pending';
    user: {
      id: string;
      email: string;
      name: string;
      isActive: boolean;
      emailVerified?: boolean;
      createdAt: string;
      updatedAt: string;
    };
    pending: {
      reason: 'two-factor' | 'webauthn' | 'email-verification' | 'magic-link';
      continuationToken: string;
    };
    pluginData?: Record<string, unknown>;
  } | {
    status: 'impersonation';
    user: {
      id: string;
      email: string;
      name: string;
      isActive: boolean;
      emailVerified?: boolean;
      createdAt: string;
      updatedAt: string;
    };
    accessToken: string;
    refreshToken: null;
    pluginData?: Record<string, unknown>;
  }> = fortress.call.login({ identifier: 'user@example.com', password: 'secret' });
  const iamResult: Promise<{
    id: string;
    name: string;
    description?: string | null;
    isSystem?: boolean;
  }> = fortress.call.createRole({
    name: 'reader',
    permissions: [{ resource: 'articles', action: 'read' }],
  });
  const paramsResult: Promise<{ ok: boolean }> = fortress.call.revokeSession({ id: 'session-id' });
  const literalEcho: ExpectedLiteralEcho = fortress.call.declarationLiteralEcho;
  const literalResult: Promise<{ echoed: string }> = fortress.call.declarationLiteralEcho({ message: 'hello' });

  void loginResult;
  void iamResult;
  void paramsResult;
  void literalEcho;
  void literalResult;

  // @ts-expect-error -- built login input requires password
  fortress.call.login({ identifier: 'user@example.com' });
  // @ts-expect-error -- built IAM input rejects invalid permission effects
  fortress.call.createRole({ name: 'reader', permissions: [{ resource: 'articles', action: 'read', effect: 'MAYBE' }] });
  // @ts-expect-error -- built params input requires id
  fortress.call.revokeSession({});
  // @ts-expect-error -- built literal route input requires message
  fortress.call.declarationLiteralEcho({});
  // @ts-expect-error -- a no-route plugin contributes no callable
  fortress.call.health({});
  // @ts-expect-error -- unknown call names remain errors in built declarations
  fortress.call.notRegistered({});
  // @ts-expect-error -- built literal response must not degrade to any/unknown
  const incompatibleLiteralResult: Promise<{ echoed: number }> = fortress.call.declarationLiteralEcho({ message: 'hello' });
  void incompatibleLiteralResult;
}
