import type { CallOptions, DatabaseAdapter, FortressPlugin } from '@bajustone/fortress';
import { createFortress, definePlugin, endpoint, obj, str } from '@bajustone/fortress';

type ExpectedLiteralEcho = (
  input: { message: string },
  options?: CallOptions,
) => Promise<{ echoed: string }>;

/** Compiled against package self-reference after `tsup` emits declarations. */
export function acceptsPreciseBuiltCallSurface(database: DatabaseAdapter): void {
  const literalRoutePlugin = definePlugin({
    name: 'declaration-literal-route',
    methods: () => ({
      declarationLiteralEcho: async ({ message }: { message: string }): Promise<{ echoed: string }> => ({ echoed: message }),
    }),
    routes: {
      declarationLiteralEcho: endpoint('POST', '/declaration/literal-echo')
        .security('none')
        .body(obj({ message: str() }, 'message'))
        .response(200, 'Echo response', obj({ echoed: str() }, 'echoed'))
        .handler('declarationLiteralEcho')
        .build(),
    },
  });
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
  }> = fortress.call.auth.login({ identifier: 'user@example.com', password: 'secret' });
  const iamResult: Promise<{
    id: string;
    name: string;
    description?: string | null;
    isSystem?: boolean;
  }> = fortress.call.iam.createRole({
    name: 'reader',
    permissions: [{ resource: 'articles', action: 'read' }],
  });
  const paramsResult: Promise<{ ok: boolean }> = fortress.call.auth.revokeSession({ id: 'session-id' });
  const literalEcho: ExpectedLiteralEcho = fortress.call.plugins['declaration-literal-route'].declarationLiteralEcho;
  const literalResult: Promise<{ echoed: string }> = fortress.call.plugins['declaration-literal-route'].declarationLiteralEcho({ message: 'hello' });

  void loginResult;
  void iamResult;
  void paramsResult;
  void literalEcho;
  void literalResult;

  // @ts-expect-error -- built login input requires password
  fortress.call.auth.login({ identifier: 'user@example.com' });
  // @ts-expect-error -- built IAM input rejects invalid permission effects
  fortress.call.iam.createRole({ name: 'reader', permissions: [{ resource: 'articles', action: 'read', effect: 'MAYBE' }] });
  // @ts-expect-error -- built params input requires id
  fortress.call.auth.revokeSession({});
  // @ts-expect-error -- built literal route input requires message
  fortress.call.plugins['declaration-literal-route'].declarationLiteralEcho({});
  // @ts-expect-error -- a no-route plugin contributes no call namespace
  void fortress.call.plugins['declaration-no-route'];
  // @ts-expect-error -- unknown call names remain errors in built declarations
  fortress.call.plugins['declaration-literal-route'].notRegistered({});
  // @ts-expect-error -- core callables are namespaced; login is not at the call root
  fortress.call.login({ identifier: 'user@example.com', password: 'secret' });
  // @ts-expect-error -- built login response must not degrade to any/never
  const incompatibleLoginResult: Promise<{ status: 'invalid' }> = fortress.call.auth.login({
    identifier: 'user@example.com',
    password: 'secret',
  });
  // @ts-expect-error -- built IAM response must not degrade to any/never
  const incompatibleIamResult: Promise<{ id: number }> = fortress.call.iam.createRole({
    name: 'reader',
    permissions: [{ resource: 'articles', action: 'read' }],
  });
  // @ts-expect-error -- built params response must not degrade to any/never
  const incompatibleParamsResult: Promise<{ ok: string }> = fortress.call.auth.revokeSession({ id: 'session-id' });
  // @ts-expect-error -- built literal response must not degrade to any/unknown
  const incompatibleLiteralResult: Promise<{ echoed: number }> = fortress.call.plugins['declaration-literal-route'].declarationLiteralEcho({ message: 'hello' });
  void incompatibleLoginResult;
  void incompatibleIamResult;
  void incompatibleParamsResult;
  void incompatibleLiteralResult;
}
