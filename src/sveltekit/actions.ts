/**
 * SvelteKit form-action helpers for the common auth flows.
 *
 * Use these in `+page.server.ts` to wire `<form method="POST">` to
 * fortress's auth methods. They handle:
 *
 * - parsing form data
 * - calling `fortress.auth.*`
 * - setting cookies via `event.cookies.set` (so SvelteKit's `Set-Cookie`
 *   handling sees them, not just the browser)
 * - returning `fail(...)` on `FortressError`
 * - throwing a `redirect(...)` on success when `redirectTo` is supplied
 *
 * The thrown redirect uses SvelteKit's convention: a thrown `Response`
 * with a 3xx status and a `Location` header. SvelteKit's action runtime
 * unwraps this into a normal HTTP redirect.
 *
 * @example
 * ```ts
 * // src/routes/login/+page.server.ts
 * import { fortressActions } from '@bajustone/fortress/sveltekit';
 * import { fortress } from '$lib/server/fortress';
 *
 * export const actions = {
 *   default: fortressActions.login(fortress, { redirectTo: '/dashboard' }),
 * };
 * ```
 */

import type { Fortress } from '../core/fortress';
import type { AuthChallenge, CreateUserInput, LoginIdentifierType } from '../core/types';
import type { SvelteKitAction, SvelteKitRequestEvent } from './types';
import { FortressError } from '../core/errors';
import { clearAuthCookies, setAuthCookies } from './cookies';

/** Shape returned by form-action helpers when something goes wrong. */
export interface FortressActionFailure {
  status: number;
  data: { error: string; code?: string };
}

/** Shape returned on success when no `redirectTo` is configured. */
export interface FortressActionSuccess {
  success: true;
  /** Present when another auth step is required and no cookies were issued. */
  pending?: AuthChallenge;
}

/** Common options for the auth-issuing helpers. */
export interface FortressActionOptions {
  /**
   * On success, throw a redirect to this path. SvelteKit's action runtime
   * picks up the thrown 3xx and emits a normal HTTP redirect.
   */
  redirectTo?: string;
}

/**
 * Build a synthetic `Response` carrying a 3xx redirect, then `throw` it.
 * SvelteKit's action runtime treats thrown responses as the action result.
 *
 * Implemented locally instead of importing `redirect` from `@sveltejs/kit`
 * so the adapter has zero hard dependency on the framework.
 */
function throwRedirect(status: 300 | 301 | 302 | 303 | 307 | 308, location: string): never {
  // SvelteKit's `redirect()` throws an object with a special shape it
  // recognizes. To stay framework-agnostic we throw a Response, which
  // SvelteKit also recognizes as a "I want this exact response."
  throw new Response(null, { status, headers: { Location: location } });
}

/** Build a `fail`-shaped object SvelteKit returns from a failed action. */
function fail(status: number, data: { error: string; code?: string }): FortressActionFailure {
  return { status, data };
}

/** Read a single string field from a form, defaulting to '' if missing. */
function field(form: FormData, name: string): string {
  const v = form.get(name);
  return typeof v === 'string' ? v : '';
}

function buildMeta(event: SvelteKitRequestEvent): { ipAddress?: string; userAgent?: string } {
  return {
    ipAddress:
      event.request.headers.get('x-forwarded-for')
      ?? event.request.headers.get('x-real-ip')
      ?? undefined,
    userAgent: event.request.headers.get('user-agent') ?? undefined,
  };
}

/** Type of the {@link fortressActions} namespace — explicit so JSR's slow-type check is happy. */
export interface FortressActions {
  login: (
    fortress: Fortress,
    opts?: FortressActionOptions,
  ) => SvelteKitAction<FortressActionFailure | FortressActionSuccess>;
  register: (
    fortress: Fortress,
    opts?: FortressActionOptions,
  ) => SvelteKitAction<FortressActionFailure | FortressActionSuccess>;
  logout: (
    fortress: Fortress,
    opts?: FortressActionOptions,
  ) => SvelteKitAction<FortressActionSuccess>;
  refresh: (
    fortress: Fortress,
  ) => SvelteKitAction<FortressActionFailure | FortressActionSuccess>;
}

/** Form-action helpers exported as a single namespace. */
export const fortressActions: FortressActions = {
  /**
   * Sign in with `identifier` + `password` form fields. Sets the access +
   * refresh cookies on success. Optionally redirects.
   */
  login(
    fortress: Fortress,
    opts: FortressActionOptions = {},
  ): SvelteKitAction<FortressActionFailure | FortressActionSuccess> {
    return async (event) => {
      const form = await event.request.formData();
      const identifier = field(form, 'identifier');
      const password = field(form, 'password');
      try {
        const result = await fortress.auth.login(identifier, password, buildMeta(event));
        if (result.status === 'pending')
          return { success: true, pending: result.pending } as const;
        if (result.status !== 'success')
          return { success: true } as const;
        setAuthCookies(event, fortress, {
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
        });
        if (opts.redirectTo)
          throwRedirect(303, opts.redirectTo);
        return { success: true } as const;
      }
      catch (err) {
        if (err instanceof FortressError) {
          return fail(err.statusCode, { error: err.message, code: err.code });
        }
        throw err;
      }
    };
  },

  /**
   * Register a new user from `email`, `name`, `password` form fields. On
   * success, immediately logs them in (sets cookies) and optionally
   * redirects. Mirrors the typical sign-up UX.
   */
  register(
    fortress: Fortress,
    opts: FortressActionOptions = {},
  ): SvelteKitAction<FortressActionFailure | FortressActionSuccess> {
    return async (event) => {
      const form = await event.request.formData();
      const data: CreateUserInput = {
        email: field(form, 'email'),
        name: field(form, 'name'),
        password: field(form, 'password'),
      };
      try {
        await fortress.auth.createUser(data);
        const result = await fortress.auth.login(data.email, data.password ?? '', buildMeta(event));
        if (result.status === 'pending')
          return { success: true, pending: result.pending } as const;
        if (result.status !== 'success')
          return { success: true } as const;
        setAuthCookies(event, fortress, {
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
        });
        if (opts.redirectTo)
          throwRedirect(303, opts.redirectTo);
        return { success: true } as const;
      }
      catch (err) {
        if (err instanceof FortressError) {
          return fail(err.statusCode, { error: err.message, code: err.code });
        }
        throw err;
      }
    };
  },

  /**
   * Revoke the current refresh token (if present) and clear both auth
   * cookies. Optionally redirects.
   */
  logout(
    fortress: Fortress,
    opts: FortressActionOptions = {},
  ): SvelteKitAction<FortressActionSuccess> {
    return async (event) => {
      const refreshToken = event.cookies.get(fortress.cookies.refreshName);
      if (refreshToken) {
        try {
          await fortress.auth.logout(refreshToken);
        }
        catch {
          // Ignore — clearing cookies is the important part.
        }
      }
      clearAuthCookies(event, fortress);
      if (opts.redirectTo)
        throwRedirect(303, opts.redirectTo);
      return { success: true } as const;
    };
  },

  /**
   * Manually rotate the access + refresh tokens using the cookie. Useful
   * if you want a `?/refresh` form action for SPAs that need to extend a
   * session without a full reload.
   */
  refresh(
    fortress: Fortress,
  ): SvelteKitAction<FortressActionFailure | FortressActionSuccess> {
    return async (event) => {
      const refreshToken = event.cookies.get(fortress.cookies.refreshName);
      if (!refreshToken) {
        return fail(401, { error: 'No refresh token', code: 'UNAUTHORIZED' });
      }
      try {
        const result = await fortress.auth.refresh(refreshToken, buildMeta(event));
        setAuthCookies(event, fortress, result);
        return { success: true } as const;
      }
      catch (err) {
        if (err instanceof FortressError) {
          return fail(err.statusCode, { error: err.message, code: err.code });
        }
        throw err;
      }
    };
  },
} as const;

// Re-export so consumers can pattern-match against the field type.
export type { LoginIdentifierType };
