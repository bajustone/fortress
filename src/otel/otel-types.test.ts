import type {
  AuthEvent,
  AuthEventListener,
  FortressLogger,
  IamEvent,
  IamEventListener,
  PermissionCheckEvent,
  PermissionCheckListener,
  TelemetryProvider,
  Unsubscribe,
} from '../index';
import type {
  AuthEvent as OtelAuthEvent,
  AuthEventListener as OtelAuthEventListener,
  FortressLogger as OtelFortressLogger,
  IamEvent as OtelIamEvent,
  IamEventListener as OtelIamEventListener,
  PermissionCheckEvent as OtelPermissionCheckEvent,
  PermissionCheckListener as OtelPermissionCheckListener,
  TelemetryProvider as OtelTelemetryProvider,
  Unsubscribe as OtelUnsubscribe,
} from './index';
import { expectTypeOf, it } from 'vitest';

it('exports public observability contracts from root and /otel', () => {
  expectTypeOf<OtelFortressLogger>().toEqualTypeOf<FortressLogger>();
  expectTypeOf<OtelTelemetryProvider>().toEqualTypeOf<TelemetryProvider>();
  expectTypeOf<OtelAuthEvent>().toEqualTypeOf<AuthEvent>();
  expectTypeOf<OtelAuthEventListener>().toEqualTypeOf<AuthEventListener>();
  expectTypeOf<OtelIamEvent>().toEqualTypeOf<IamEvent>();
  expectTypeOf<OtelIamEventListener>().toEqualTypeOf<IamEventListener>();
  expectTypeOf<OtelPermissionCheckEvent>().toEqualTypeOf<PermissionCheckEvent>();
  expectTypeOf<OtelPermissionCheckListener>().toEqualTypeOf<PermissionCheckListener>();
  expectTypeOf<OtelUnsubscribe>().toEqualTypeOf<Unsubscribe>();
});
