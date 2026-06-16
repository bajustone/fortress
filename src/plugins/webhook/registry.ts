/**
 * Event registry — the single source of truth for which events may be emitted.
 * Validates declarations at construction and provides name lookup.
 *
 * @module
 */

import type { BuiltinEventSource, WebhookEventDeclaration } from './types';

export interface EventRegistry {
  /** All declarations, in registration order. */
  list: () => WebhookEventDeclaration[];
  /** All event names, in registration order. */
  names: () => string[];
  get: (name: string) => WebhookEventDeclaration | undefined;
  has: (name: string) => boolean;
  /** Map of built-in hook source → event name, for hook binding. */
  sources: () => Map<BuiltinEventSource, string>;
}

const VALID_SOURCES: ReadonlySet<string> = new Set<BuiltinEventSource>([
  'afterLogin',
  'onLoginFailure',
  'beforeLogout',
  'afterRegister',
  'afterTokenRefresh',
]);

/**
 * Validate an event registry: every declaration needs a non-empty string name,
 * names must be unique, and any `source` must name a real hook. Throws on the
 * first violation (a construction-time bug, not a runtime condition).
 */
export function assertEventRegistry(events: WebhookEventDeclaration[]): void {
  const seen = new Set<string>();
  for (const event of events) {
    if (typeof event.name !== 'string' || event.name.length === 0)
      throw new TypeError('Webhook event declaration requires a non-empty string `name`');
    if (seen.has(event.name))
      throw new Error(`Duplicate webhook event name: ${event.name}`);
    seen.add(event.name);
    if (event.source !== undefined && !VALID_SOURCES.has(event.source))
      throw new Error(`Webhook event '${event.name}' has an unknown source: ${event.source}`);
  }
}

/** Build a validated {@link EventRegistry} from a list of declarations. */
export function createEventRegistry(events: WebhookEventDeclaration[]): EventRegistry {
  assertEventRegistry(events);
  const ordered = [...events];
  const byName = new Map(ordered.map(e => [e.name, e]));
  const sources = new Map<BuiltinEventSource, string>();
  for (const event of ordered) {
    if (event.source && !sources.has(event.source))
      sources.set(event.source, event.name);
  }
  return {
    list: () => ordered.map(e => ({ ...e })),
    names: () => ordered.map(e => e.name),
    get: name => byName.get(name),
    has: name => byName.has(name),
    sources: () => new Map(sources),
  };
}
