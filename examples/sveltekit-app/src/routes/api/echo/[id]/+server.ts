/**
 * Demonstrates the SvelteKit `vBody`/`vParam`/`vQuery` helpers.
 *
 * - GET  /api/echo/42?greeting=hi   → 200 { id: '42', greeting: 'hi' }
 * - GET  /api/echo/42               → 422 VALIDATION_ERROR (missing greeting)
 * - POST /api/echo/42 { name }      → 200 { id: '42', name }
 * - POST /api/echo/42 {}            → 422 VALIDATION_ERROR (missing name)
 *
 * Validation failures throw `FortressError('VALIDATION_ERROR', 422)` — the
 * same shape every fortress-managed endpoint produces. SvelteKit's default
 * error handling reports the thrown `FortressError` to the client.
 */

import { json } from '@sveltejs/kit';
import { obj, str } from '../../../../../../../src';
import { vBody, vParam, vQuery } from '../../../../../../../src/sveltekit';

const Param = obj({ id: str('Echo ID') }, 'id');
const Query = obj({ greeting: str('Greeting') }, 'greeting');
const Body = obj({ name: str('Name') }, 'name');

export async function GET(event: any): Promise<Response> {
  const { id } = await vParam(event, Param);
  const { greeting } = await vQuery(event, Query);
  return json({ id, greeting });
}

export async function POST(event: any): Promise<Response> {
  const { id } = await vParam(event, Param);
  const { name } = await vBody(event, Body);
  return json({ id, name });
}
