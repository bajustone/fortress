<!--
  OAuth consent page. Renders the client name, redirect URI, and requested
  scopes from the data the `+page.server.ts` load returned, then offers
  Allow / Deny form actions.

  Two separate <form>s so each button submits to its own action. SvelteKit's
  `?/approve` / `?/deny` syntax in `formaction` keeps this single-file.
-->
<script lang="ts">
  import { enhance } from '$app/forms';

  let { data } = $props<{
    data: {
      flow: {
        flowId: number;
        client: { clientId: string; name: string };
        redirectUri: string;
        scopes: string[];
        state: string;
      };
    };
  }>();
</script>

<main class="consent">
  <h1>Authorize {data.flow.client.name}</h1>
  <p>
    <strong>{data.flow.client.name}</strong> wants to access your account.
    It will be able to:
  </p>

  {#if data.flow.scopes.length > 0}
    <ul>
      {#each data.flow.scopes as scope}
        <li><code>{scope}</code></li>
      {/each}
    </ul>
  {:else}
    <p><em>No specific permissions requested.</em></p>
  {/if}

  <p class="redirect">
    You will be redirected to:
    <code>{data.flow.redirectUri}</code>
  </p>

  <form method="POST" use:enhance class="actions">
    <button type="submit" formaction="?/deny" class="btn-secondary">
      Deny
    </button>
    <button type="submit" formaction="?/approve" class="btn-primary">
      Allow
    </button>
  </form>
</main>

<style>
  .consent {
    max-width: 28rem;
    margin: 4rem auto;
    padding: 2rem;
    border: 1px solid #e2e8f0;
    border-radius: 0.75rem;
    font-family: system-ui, sans-serif;
  }
  h1 { margin-top: 0; }
  ul { margin: 0.5rem 0 1.5rem; padding-left: 1.5rem; }
  .redirect { color: #475569; font-size: 0.9rem; }
  .actions {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    margin-top: 1.5rem;
  }
  .btn-primary, .btn-secondary {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    cursor: pointer;
  }
  .btn-primary  { background: #2563eb; color: white; border: none; }
  .btn-secondary{ background: white; color: #334155; border: 1px solid #cbd5e1; }
</style>
