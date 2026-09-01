import { parseExpectedMemoryPostgrestSurface } from '../../packages/server/src/postgrest-openapi-census.js';

const supabaseUrl = process.env.M2_SUPABASE_URL;
const projectPublishableKey = process.env.M2_PUBLISHABLE_KEY;
const userAccessToken = process.env.M2_ALICE_TOKEN;
if (!supabaseUrl || !projectPublishableKey || !userAccessToken) {
  process.stderr.write('PostgREST surface census configuration is incomplete.\n');
  process.exit(2);
}

try {
  const response = await fetch(new URL('/rest/v1/', supabaseUrl), {
    method: 'GET',
    redirect: 'error',
    headers: {
      apikey: projectPublishableKey,
      Authorization: `Bearer ${userAccessToken}`,
      Accept: 'application/openapi+json',
      'Accept-Profile': 'memory',
    },
  });
  if (!response.ok) throw new Error('PostgREST OpenAPI request failed.');
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > 1_048_576) {
    throw new Error('PostgREST OpenAPI document exceeds the census ceiling.');
  }
  const census = parseExpectedMemoryPostgrestSurface(text);
  process.stdout.write(JSON.stringify(census));
} catch {
  process.stderr.write('Authenticated PostgREST surface census failed.\n');
  process.exit(1);
}
