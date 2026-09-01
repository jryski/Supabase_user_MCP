import { createRequire } from 'node:module';

interface AuthClientOptions {
  url: string;
  headers: Record<string, string>;
  fetch?: typeof globalThis.fetch;
  persistSession: boolean;
  autoRefreshToken: boolean;
  detectSessionInUrl: boolean;
  skipAutoInitialize: boolean;
}

interface AuthClientLike {
  signInWithPassword(credentials: { email: string; password: string }): Promise<{
    data: { session: { access_token?: string } | null };
    error: unknown;
  }>;
}

interface AuthClientConstructor {
  new (options: AuthClientOptions): AuthClientLike;
}

const require = createRequire(import.meta.url);
const { AuthClient } = require('@supabase/auth-js') as {
  AuthClient: AuthClientConstructor;
};

export interface SyntheticM2SignInOptions {
  readonly authUrl: string;
  readonly projectPublishableKey: string;
  readonly email: string;
  readonly password: string;
  readonly fetch?: typeof globalThis.fetch;
}

export async function signInSyntheticM2User(options: SyntheticM2SignInOptions): Promise<string> {
  const authUrl = new URL(options.authUrl);
  if (authUrl.search || authUrl.hash || authUrl.pathname.replace(/\/$/u, '') !== '/auth/v1') {
    throw new TypeError('Synthetic local Auth URL must target the fixed /auth/v1 endpoint.');
  }

  const authOptions: AuthClientOptions = {
    url: authUrl.href.replace(/\/$/u, ''),
    headers: { apikey: options.projectPublishableKey },
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
    skipAutoInitialize: true,
  };
  if (options.fetch) authOptions.fetch = options.fetch;
  const auth = new AuthClient(authOptions);
  const { data, error } = await auth.signInWithPassword({
    email: options.email,
    password: options.password,
  });
  const accessToken = data.session?.access_token;
  if (error || typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new Error('Synthetic local Auth sign-in failed.');
  }
  return accessToken;
}
