import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Minimal Supabase-shaped database surface for local PGlite runs: the API
 * roles, `auth.jwt()` / `auth.uid()`, and the parts of the `storage` schema
 * the storage migrations and policies use. Synthetic only; never a live project.
 */
export const SUPABASE_STUB_SQL = `
create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
create schema if not exists extensions;
create schema auth;
create table auth.users (id uuid primary key);
create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claim', true), ''),
                  nullif(current_setting('request.jwt.claims', true), ''))::jsonb $$;
create function auth.uid() returns uuid language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''),
                  (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'))::uuid $$;
grant usage on schema auth to anon, authenticated;
grant execute on all functions in schema auth to anon, authenticated;
create schema storage;
create table storage.buckets (id text primary key, name text not null unique, public boolean default false,
  file_size_limit bigint, allowed_mime_types text[], owner uuid, created_at timestamptz default now());
create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text references storage.buckets(id),
  name text, owner uuid, owner_id text, metadata jsonb, created_at timestamptz default now(), unique (bucket_id, name));
alter table storage.objects enable row level security;
create function storage.foldername(name text) returns text[] language sql immutable as $$
  select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1] $$;
create function storage.allow_only_operation(op text) returns boolean language sql stable as $$
  select current_setting('storage.operation', true) = op $$;
grant usage on schema storage to anon, authenticated;
grant select, insert, update, delete on storage.objects, storage.buckets to anon, authenticated;
grant execute on all functions in schema storage to anon, authenticated;
`;

/**
 * Copy of the hosted Storage guard (supabase/storage tenant migration
 * 0055-prevent-direct-deletes): a direct DELETE on storage.objects or
 * storage.buckets fails with 42501 unless the transaction sets
 * `storage.allow_delete_query` to 'true', which the Storage API does for its
 * own deletes.
 */
export const STORAGE_PROTECT_DELETE_SQL = `
CREATE OR REPLACE FUNCTION storage.protect_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF COALESCE(current_setting('storage.allow_delete_query', true), 'false') != 'true' THEN
        RAISE EXCEPTION 'Direct deletion from storage tables is not allowed. Use the Storage API instead.'
            USING HINT = 'This prevents accidental data loss from orphaned objects.',
                  ERRCODE = '42501';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS protect_buckets_delete ON storage.buckets;
CREATE TRIGGER protect_buckets_delete
    BEFORE DELETE ON storage.buckets
    FOR EACH STATEMENT
    EXECUTE FUNCTION storage.protect_delete();

DROP TRIGGER IF EXISTS protect_objects_delete ON storage.objects;
CREATE TRIGGER protect_objects_delete
    BEFORE DELETE ON storage.objects
    FOR EACH STATEMENT
    EXECUTE FUNCTION storage.protect_delete();
`;

export interface SqlExecutor {
  exec(sql: string): Promise<unknown>;
}

export async function applySupabaseStub(
  db: SqlExecutor,
  options: { readonly protectDelete?: boolean } = {},
): Promise<void> {
  await db.exec(SUPABASE_STUB_SQL);
  if (options.protectDelete ?? true) await db.exec(STORAGE_PROTECT_DELETE_SQL);
}

/** Applies every repo migration in file-name order and returns the names applied. */
export async function applyRepoMigrations(db: SqlExecutor, repoRoot: string): Promise<string[]> {
  const directory = join(repoRoot, 'supabase/migrations');
  const files = readdirSync(directory)
    .filter((file) => file.endsWith('.sql'))
    .toSorted();
  for (const file of files) await db.exec(readFileSync(join(directory, file), 'utf8'));
  return files;
}
