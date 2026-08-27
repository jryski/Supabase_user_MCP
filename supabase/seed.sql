-- Seed fixtures for Prompt 1 / S1 Governed Artifact Inspection.
-- Synthetic-only identities and artifacts; no production keys or data.

begin;

-- Local-lab fixture setup only. Keeping this policy in seed.sql prevents it
-- from entering a hosted project through the production migration path.
drop policy if exists artifact_storage_fixture_upload on storage.objects;
create policy artifact_storage_fixture_upload
  on storage.objects
  for insert
  to authenticated
  with check (
    bucket_id in ('artifact-lab', 'artifact-outside')
    and auth.jwt() #>> '{app_metadata,s1_fixture_loader}' = 'true'
  );

insert into public.approved_inspector_clients (client_id, active, notes)
values
  ('smp-lab-inspector', true, 'Primary synthetic inspector client'),
  ('smp-lab-reviewer', true, 'Secondary synthetic reviewer client')
on conflict (client_id) do nothing;

insert into auth.users (
  id,
  instance_id,
  aud,
  role,
  email,
  raw_app_meta_data,
  encrypted_password,
  email_confirmed_at,
  created_at,
  updated_at
)
values
  (
    '11111111-1111-4111-9111-111111111111'::uuid,
    '00000000-0000-0000-0000-000000000000'::uuid,
    'authenticated',
    'authenticated',
    'alice.fixture@example.test',
    '{"provider":"email","providers":["email"],"client_id":"smp-lab-inspector"}'::jsonb,
    crypt('SmpStrongPass!1', gen_salt('bf')),
    now(),
    now(),
    now()
  ),
  (
    '22222222-2222-4222-9222-222222222222'::uuid,
    '00000000-0000-0000-0000-000000000000'::uuid,
    'authenticated',
    'authenticated',
    'bob.fixture@example.test',
    '{"provider":"email","providers":["email"],"client_id":"smp-lab-inspector"}'::jsonb,
    crypt('SmpStrongPass!1', gen_salt('bf')),
    now(),
    now(),
    now()
  ),
  (
    '33333333-3333-4333-9333-333333333333'::uuid,
    '00000000-0000-0000-0000-000000000000'::uuid,
    'authenticated',
    'authenticated',
    'charlie.fixture@example.test',
    '{"provider":"email","providers":["email"],"client_id":"smp-lab-unapproved"}'::jsonb,
    crypt('SmpStrongPass!1', gen_salt('bf')),
    now(),
    now(),
    now()
  ),
  (
    '44444444-4444-4444-8444-444444444444'::uuid,
    '00000000-0000-0000-0000-000000000000'::uuid,
    'authenticated',
    'authenticated',
    'dana.fixture@example.test',
    '{"provider":"email","providers":["email"]}'::jsonb,
    crypt('SmpStrongPass!1', gen_salt('bf')),
    now(),
    now(),
    now()
  ),
  (
    '55555555-5555-4555-8555-555555555555'::uuid,
    '00000000-0000-0000-0000-000000000000'::uuid,
    'authenticated',
    'authenticated',
    'loader.fixture@example.test',
    '{"provider":"email","providers":["email"],"s1_fixture_loader":true}'::jsonb,
    crypt('SmpStrongPass!1', gen_salt('bf')),
    now(),
    now(),
    now()
  )
on conflict (id) do nothing;

update auth.users
set confirmation_token = '',
    recovery_token = '',
    email_change_token_new = '',
    email_change = '',
    phone_change = '',
    phone_change_token = '',
    email_change_token_current = '',
    reauthentication_token = ''
where id in (
  '11111111-1111-4111-9111-111111111111'::uuid,
  '22222222-2222-4222-9222-222222222222'::uuid,
  '33333333-3333-4333-9333-333333333333'::uuid,
  '44444444-4444-4444-8444-444444444444'::uuid,
  '55555555-5555-4555-8555-555555555555'::uuid
);

insert into auth.identities (
  id,
  user_id,
  provider_id,
  identity_data,
  provider,
  last_sign_in_at,
  created_at,
  updated_at
)
select
  gen_random_uuid(),
  u.id,
  u.id::text,
  jsonb_build_object(
    'sub', u.id::text,
    'email', u.email,
    'email_verified', true,
    'phone_verified', false
  ),
  'email',
  now(),
  now(),
  now()
from auth.users u
where u.id in (
  '11111111-1111-4111-9111-111111111111'::uuid,
  '22222222-2222-4222-9222-222222222222'::uuid,
  '33333333-3333-4333-9333-333333333333'::uuid,
  '44444444-4444-4444-8444-444444444444'::uuid,
  '55555555-5555-4555-8555-555555555555'::uuid
)
on conflict (provider_id, provider) do nothing;

insert into storage.buckets (id, name, public)
values
  ('artifact-lab', 'artifact-lab', false),
  ('artifact-outside', 'artifact-outside', false)
on conflict (id) do nothing;

-- 1) authorized artifact (alice)
insert into public.artifact_registry (
  artifact_id,
  principal_id,
  bucket,
  object_key,
  byte_length,
  sha256_full,
  merkle_root,
  chunk_size,
  chunk_count,
  content_type
) values (
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
  '11111111-1111-4111-9111-111111111111'::uuid,
  'artifact-lab',
  'authorized.txt',
  28,
  decode('7def1c34107698d399c57f22ef2dc4af7fd129fe11f486bc93b7b0030ad6dffc', 'hex'),
  decode('71fde2b05978951439eac2f35ae71ae997a8ee09279c139a6e19dec2cef5a360', 'hex'),
  16,
  2,
  'text/plain'
) on conflict (artifact_id) do nothing;

insert into public.artifact_chunks (artifact_id, chunk_index, byte_start, byte_length, sha256)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid, 0, 0, 16, decode('cf8c651e1de35afb34aa58e554d80871aebc2b9db2ebab6dbf2f4d8259b3b178', 'hex')),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid, 1, 16, 12, decode('89e473e57b5dc545765fd76e51d0cde9dc3bd9263d05be42fef24a5138d6abde', 'hex'))
on conflict do nothing;

-- 2) wrong principal artifact (bob)
insert into public.artifact_registry (
  artifact_id,
  principal_id,
  bucket,
  object_key,
  byte_length,
  sha256_full,
  merkle_root,
  chunk_size,
  chunk_count,
  content_type
) values (
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,
  '22222222-2222-4222-9222-222222222222'::uuid,
  'artifact-lab',
  'wrong-principal.txt',
  12,
  decode('439675cb240724c005c4dc880f5e832f12e1d7bb27f35356e25c978de246270f', 'hex'),
  decode('439675cb240724c005c4dc880f5e832f12e1d7bb27f35356e25c978de246270f', 'hex'),
  12,
  1,
  'text/plain'
) on conflict (artifact_id) do nothing;

insert into public.artifact_chunks (artifact_id, chunk_index, byte_start, byte_length, sha256)
values
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid, 0, 0, 12, decode('439675cb240724c005c4dc880f5e832f12e1d7bb27f35356e25c978de246270f', 'hex'))
on conflict do nothing;

-- 3) expired fixture row (alice)
insert into public.artifact_registry (
  artifact_id,
  principal_id,
  bucket,
  object_key,
  byte_length,
  sha256_full,
  merkle_root,
  chunk_size,
  chunk_count,
  content_type,
  expires_at
) values (
  'cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,
  '11111111-1111-4111-9111-111111111111'::uuid,
  'artifact-lab',
  'expired.txt',
  16,
  decode('605b06e47d1aa1c2885c0798dcec05d99251dd0d05b2e81e4ee8bf0ea7dc001a', 'hex'),
  decode('605b06e47d1aa1c2885c0798dcec05d99251dd0d05b2e81e4ee8bf0ea7dc001a', 'hex'),
  16,
  1,
  'text/plain',
  now() - interval '1 hour'
) on conflict (artifact_id) do nothing;

insert into public.artifact_chunks (artifact_id, chunk_index, byte_start, byte_length, sha256)
values
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid, 0, 0, 16, decode('605b06e47d1aa1c2885c0798dcec05d99251dd0d05b2e81e4ee8bf0ea7dc001a', 'hex'))
on conflict do nothing;

-- 4) registered row without object in storage
insert into public.artifact_registry (
  artifact_id,
  principal_id,
  bucket,
  object_key,
  byte_length,
  sha256_full,
  merkle_root,
  chunk_size,
  chunk_count,
  content_type
) values (
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd'::uuid,
  '11111111-1111-4111-9111-111111111111'::uuid,
  'artifact-lab',
  'registered-missing.txt',
  11,
  decode(repeat('ee', 32), 'hex'),
  decode(repeat('ee', 32), 'hex'),
  11,
  1,
  'text/plain'
) on conflict (artifact_id) do nothing;

-- 5) object-present-without-registry fixture
-- Inserted by the matrix harness as a storage object under artifact-lab/present-unregistered.txt.
-- No registry row exists for this key, intentionally.

-- Object in a non-inspector bucket, even though Alice owns its registry row.
insert into public.artifact_registry (
  artifact_id, principal_id, bucket, object_key, byte_length, sha256_full,
  merkle_root, chunk_size, chunk_count, content_type
) values (
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
  '11111111-1111-4111-9111-111111111111'::uuid,
  'artifact-outside',
  'outside.txt',
  14,
  decode('8c32ea895d4092c49a1f37edfcbf60fd53db4427e7043957fb21a7fafde0c84d', 'hex'),
  decode('8c32ea895d4092c49a1f37edfcbf60fd53db4427e7043957fb21a7fafde0c84d', 'hex'),
  14,
  1,
  'text/plain'
) on conflict (artifact_id) do nothing;

insert into public.artifact_chunks (artifact_id, chunk_index, byte_start, byte_length, sha256)
values (
  'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,
  0,
  0,
  14,
  decode('8c32ea895d4092c49a1f37edfcbf60fd53db4427e7043957fb21a7fafde0c84d', 'hex')
) on conflict do nothing;

-- 6) mutation detection fixture: registry + chunks intentionally inconsistent
insert into public.artifact_registry (
  artifact_id,
  principal_id,
  bucket,
  object_key,
  byte_length,
  sha256_full,
  merkle_root,
  chunk_size,
  chunk_count,
  content_type
) values (
  'ffffffff-ffff-4fff-8fff-ffffffffffff'::uuid,
  '11111111-1111-4111-9111-111111111111'::uuid,
  'artifact-lab',
  'mutated-after-reg.txt',
  16,
  decode('09757dab1d4c65e1bee3b4a452d1e8e45e1b28a2ff76de694be6b0c97e7e7d49', 'hex'),
  decode('53af90fe4d544c7efe38329f3b0cf1e45e5a85d2ae37c66293dce0a4ad14b78d', 'hex'),
  8,
  2,
  'text/plain'
) on conflict (artifact_id) do nothing;

insert into public.artifact_chunks (artifact_id, chunk_index, byte_start, byte_length, sha256)
values
  ('ffffffff-ffff-4fff-8fff-ffffffffffff'::uuid, 0, 0, 8, decode('0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5', 'hex')),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff'::uuid, 1, 8, 8, decode('758f87ce10ea274414d02468f25b5f85fcac10a850afa9feb02a2910ad26c847', 'hex'))
on conflict do nothing;

insert into public.artifact_derivations (
  derivation_id,
  derived_artifact_id,
  derivation_type,
  profile_id,
  profile_version,
  scope
) values (
  '12345678-1234-4123-8123-1234567890ab'::uuid,
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
  'profile_csv',
  's1_csv',
  '2026.08.26',
  'artifact_scope'
) on conflict (derivation_id) do nothing;

insert into public.derivation_inputs (
  derivation_id,
  source_artifact_id,
  source_sha256
) values (
  '12345678-1234-4123-8123-1234567890ab'::uuid,
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
  decode('7def1c34107698d399c57f22ef2dc4af7fd129fe11f486bc93b7b0030ad6dffc', 'hex')
), (
  '12345678-1234-4123-8123-1234567890ab'::uuid,
  'ffffffff-ffff-4fff-8fff-ffffffffffff'::uuid,
  decode('09757dab1d4c65e1bee3b4a452d1e8e45e1b28a2ff76de694be6b0c97e7e7d49', 'hex')
) on conflict do nothing;

commit;
