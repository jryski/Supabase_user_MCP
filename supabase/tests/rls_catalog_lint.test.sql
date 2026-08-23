begin;
create extension if not exists pgtap with schema extensions;
select plan(18);

create schema catalog_lint_fixture;

create table catalog_lint_fixture.l01 (id bigint);
grant select on catalog_lint_fixture.l01 to anon;

create table catalog_lint_fixture.l02 (id bigint);
alter table catalog_lint_fixture.l02 enable row level security;

create table catalog_lint_fixture.policies (id bigint, owner_id uuid);
alter table catalog_lint_fixture.policies enable row level security;
create policy l03 on catalog_lint_fixture.policies for select to public using (owner_id = auth.uid());
create policy l04 on catalog_lint_fixture.policies for select to authenticated using (auth.role() = 'authenticated');
create policy l05 on catalog_lint_fixture.policies for select to authenticated using (true);
create policy l06 on catalog_lint_fixture.policies for update to authenticated using (owner_id = auth.uid());

create table catalog_lint_fixture.view_source (id bigint);
create view catalog_lint_fixture.l07 as select id from catalog_lint_fixture.view_source;
grant select on catalog_lint_fixture.l07 to authenticated;

create function catalog_lint_fixture.l08() returns uuid language sql security definer
as 'select auth.uid()';
revoke all on function catalog_lint_fixture.l08() from public;
grant execute on function catalog_lint_fixture.l08() to authenticated;

create function catalog_lint_fixture.l09() returns integer language sql security definer
set search_path = pg_catalog
as 'select 1';
revoke all on function catalog_lint_fixture.l09() from public;
grant execute on function catalog_lint_fixture.l09() to anon;

create table catalog_lint_fixture.clean_table (id bigint, owner_id uuid);
alter table catalog_lint_fixture.clean_table enable row level security;
create policy clean_policy on catalog_lint_fixture.clean_table for update to authenticated
using (owner_id = auth.uid()) with check (owner_id = auth.uid());
grant update on catalog_lint_fixture.clean_table to authenticated;
create view catalog_lint_fixture.clean_view with (security_invoker = true) as
select id from catalog_lint_fixture.clean_table;
grant select on catalog_lint_fixture.clean_view to authenticated;
create function catalog_lint_fixture.clean_function() returns uuid language sql security definer
set search_path = pg_catalog
as 'select auth.uid()';
revoke all on function catalog_lint_fixture.clean_function() from public;
grant execute on function catalog_lint_fixture.clean_function() to authenticated;

\ir .rls_catalog_lint.generated.sql

select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L01' and obj = 'catalog_lint_fixture.l01'), 1::bigint, 'L01 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L02' and obj = 'catalog_lint_fixture.l02'), 1::bigint, 'L02 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L03' and obj like 'catalog_lint_fixture.policies.%'), 1::bigint, 'L03 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L04' and obj like 'catalog_lint_fixture.policies.%'), 1::bigint, 'L04 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L05' and obj like 'catalog_lint_fixture.policies.%'), 1::bigint, 'L05 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L06' and obj like 'catalog_lint_fixture.policies.%'), 1::bigint, 'L06 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L07' and obj = 'catalog_lint_fixture.l07'), 1::bigint, 'L07 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L08' and obj like 'catalog_lint_fixture.l08%'), 1::bigint, 'L08 positive');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L09' and obj like 'catalog_lint_fixture.l09%'), 1::bigint, 'L09 positive');

select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L01' and obj = 'catalog_lint_fixture.clean_table'), 0::bigint, 'L01 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L02' and obj = 'catalog_lint_fixture.clean_table'), 0::bigint, 'L02 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L03' and obj like 'catalog_lint_fixture.clean_table.%'), 0::bigint, 'L03 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L04' and obj like 'catalog_lint_fixture.clean_table.%'), 0::bigint, 'L04 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L05' and obj like 'catalog_lint_fixture.clean_table.%'), 0::bigint, 'L05 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L06' and obj like 'catalog_lint_fixture.clean_table.%'), 0::bigint, 'L06 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L07' and obj = 'catalog_lint_fixture.clean_view'), 0::bigint, 'L07 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L08' and obj like 'catalog_lint_fixture.clean_function%'), 0::bigint, 'L08 clean');
select is((select count(*) from pg_temp.rls_catalog_lint where id = 'L09' and obj like 'catalog_lint_fixture.clean_function%'), 0::bigint, 'L09 clean');

select * from finish();
rollback;
