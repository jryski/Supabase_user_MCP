create or replace function public.post_model_message(
  p_from_agent text,
  p_to_agent text,
  p_subject text,
  p_body text,
  p_re_seq bigint default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public
as $function$
declare
  v_seq bigint;
  v_id uuid;
begin
  if nullif(btrim(p_from_agent), '') is null then
    raise exception 'from_agent is required';
  end if;

  if nullif(btrim(p_to_agent), '') is null then
    raise exception 'to_agent is required';
  end if;

  if nullif(btrim(p_body), '') is null then
    raise exception 'body is required';
  end if;

  if p_re_seq is not null
     and not exists (
       select 1
       from public.model_channel
       where seq = p_re_seq
     ) then
    raise exception 're_seq does not exist: %', p_re_seq;
  end if;

  insert into public.model_channel(
    from_agent,
    to_agent,
    re_seq,
    subject,
    body
  )
  values (
    btrim(p_from_agent),
    btrim(p_to_agent),
    p_re_seq,
    nullif(btrim(p_subject), ''),
    p_body
  )
  returning id, seq into v_id, v_seq;

  return jsonb_build_object(
    'id', v_id,
    'seq', v_seq,
    'from_agent', btrim(p_from_agent),
    'to_agent', btrim(p_to_agent)
  );
end;
$function$;

alter function public.post_model_message(text, text, text, text, bigint) owner to postgres;

revoke all on function public.post_model_message(text, text, text, text, bigint) from public;
revoke all on function public.post_model_message(text, text, text, text, bigint) from anon;
revoke all on function public.post_model_message(text, text, text, text, bigint) from authenticated;
grant execute on function public.post_model_message(text, text, text, text, bigint) to postgres;
grant execute on function public.post_model_message(text, text, text, text, bigint) to service_role;

comment on function public.post_model_message(text, text, text, text, bigint) is
  'Bounded service-role API for posting one model-channel message or reply. The model_channel identity allocates seq; the generated id and seq are returned in the receipt.';
