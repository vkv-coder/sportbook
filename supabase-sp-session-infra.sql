-- Sportbook / Mahjong (sp_/mj_) — real session-token identity layer.
--
-- Root cause of the mj_ findings: there was no server-verifiable
-- identity for regular players at all. Login (verify_player_otp) only
-- checked the OTP and returned a boolean; the client then fetched the
-- plain sp_members row and stored the whole thing (including id) in
-- localStorage. Every subsequent write just trusted whatever id was
-- sitting in localStorage - trivially spoofable via browser devtools,
-- no server-side check possible. This is what let every mj_ table be
-- USING(true)/WITH CHECK(true) - there was nothing real to check
-- against.
--
-- This adds the same technique Supabase itself documents for building
-- custom (non-Supabase-Auth) login: after OTP verification, issue a
-- real, unguessable session token stored server-side, have the client
-- send it as an Authorization header on every request, and let RLS
-- policies resolve "who is making this request" from that header via
-- sp_current_member_id() - the same role auth.uid() plays for real
-- Supabase Auth apps elsewhere in this portfolio (mt_, gc_, hb_, dr_).

create table if not exists sp_member_sessions (
  token uuid primary key default gen_random_uuid(),
  member_id uuid not null references sp_members(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 days')
);

alter table sp_member_sessions enable row level security;
-- No policies -> deny-all for anon/authenticated; only SECURITY DEFINER
-- functions (which bypass RLS) can read/write this table.

-- Resolves the current request's member identity from a custom
-- X-Session-Token header, the same way auth.uid() resolves identity
-- from a Supabase Auth JWT elsewhere in this portfolio. Uses a custom
-- header rather than Authorization: PostgREST validates Authorization
-- as a real Supabase Auth JWT and rejects the request outright
-- (PGRST301 "Expected 3 parts in JWT") if it isn't one - confirmed by
-- testing directly against the live API before settling on this
-- design. Authorization keeps carrying the normal anon apikey/JWT;
-- this custom session token rides alongside it in its own header.
-- Returns null if there's no header, no matching session, or the
-- session has expired - RLS policies built on this correctly deny by
-- default for a caller with no valid session, exactly like auth.uid()
-- does for an anonymous one. Verified empirically against the real API
-- (correct token resolves the right member, wrong/missing token
-- returns null) before being used in any RLS policy.
create or replace function public.sp_current_member_id()
returns uuid
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_token text;
  v_member_id uuid;
begin
  v_token := current_setting('request.headers', true)::json ->> 'x-session-token';
  if v_token is null or v_token = '' then
    return null;
  end if;

  select member_id into v_member_id
  from sp_member_sessions
  where token = v_token::uuid and expires_at > now();

  return v_member_id;
exception when others then
  -- Malformed/non-uuid session token -> treat as no session, never
  -- error the request.
  return null;
end;
$$;

revoke all on function public.sp_current_member_id() from public;
grant execute on function public.sp_current_member_id() to anon, authenticated;

-- verify_player_otp now issues a real session on success instead of
-- just returning true/false. Only caller is select-game.html (verified
-- before this change), so changing its return shape is safe.
drop function if exists public.verify_player_otp(text, text);
create or replace function public.verify_player_otp(p_mobile text, p_otp text)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_member sp_members%rowtype;
  v_token uuid;
begin
  select * into v_member from sp_members where mobile = p_mobile and otp = p_otp;
  if v_member.id is null then
    return jsonb_build_object('ok', false);
  end if;

  update sp_members set otp_verified = true where id = v_member.id;

  insert into sp_member_sessions (member_id) values (v_member.id)
  returning token into v_token;

  return jsonb_build_object(
    'ok', true,
    'token', v_token,
    'member', jsonb_build_object(
      'id', v_member.id, 'name', v_member.name, 'mobile', v_member.mobile,
      'email', v_member.email, 'gender', v_member.gender, 'whatsapp', v_member.whatsapp,
      'telegram_id', v_member.telegram_id, 'otp_verified', true, 'status', v_member.status,
      'created_at', v_member.created_at
    )
  );
end;
$$;
