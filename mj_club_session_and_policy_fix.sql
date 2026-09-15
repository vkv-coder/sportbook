-- Mahjong club-admin identity layer + policy corrections.
--
-- Root cause (same pattern as sp_ before its fix): mj_verify_login_v2
-- checked email/password server-side but returned the raw mj_clubs row;
-- the client then stored that whole object (including id) in
-- localStorage with zero server-verifiable session. Club-admin.html
-- (organiser dashboard) uses that spoofable club.id for every write to
-- mj_clubs/mj_slots/mj_venue_events/mj_table_sessions/mj_bookings/
-- mj_booking_requests/mj_group_requests.
--
-- Separately, the mj_rls_redesign.sql pass (already applied) gated
-- several of those same tables on sp_current_member_id() (the PLAYER
-- session) alone, not knowing club-admin.html writes to them too as
-- the club owner, not as a player. That is live now and has broken
-- every club-admin write path on: mj_clubs (settings save), mj_slots
-- (create/delete), mj_venue_events (create/delete), mj_bookings
-- (admin-assigns a player to a table), mj_booking_requests (approve),
-- mj_group_requests (approve/reject), and mj_table_sessions (admin
-- seats a full table from a group request). This migration adds a
-- real club-level session (mirroring sp_member_sessions) and folds a
-- "club admin OR player" check into every policy that legitimately
-- needs both actors.

-- ── 1. Club session identity ──────────────────────────────────────
create table if not exists mj_club_sessions (
  token uuid primary key default gen_random_uuid(),
  club_id uuid not null references mj_clubs(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 days')
);
alter table mj_club_sessions enable row level security;
-- No policies -> deny-all for anon/authenticated; only SECURITY
-- DEFINER functions (which bypass RLS) touch this table.

-- Resolves the current request's club identity from a custom
-- X-Club-Session-Token header, parallel to sp_current_member_id()'s
-- X-Session-Token for players. A separate header (not the player one)
-- because a browser can legitimately hold both a player session and a
-- club-admin session at once (e.g. the demo club owner is also a
-- registered player), and because Authorization is reserved by
-- PostgREST for the real Supabase Auth JWT.
create or replace function public.mj_current_club_id()
returns uuid
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_token text;
  v_club_id uuid;
begin
  v_token := current_setting('request.headers', true)::json ->> 'x-club-session-token';
  if v_token is null or v_token = '' then
    return null;
  end if;

  select club_id into v_club_id
  from mj_club_sessions
  where token = v_token::uuid and expires_at > now();

  return v_club_id;
exception when others then
  return null;
end;
$$;

revoke all on function public.mj_current_club_id() from public;
grant execute on function public.mj_current_club_id() to anon, authenticated;

-- mj_verify_login_v2 now issues a real session token instead of
-- returning the raw mj_clubs row (which included the bcrypt
-- admin_password hash and both admins' password_hash indirectly via
-- the join). Only caller is club-admin.html's adminLogin() (verified
-- before this change), so changing the return shape is safe. Return
-- type changes SETOF mj_clubs -> jsonb, so the old function must be
-- dropped first (CREATE OR REPLACE cannot change a return type).
drop function if exists public.mj_verify_login_v2(text, text);
create or replace function public.mj_verify_login_v2(p_email text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_club mj_clubs%rowtype;
  v_token uuid;
begin
  select c.* into v_club
  from mj_clubs c
  join mj_club_admins a on a.club_id = c.id
  where a.email = p_email
    and a.password_hash = extensions.crypt(p_password, a.password_hash);

  if v_club.id is null then
    select c.* into v_club
    from mj_clubs c
    where c.email = p_email
      and c.admin_password = extensions.crypt(p_password, c.admin_password);
  end if;

  if v_club.id is null then
    return jsonb_build_object('ok', false);
  end if;

  insert into mj_club_sessions (club_id) values (v_club.id)
  returning token into v_token;

  return jsonb_build_object(
    'ok', true,
    'token', v_token,
    'club', jsonb_build_object(
      'id', v_club.id, 'club_name', v_club.club_name, 'owner_name', v_club.owner_name,
      'email', v_club.email, 'mobile', v_club.mobile, 'city', v_club.city, 'address', v_club.address,
      'total_tables', v_club.total_tables, 'gender_condition', v_club.gender_condition,
      'status', v_club.status, 'upi_id', v_club.upi_id, 'whatsapp_no', v_club.whatsapp_no,
      'created_at', v_club.created_at, 'cancellation_policy', v_club.cancellation_policy,
      'cancellation_hours', v_club.cancellation_hours, 'banner_url', v_club.banner_url,
      'code_prefix', v_club.code_prefix, 'telegram_admin_id', v_club.telegram_admin_id,
      'telegram_bot_username', v_club.telegram_bot_username, 'telegram_gas_url', v_club.telegram_gas_url,
      'accepting_requests', v_club.accepting_requests
    )
  );
end;
$$;

-- ── 2. mj_clubs: real ownership instead of "any session will do" ──
-- Registration goes through mj_register_club (SECURITY DEFINER, bypasses
-- RLS - confirmed via register-club.html), so this INSERT policy only
-- matters for someone POSTing directly to the REST endpoint, bypassing
-- that RPC. It should behave the same way: start pending, never
-- self-approve.
drop policy if exists "mj_clubs_write" on mj_clubs;
drop policy if exists "mj_clubs_update" on mj_clubs;

create policy "mj_clubs_insert" on mj_clubs
  for insert to anon, authenticated
  with check (status = 'pending');

create policy "mj_clubs_update" on mj_clubs
  for update to anon, authenticated
  using (id = mj_current_club_id())
  with check (id = mj_current_club_id());

-- ── 3. mj_slots / mj_venue_events: club-admin-only resources ───────
-- Both are written exclusively by club-admin.html (confirmed - no
-- player-facing insert/update/delete calls exist for either). Neither
-- had a DELETE policy after the earlier redesign even though
-- club-admin.html deletes both directly - that was a second
-- regression (silently denied, not just wrongly gated).
drop policy if exists "mj_slots_write" on mj_slots;
drop policy if exists "mj_slots_update" on mj_slots;

create policy "mj_slots_insert" on mj_slots
  for insert to anon, authenticated with check (club_id = mj_current_club_id());
create policy "mj_slots_update" on mj_slots
  for update to anon, authenticated
  using (club_id = mj_current_club_id()) with check (club_id = mj_current_club_id());
create policy "mj_slots_delete" on mj_slots
  for delete to anon, authenticated using (club_id = mj_current_club_id());

drop policy if exists "mj_venue_events_write" on mj_venue_events;
drop policy if exists "mj_venue_events_update" on mj_venue_events;

create policy "mj_venue_events_insert" on mj_venue_events
  for insert to anon, authenticated with check (club_id = mj_current_club_id());
create policy "mj_venue_events_update" on mj_venue_events
  for update to anon, authenticated
  using (club_id = mj_current_club_id()) with check (club_id = mj_current_club_id());
create policy "mj_venue_events_delete" on mj_venue_events
  for delete to anon, authenticated using (club_id = mj_current_club_id());

-- ── 4. Tables written by BOTH a player and their club's admin ──────
-- mj_bookings: a player books themselves, OR the club admin assigns a
-- player to a table directly (group-request approval flow).
drop policy if exists "mj_bookings_insert" on mj_bookings;
drop policy if exists "mj_bookings_update" on mj_bookings;
drop policy if exists "mj_bookings_delete" on mj_bookings;

create policy "mj_bookings_insert" on mj_bookings
  for insert to anon, authenticated
  with check (player_id = sp_current_member_id() or club_id = mj_current_club_id());
create policy "mj_bookings_update" on mj_bookings
  for update to anon, authenticated
  using (player_id = sp_current_member_id() or club_id = mj_current_club_id())
  with check (player_id = sp_current_member_id() or club_id = mj_current_club_id());
create policy "mj_bookings_delete" on mj_bookings
  for delete to anon, authenticated
  using (player_id = sp_current_member_id() or club_id = mj_current_club_id());

-- mj_booking_requests: a player requests, the club admin confirms/
-- rejects (UPDATE only - club-admin.html never inserts these).
drop policy if exists "mj_booking_requests_update" on mj_booking_requests;
create policy "mj_booking_requests_update" on mj_booking_requests
  for update to anon, authenticated
  using (player_id = sp_current_member_id() or club_id = mj_current_club_id())
  with check (player_id = sp_current_member_id() or club_id = mj_current_club_id());

-- mj_group_requests: a player requests, the club admin approves/
-- rejects (UPDATE only - same shape as booking_requests).
drop policy if exists "mj_group_requests_update" on mj_group_requests;
create policy "mj_group_requests_update" on mj_group_requests
  for update to anon, authenticated
  using (requested_by = sp_current_member_id() or club_id = mj_current_club_id())
  with check (requested_by = sp_current_member_id() or club_id = mj_current_club_id());

-- mj_table_sessions: up to 4 seated players, OR the club admin seating
-- them as a block (group-request approval - confirmed at
-- club-admin.html's approveGroupRequest, which inserts the full table
-- directly rather than each player inserting their own seat).
drop policy if exists "mj_table_sessions_insert" on mj_table_sessions;
drop policy if exists "mj_table_sessions_update" on mj_table_sessions;
drop policy if exists "mj_table_sessions_delete" on mj_table_sessions;

create policy "mj_table_sessions_insert" on mj_table_sessions
  for insert to anon, authenticated
  with check (
    sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id)
    or club_id = mj_current_club_id()
  );
create policy "mj_table_sessions_update" on mj_table_sessions
  for update to anon, authenticated
  using (
    sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id)
    or club_id = mj_current_club_id()
  )
  with check (
    sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id)
    or club_id = mj_current_club_id()
  );
create policy "mj_table_sessions_delete" on mj_table_sessions
  for delete to anon, authenticated
  using (
    sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id)
    or club_id = mj_current_club_id()
  );

-- ── 5. mj_score_rooms: purely player-owned (club-admin.html only
-- ever SELECTs this table - confirmed, no admin writes exist). The
-- earlier redesign left this on the generic "any session" placeholder;
-- give it the same real per-row ownership as mj_score_confirmations.
drop policy if exists "mj_score_rooms_write" on mj_score_rooms;
drop policy if exists "mj_score_rooms_update" on mj_score_rooms;

create policy "mj_score_rooms_insert" on mj_score_rooms
  for insert to anon, authenticated with check (created_by = sp_current_member_id());
create policy "mj_score_rooms_update" on mj_score_rooms
  for update to anon, authenticated
  using (sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id))
  with check (sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id));
