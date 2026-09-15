-- Mahjong (mj_) — real RLS using the new sp_current_member_id()
-- session-token identity (see sp_session_infra.sql, applied first and
-- verified empirically against the live API before this file).
--
-- Every table below previously had USING(true)/WITH CHECK(true) -
-- anyone, unauthenticated, could read/write/delete everything. This
-- replaces that with real ownership checks for the tables where a
-- player-identity column makes the intended rule unambiguous.
--
-- Admin corrections (score fixes etc.) go through SECURITY DEFINER
-- RPCs (mj_admin_*), which bypass RLS entirely - locking down the raw
-- table paths below does not block legitimate admin actions.

-- ── mj_bookings: single player_id owner ──────────────────────────
drop policy if exists "allow_all" on mj_bookings;

create policy "mj_bookings_select" on mj_bookings
  for select to anon, authenticated using (true); -- booking-status board, low sensitivity, unchanged from current behavior

create policy "mj_bookings_insert" on mj_bookings
  for insert to anon, authenticated with check (player_id = sp_current_member_id());

create policy "mj_bookings_update" on mj_bookings
  for update to anon, authenticated
  using (player_id = sp_current_member_id())
  with check (player_id = sp_current_member_id());

create policy "mj_bookings_delete" on mj_bookings
  for delete to anon, authenticated using (player_id = sp_current_member_id());

-- ── mj_booking_requests: single player_id owner ──────────────────
drop policy if exists "anon_all_booking_requests" on mj_booking_requests;

create policy "mj_booking_requests_select" on mj_booking_requests
  for select to anon, authenticated using (true);

create policy "mj_booking_requests_insert" on mj_booking_requests
  for insert to anon, authenticated with check (player_id = sp_current_member_id());

create policy "mj_booking_requests_update" on mj_booking_requests
  for update to anon, authenticated
  using (player_id = sp_current_member_id())
  with check (player_id = sp_current_member_id());

create policy "mj_booking_requests_delete" on mj_booking_requests
  for delete to anon, authenticated using (player_id = sp_current_member_id());

-- ── mj_waitlist: single player_id owner ──────────────────────────
drop policy if exists "allow_all" on mj_waitlist;

create policy "mj_waitlist_select" on mj_waitlist
  for select to anon, authenticated using (true);

create policy "mj_waitlist_insert" on mj_waitlist
  for insert to anon, authenticated with check (player_id = sp_current_member_id());

create policy "mj_waitlist_update" on mj_waitlist
  for update to anon, authenticated
  using (player_id = sp_current_member_id())
  with check (player_id = sp_current_member_id());

create policy "mj_waitlist_delete" on mj_waitlist
  for delete to anon, authenticated using (player_id = sp_current_member_id());

-- ── mj_group_requests: requested_by is the owner ─────────────────
drop policy if exists "allow_all" on mj_group_requests;

create policy "mj_group_requests_select" on mj_group_requests
  for select to anon, authenticated using (true);

create policy "mj_group_requests_insert" on mj_group_requests
  for insert to anon, authenticated with check (requested_by = sp_current_member_id());

create policy "mj_group_requests_update" on mj_group_requests
  for update to anon, authenticated
  using (requested_by = sp_current_member_id())
  with check (requested_by = sp_current_member_id());

create policy "mj_group_requests_delete" on mj_group_requests
  for delete to anon, authenticated using (requested_by = sp_current_member_id());

-- ── mj_table_sessions: up to 4 seated players ────────────────────
-- The creator must be genuinely one of the 4 seats being filled - the
-- other 3 are commonly friends entered by name/mobile, not necessarily
-- themselves verified sp_members, matching the group-booking pattern
-- elsewhere in this app.
drop policy if exists "allow_all" on mj_table_sessions;

create policy "mj_table_sessions_select" on mj_table_sessions
  for select to anon, authenticated using (true);

create policy "mj_table_sessions_insert" on mj_table_sessions
  for insert to anon, authenticated
  with check (sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id));

create policy "mj_table_sessions_update" on mj_table_sessions
  for update to anon, authenticated
  using (sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id))
  with check (sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id));

create policy "mj_table_sessions_delete" on mj_table_sessions
  for delete to anon, authenticated
  using (sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id));

-- ── mj_score_confirmations: the real anti-cheat fix ──────────────
-- This table exists specifically so OTHER players in a room confirm a
-- submitted score (consensus, not self-report). With everything open,
-- one malicious player could forge every other player's confirmation
-- too, defeating the whole point of this table. A player may now only
-- ever confirm AS THEMSELVES.
drop policy if exists "anon_all_score_confirmations" on mj_score_confirmations;

create policy "mj_score_confirmations_select" on mj_score_confirmations
  for select to anon, authenticated using (true);

create policy "mj_score_confirmations_insert" on mj_score_confirmations
  for insert to anon, authenticated with check (player_id = sp_current_member_id());

create policy "mj_score_confirmations_update" on mj_score_confirmations
  for update to anon, authenticated
  using (player_id = sp_current_member_id())
  with check (player_id = sp_current_member_id());
-- No delete policy - a confirmation should never be retractable by the
-- confirming player once given; only admin RPCs (which bypass RLS) can
-- remove one if genuinely needed.

-- ── mj_score_entries: a player may submit their own score ────────
drop policy if exists "anon_all_score_entries" on mj_score_entries;

create policy "mj_score_entries_select" on mj_score_entries
  for select to anon, authenticated using (true); -- leaderboard is intentionally public

create policy "mj_score_entries_insert" on mj_score_entries
  for insert to anon, authenticated with check (player_id = sp_current_member_id());
-- No update/delete policy for regular players - score correction after
-- submission goes through admin RPCs only (bypass RLS), not a raw
-- table edit.

-- ── Remaining tables: baseline safety net ────────────────────────
-- Lower-certainty ownership model (no single obvious "owner" column,
-- or genuinely intended to be broadly writable during trial) - rather
-- than guess a specific rule and risk being wrong, apply the same
-- minimum bar as everything above: block DELETE outright (nothing here
-- has a clear legitimate reason for a random anon client to delete
-- rows), and require at least a valid session to write at all (closes
-- the fully-anonymous/no-login attack surface even where per-row
-- ownership isn't modeled yet).

drop policy if exists "allow_all" on mj_clubs;
create policy "mj_clubs_select" on mj_clubs for select to anon, authenticated using (true);
create policy "mj_clubs_write" on mj_clubs for insert to anon, authenticated with check (sp_current_member_id() is not null);
create policy "mj_clubs_update" on mj_clubs for update to anon, authenticated using (sp_current_member_id() is not null) with check (sp_current_member_id() is not null);

drop policy if exists "anon_all_venue_events" on mj_venue_events;
create policy "mj_venue_events_select" on mj_venue_events for select to anon, authenticated using (true);
create policy "mj_venue_events_write" on mj_venue_events for insert to anon, authenticated with check (sp_current_member_id() is not null);
create policy "mj_venue_events_update" on mj_venue_events for update to anon, authenticated using (sp_current_member_id() is not null) with check (sp_current_member_id() is not null);

drop policy if exists "allow_all" on mj_availability_posts;
create policy "mj_availability_posts_select" on mj_availability_posts for select to anon, authenticated using (true);
create policy "mj_availability_posts_write" on mj_availability_posts for insert to anon, authenticated with check (sp_current_member_id() is not null);
create policy "mj_availability_posts_update" on mj_availability_posts for update to anon, authenticated using (sp_current_member_id() is not null) with check (sp_current_member_id() is not null);

drop policy if exists "anon_all_score_rooms" on mj_score_rooms;
create policy "mj_score_rooms_select" on mj_score_rooms for select to anon, authenticated using (true);
create policy "mj_score_rooms_write" on mj_score_rooms for insert to anon, authenticated with check (sp_current_member_id() is not null);
create policy "mj_score_rooms_update" on mj_score_rooms for update to anon, authenticated using (sp_current_member_id() is not null) with check (sp_current_member_id() is not null);

drop policy if exists "allow_all" on mj_slots;
create policy "mj_slots_select" on mj_slots for select to anon, authenticated using (true);
create policy "mj_slots_write" on mj_slots for insert to anon, authenticated with check (sp_current_member_id() is not null);
create policy "mj_slots_update" on mj_slots for update to anon, authenticated using (sp_current_member_id() is not null) with check (sp_current_member_id() is not null);

-- mj_fill_alerts: currently read-only for anon (no write policy existed before either) - leave as-is.
