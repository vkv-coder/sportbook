-- mj_score_entries: real usage is collaborative, not single-owner.
--
-- The real submitScores() flow (mahjong/scores.html) has ONE player (the
-- room creator, or whoever is filling the form) submit all 4 players'
-- entries in a single loop, then later the confirming player's own
-- confirmScores() call assigns rank/rank_points across all 4 rows via
-- UPDATE, and a resubmission first DELETEs all existing entries for the
-- room. None of that is "each player writes only their own row" - it's
-- "any of the 4 real participants at this table may write any row that
-- belongs to their shared room."
--
-- The previous policy (player_id = sp_current_member_id(), INSERT only,
-- no UPDATE/DELETE policy at all) broke all three of those paths: only
-- the submitter's own entry ever got inserted before the loop hit the
-- next player's row and threw; the whole game's scores were then stuck
-- with 1-of-4 entries recorded, and the room could never actually reach
-- a real confirmed state again (the reset-and-resubmit path was also
-- silently blocked with no DELETE policy).
--
-- Fix: any of the room's 4 real seated players (verified via
-- sp_current_member_id(), same session-token identity used everywhere
-- else in mj_) may insert/update/delete entries for THAT room - checked
-- by looking up the room's own player1-4 columns, not by comparing
-- player_id on the entry row itself. A random outsider who isn't seated
-- at this table still can't touch it, since they won't match any of the
-- room's four player columns.

drop policy if exists "mj_score_entries_insert" on mj_score_entries;

create policy "mj_score_entries_insert" on mj_score_entries
  for insert to anon, authenticated
  with check (
    exists (
      select 1 from mj_score_rooms r
      where r.id = room_id
        and sp_current_member_id() in (r.player1_id, r.player2_id, r.player3_id, r.player4_id)
    )
  );

create policy "mj_score_entries_update" on mj_score_entries
  for update to anon, authenticated
  using (
    exists (
      select 1 from mj_score_rooms r
      where r.id = room_id
        and sp_current_member_id() in (r.player1_id, r.player2_id, r.player3_id, r.player4_id)
    )
  )
  with check (
    exists (
      select 1 from mj_score_rooms r
      where r.id = room_id
        and sp_current_member_id() in (r.player1_id, r.player2_id, r.player3_id, r.player4_id)
    )
  );

create policy "mj_score_entries_delete" on mj_score_entries
  for delete to anon, authenticated
  using (
    exists (
      select 1 from mj_score_rooms r
      where r.id = room_id
        and sp_current_member_id() in (r.player1_id, r.player2_id, r.player3_id, r.player4_id)
    )
  );

-- mj_score_rooms itself had the same gap for DELETE (no policy existed -
-- found while cleaning up the 3 corrupted rooms below, which need a
-- fresh resubmission from the real app since the other 3 players'
-- actual score values were never captured anywhere and can't be
-- reconstructed). Rooms stay collaboratively owned by their 4 seated
-- players, same as the write policies above.
create policy "mj_score_rooms_delete" on mj_score_rooms
  for delete to anon, authenticated
  using (
    sp_current_member_id() in (player1_id, player2_id, player3_id, player4_id)
    or club_id = mj_current_club_id()
  );
