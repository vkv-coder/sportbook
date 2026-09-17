-- BUG: mj_score_confirmations_insert only allowed player_id = sp_current_member_id(),
-- but scores.html's logNewMatch() and submitScores() both need the acting
-- player to pre-create 'pending' confirmation rows for the OTHER 3 players
-- in the room (see mahjong/scores.html:320, :511) - every new match and
-- every score (re)submission hit "new row violates row-level security
-- policy for table mj_score_confirmations" as a result.
--
-- Fix: allow any of the room's 4 players to insert a 'pending' row for
-- another player, but only if the target player_id is also one of that
-- same room's 4 players, and only with status='pending' - so nobody can
-- fabricate a 'confirmed' row on someone else's behalf. Own-row inserts
-- (player_id = sp_current_member_id(), used when a player confirms and no
-- pending row exists yet - scores.html:540) are unaffected.

drop policy if exists "mj_score_confirmations_insert" on mj_score_confirmations;
create policy "mj_score_confirmations_insert" on mj_score_confirmations
for insert to anon, authenticated
with check (
  player_id = sp_current_member_id()
  or (
    status = 'pending'
    and exists (
      select 1 from mj_score_rooms r
      where r.id = mj_score_confirmations.room_id
        and sp_current_member_id() in (r.player1_id, r.player2_id, r.player3_id, r.player4_id)
        and player_id in (r.player1_id, r.player2_id, r.player3_id, r.player4_id)
    )
  )
);
