-- ============================================================================
-- sportbook / mahjong — fix leaderboard regression from the 2026-10 audit
-- ============================================================================
-- Already applied directly against the live database. Committed here purely
-- as a record of what changed.
--
-- CONTEXT
--   The 2026-10 monthly audit closed a real vulnerability: mj_members_by_club
--   and mj_members_by_id could previously be called by anyone unauthenticated
--   to harvest every club member's data, including telegram_id. The fix
--   restricted both to require a club-admin session (mj_current_club_id()).
--
--   That broke two legitimate PLAYER-facing (not admin) callers that share
--   the same RPCs:
--     - mahjong/leaderboard.html called mj_members_by_club to add each
--       approved member's starting points (initial_points +
--       initial_points_taiwanese) to the public leaderboard. With the
--       admin-only guard, a regular player session gets zero rows back, so
--       any member with no confirmed games vanished from the leaderboard
--       entirely, and members who had played lost their starting bonus from
--       the displayed total.
--     - mahjong/index.html polls mj_members_by_id to detect when a player's
--       Telegram connection completes. Same guard, same breakage - the poll
--       silently never succeeds for a real player.
--
--   No data was lost or changed in mj_members itself - this was a read-path
--   authorization regression only, confirmed via direct DB inspection
--   (95/95 members present, all initial_points=500 for Green Mahjong Circle)
--   before this fix.
--
-- FIX
--   1. New function mj_leaderboard_points_by_club: same non-sensitive
--      columns the leaderboard actually needs (player_id, member_code,
--      initial_points, initial_points_taiwanese - no telegram_id), gated on
--      "any valid player session" (sp_current_member_id() is not null)
--      instead of club-admin. mj_members_by_club itself is untouched -
--      club-admin.html's existing admin-only use of it stays exactly as the
--      audit intended.
--   2. mj_members_by_id: added back an OR-branch so the row's OWNING player
--      (sp_current_member_id() = mm.player_id) can read their own
--      membership row, alongside the existing club-admin path. A player can
--      still only ever see their own row, not any other member's.
--
--   Verified empirically (not just by statement success) via simulated
--   PostgREST session headers against the live DB: a real player session
--   now gets all 95 members back from the new leaderboard RPC; a caller
--   with no session still gets zero (original vulnerability stays closed);
--   a player can read their own mj_members_by_id row but not another
--   player's.
--
-- CORRECTION (same day, follow-up): the first version of this fix gated
-- mj_leaderboard_points_by_club on "any valid player session"
-- (sp_current_member_id() is not null). That was still too strict --
-- leaderboard.html has an explicit anonymous "Public View" mode (shown
-- when no sp_member is in localStorage at all, see its DOMContentLoaded
-- handler) and its own sb() helper never sent X-Session-Token in the
-- first place, so a real logged-in player got zero rows too, not just
-- anonymous visitors. Confirmed this page was never session-gated before
-- today's incident. Dropped the session check entirely -- the function
-- still only exposes non-sensitive columns (no telegram_id), so this is
-- safe and matches the exact original public behavior. Verified via a
-- real HTTP call to the live REST endpoint with the page's own anon key,
-- no session headers at all: 95/95 rows returned.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.mj_leaderboard_points_by_club(p_club_id uuid)
 RETURNS TABLE(player_id uuid, member_code text, initial_points integer, initial_points_taiwanese integer)
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select mm.player_id, mm.member_code, mm.initial_points, mm.initial_points_taiwanese
  from mj_members mm
  where mm.club_id = p_club_id
    and mm.status = 'approved';
$function$;

GRANT EXECUTE ON FUNCTION public.mj_leaderboard_points_by_club(uuid) TO anon, authenticated;

CREATE OR REPLACE FUNCTION public.mj_members_by_id(p_id uuid)
 RETURNS TABLE(id uuid, telegram_id text)
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select mm.id, mm.telegram_id from mj_members mm
  where mm.id = p_id
    and (
      (mj_current_club_id() is not null and mm.club_id = mj_current_club_id())
      or (sp_current_member_id() is not null and mm.player_id = sp_current_member_id())
    );
$function$;
