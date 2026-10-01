-- ============================================================================
-- sportbook — document removal of dormant anon grants
-- ============================================================================
-- Already applied directly against the live database. Committed here purely
-- as a record of what changed — safe to re-run, no-op if already revoked.
--
-- CONTEXT
--   A monthly Supabase RLS/RPC audit (2026-10) swept both Supabase projects
--   for tables where the `anon` role held a raw table GRANT (SELECT/INSERT/
--   UPDATE/DELETE) with no RLS policy actually covering that privilege for
--   anon. In Postgres, that combination is inert the moment it happens —
--   with RLS enabled and no matching policy, the role sees/affects zero
--   rows regardless of the grant. But it's a landmine: if a permissive
--   policy for anon/public is ever added later without someone checking
--   existing grants, the table becomes fully exposed with no further step
--   needed. Every instance below was confirmed dormant (live curl tests
--   with the anon key, before and after) before revoking. mj_club_sessions
--   and sp_member_sessions are the highest-stakes of this batch -- the
--   latter held 278 real live session-token rows.
--
--   Separate from this dormant-grant cleanup, the same audit also found
--   and fixed five mj_admin_* RPCs that had zero auth checks at all
--   (mj_admin_approve_member/reject_member/set_category/
--   set_initial_points/set_slot_balance), plus two unauthenticated
--   member-lookup RPCs (mj_members_by_club/by_id) and a self-adjust RPC
--   that never verified the caller owned the row it was adjusting
--   (mj_self_adjust_slot_balance). Those were patched directly in the
--   database with mj_current_club_id()/sp_current_member_id() guards,
--   matching this app's existing session-token architecture -- not
--   re-documented here since they're RPC-body changes, not grants.
-- ============================================================================

REVOKE DELETE ON public.mj_availability_posts FROM anon;
REVOKE DELETE, INSERT, SELECT, UPDATE ON public.mj_bot_state FROM anon;
REVOKE DELETE, INSERT, SELECT, UPDATE ON public.mj_club_sessions FROM anon;
REVOKE DELETE ON public.mj_clubs FROM anon;
REVOKE DELETE, SELECT ON public.mj_members FROM anon;
REVOKE DELETE, INSERT, SELECT, UPDATE ON public.mj_password_resets FROM anon;
REVOKE DELETE ON public.mj_score_confirmations FROM anon;
REVOKE DELETE, INSERT, SELECT, UPDATE ON public.sp_member_sessions FROM anon;
REVOKE DELETE, SELECT ON public.sz_bookings FROM anon;
REVOKE DELETE, INSERT, UPDATE ON public.sz_courts FROM anon;
REVOKE DELETE, INSERT, UPDATE ON public.sz_slots FROM anon;
REVOKE DELETE, INSERT, UPDATE ON public.sz_zones FROM anon;
