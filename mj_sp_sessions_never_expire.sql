-- Per explicit request 2026-10-19: club-admin and player logins should not
-- need re-login every 30 days (this silently broke both Green Mahjong
-- Circle's admin dashboard and a player's score confirmation, with no
-- visible error, since nothing checked session freshness before the
-- 2026-10-19 fix). Changing the default to 100 years rather than removing
-- expiry entirely keeps the existing expires_at > now() check in
-- mj_current_club_id()/sp_current_member_id() working unchanged - only
-- affects sessions created from here on, does not revive already-expired
-- rows (those still need one fresh login).

alter table public.mj_club_sessions
  alter column expires_at set default (now() + interval '100 years');

alter table public.sp_member_sessions
  alter column expires_at set default (now() + interval '100 years');
