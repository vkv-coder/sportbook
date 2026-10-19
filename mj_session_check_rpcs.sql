-- Lightweight "is my saved session still valid" checks, used on page load
-- before trusting a cached localStorage session - lets the frontend detect
-- a silently-expired token and force a fresh login instead of showing a
-- blank/broken screen or (worse) a false success message on a write that
-- actually failed RLS. Added 2026-10-19 after both mj_club_sessions
-- (club-admin.html, 30-day expiry) and sp_member_sessions (scores.html /
-- mahjong/index.html, 30-day expiry) were found to expire silently with no
-- user-facing signal.

create or replace function public.mj_club_session_check()
returns uuid
language sql
stable security definer
set search_path to 'public'
as $$
  select mj_current_club_id();
$$;
grant execute on function public.mj_club_session_check() to anon, authenticated;

create or replace function public.sp_session_check()
returns uuid
language sql
stable security definer
set search_path to 'public'
as $$
  select sp_current_member_id();
$$;
grant execute on function public.sp_session_check() to anon, authenticated;
