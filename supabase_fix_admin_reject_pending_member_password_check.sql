-- Daily audit 2026-11-07: admin_reject_pending_member was missed by the
-- 2026-11-06 pass that added p_admin_password to sp_admin_set_member_status
-- and mj_site_admin_approve_green_mahjong - same class of gap, same fix.
-- Anyone with the anon key could reject (hard-delete) any pending signup
-- with no admin credential at all.

drop function if exists public.admin_reject_pending_member(uuid);
create or replace function public.admin_reject_pending_member(p_id uuid, p_admin_password text)
returns void
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;
  delete from sp_members where id = p_id and status = 'pending';
end;
$$;
grant execute on function public.admin_reject_pending_member(uuid, text) to anon, authenticated;
