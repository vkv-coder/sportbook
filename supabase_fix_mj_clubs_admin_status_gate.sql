-- Daily audit 2026-11-24: admin/index.html's updateMjClub() (mj_clubs
-- Approve/Pause/Delete) did a raw anon-key PATCH with no admin-password
-- gate at all, unlike every other action in this panel.
--
-- Investigated the actual live exposure: mj_clubs' RLS UPDATE policy
-- (mj_clubs_update) is scoped to id = mj_current_club_id(), which reads a
-- real x-club-session-token header -- so the super-admin panel's bare
-- fetch (no such header) always no-ops against THAT policy. But anon's
-- column grant for UPDATE still included `status`, and no app code ever
-- legitimately needs that column PATCH-able (club-admin.html's own
-- self-service PATCH only ever writes cancellation_policy/
-- cancellation_hours/code_prefix/accepting_requests, never status) --
-- so any club that holds a valid session token for ITSELF could PATCH
-- its own status directly via REST: self-approve out of pending, or
-- un-pause itself after being paused by the admin, bypassing the
-- approval workflow entirely. Same shape as the sz_zones/upi_id fix.
--
-- Fix: revoke the unused `status` column grant (zero functionality
-- loss), and give the admin panel a real password-gated RPC for
-- Approve/Pause/Delete, mirroring sp_admin_set_member_status.

revoke update (status) on public.mj_clubs from anon, authenticated;

create or replace function public.mj_site_admin_update_club_status(p_id uuid, p_status text, p_admin_password text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;
  if p_status not in ('active', 'paused', 'deleted') then raise exception 'Invalid status'; end if;
  update public.mj_clubs set status = p_status where id = p_id;
  return found;
end;
$$;
grant execute on function public.mj_site_admin_update_club_status(uuid, text, text) to anon, authenticated;
