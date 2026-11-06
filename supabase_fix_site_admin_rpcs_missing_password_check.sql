-- Daily audit 2026-11-06: sp_admin_set_member_status and
-- mj_site_admin_approve_green_mahjong were the only two admin/index.html
-- RPCs that never got the p_admin_password gate added by
-- supabase-add-real-password-check.sql — every other action in this panel
-- (sz_admin_*, mj_site_admin_log_rank_batch, mj_site_admin_undo_rank_batch)
-- already requires it. Anyone with the public anon key could call either
-- function directly (browser console/curl) and bypass the admin PIN
-- screen entirely — approve/pause any SportBook member, or fast-track any
-- pending Green Mahjong Circle request straight to approved+500pts.
--
-- Same fix shape as supabase-add-real-password-check.sql: add
-- p_admin_password text, verify via the existing sz_admin_check_password()
-- (already live, backs every other admin action in this same panel), drop
-- the old unguarded signature so it can't still be called the old way.

drop function if exists public.sp_admin_set_member_status(uuid, text);
create or replace function public.sp_admin_set_member_status(p_id uuid, p_status text, p_admin_password text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;
  if p_status not in ('active', 'paused') then raise exception 'Invalid status'; end if;
  update public.sp_members set status = p_status where id = p_id;
  return found;
end;
$$;
grant execute on function public.sp_admin_set_member_status(uuid, text, text) to anon, authenticated;

drop function if exists public.mj_site_admin_approve_green_mahjong(uuid);
create or replace function public.mj_site_admin_approve_green_mahjong(p_player_id uuid, p_admin_password text)
returns text
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_club_id uuid := '87c20ae0-ff75-4042-8b01-7475be316479';
  v_id uuid;
  v_prefix text;
  v_next_num int;
  v_code text;
  v_attempts int := 0;
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;

  select id into v_id from public.mj_members
    where club_id = v_club_id and player_id = p_player_id and status = 'pending';
  if v_id is null then
    raise exception 'No pending Green Mahjong Circle request found for this player';
  end if;

  select coalesce(code_prefix, 'GM') into v_prefix from public.mj_clubs where id = v_club_id;

  loop
    select coalesce(max(nullif(regexp_replace(member_code, '^' || v_prefix, ''), ''))::int, 0) + 1
      into v_next_num
      from public.mj_members
      where club_id = v_club_id and member_code is not null;
    v_code := v_prefix || lpad(v_next_num::text, 3, '0');
    begin
      update public.mj_members
        set status = 'approved', member_code = v_code, initial_points = 500
        where id = v_id;
      exit;
    exception when unique_violation then
      v_attempts := v_attempts + 1;
      if v_attempts >= 5 then raise; end if;
    end;
  end loop;

  return v_code;
end;
$$;
grant execute on function public.mj_site_admin_approve_green_mahjong(uuid, text) to anon, authenticated;
