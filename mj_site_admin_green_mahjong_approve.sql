-- admin/index.html's "Also add to Green Mahjong" checkbox (approveIntoGreenMahjong)
-- used to call mj_admin_approve_member + mj_admin_set_initial_points directly.
-- Both of those got an mj_current_club_id() guard added on 2026-10-01 to close
-- an unauthenticated-admin hole - correct for club-admin.html (which has a real
-- per-club session token), but admin/index.html is a separate site-wide admin
-- panel with no club session at all, so both calls now always fail there,
-- leaving the mj_members row stuck at status='pending' with no member_code and
-- 0 points - invisible on the leaderboard. Found 2026-10-20 after 3 real
-- registrations (Geeta Bhuva, Renu Jhalaria, Nisha Sheth) got stuck this way.
--
-- This RPC is a narrow replacement scoped ONLY to this one site-admin shortcut:
-- hardcoded to Green Mahjong Circle (not a club_id parameter - cannot touch any
-- other club), and only acts on a row that is ALREADY 'pending' for that club +
-- player (cannot create a membership, only fast-track an existing request).
-- Does both the approve + 500-point baseline in one atomic call, replacing the
-- two now-broken RPC calls.
--
-- Caveat (not new - same as every other admin/index.html action): this site
-- admin panel's own login is a client-side PIN gate with no server-verifiable
-- session, so this RPC can't require real site-admin proof either. It's scoped
-- as narrowly as the feature allows, but is not a stronger guarantee than the
-- rest of this panel's existing actions (e.g. sp_admin_set_member_status).

create or replace function public.mj_site_admin_approve_green_mahjong(p_player_id uuid)
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
grant execute on function public.mj_site_admin_approve_green_mahjong(uuid) to anon, authenticated;
