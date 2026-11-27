-- Documentation-parity commit (2026-11-27): mj_site_admin_log_rank_batch and
-- mj_site_admin_undo_rank_batch (admin/index.html's leaderboard batch
-- log/undo panel) were flagged by the daily audit as "unverified from
-- source" -- the frontend correctly sends p_admin_password on both calls,
-- but neither function's defining migration was ever committed to this
-- repo, so a static read of the repo alone couldn't confirm the
-- server-side check was real.
--
-- Checked live via `supabase db query --linked`: both functions already
-- call sz_admin_check_password(p_admin_password) and raise 'Unauthorized'
-- on failure, before any mutation -- same gating convention as every other
-- RPC in this panel. This file is a no-op (CREATE OR REPLACE against the
-- exact already-live definition) committed purely so the repo matches
-- what's actually running in production.

create or replace function public.mj_site_admin_log_rank_batch(p_club_id uuid, p_session_date date, p_codes text[], p_ranks integer[], p_category text, p_admin_password text)
returns table(room_ids uuid[], entries_logged integer)
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_rank_points int[] := array[100,75,50,25];
  v_n int;
  v_i int;
  v_code text;
  v_pid uuid;
  v_player_ids uuid[] := array[]::uuid[];
  v_missing text[] := array[]::text[];
  v_room_id uuid;
  v_room_ids uuid[] := array[]::uuid[];
  v_starting_points int;
begin
  if not sz_admin_check_password(p_admin_password) then
    raise exception 'Unauthorized';
  end if;

  if not exists (select 1 from public.mj_clubs where id = p_club_id and status = 'active') then
    raise exception 'Club not found or not active';
  end if;

  if p_category not in ('traditional','taiwanese') then
    raise exception 'Invalid category: % (must be traditional or taiwanese)', p_category;
  end if;

  v_n := coalesce(array_length(p_codes, 1), 0);
  if v_n = 0 then
    raise exception 'No entries provided';
  end if;
  if coalesce(array_length(p_ranks, 1), -1) <> v_n then
    raise exception 'codes and ranks must be the same length';
  end if;
  if v_n % 4 <> 0 then
    raise exception 'Total entries (%) must be a multiple of 4', v_n;
  end if;

  for v_i in 1..v_n loop
    if p_ranks[v_i] not in (1,2,3,4) then
      raise exception 'Invalid rank % for code % (must be 1-4)', p_ranks[v_i], p_codes[v_i];
    end if;
  end loop;

  -- Resolve every code to a real approved member of this club before
  -- writing anything - all-or-nothing, no partial batch ever gets saved.
  for v_i in 1..v_n loop
    v_code := upper(btrim(p_codes[v_i]));
    select mm.player_id into v_pid
      from public.mj_members mm
      where mm.club_id = p_club_id
        and mm.status = 'approved'
        and upper(mm.member_code) = v_code;
    if v_pid is null then
      v_missing := array_append(v_missing, p_codes[v_i]);
    end if;
    v_player_ids := array_append(v_player_ids, v_pid);
  end loop;

  if array_length(v_missing, 1) > 0 then
    raise exception 'Unknown member code(s) in this club: %', array_to_string(v_missing, ', ');
  end if;

  v_starting_points := case when p_category = 'taiwanese' then 0 else 35000 end;

  v_i := 1;
  while v_i <= v_n loop
    insert into public.mj_score_rooms
      (club_id, session_date, created_by, player1_id, player2_id, player3_id, player4_id, status, playing_category)
    values
      (p_club_id, p_session_date, v_player_ids[v_i],
       v_player_ids[v_i], v_player_ids[v_i+1], v_player_ids[v_i+2], v_player_ids[v_i+3],
       'confirmed', p_category)
    returning id into v_room_id;

    v_room_ids := array_append(v_room_ids, v_room_id);

    insert into public.mj_score_entries (room_id, player_id, starting_points, final_points, rank, rank_points, playing_category)
    select v_room_id, v_player_ids[v_i + k], v_starting_points, null, p_ranks[v_i + k], v_rank_points[p_ranks[v_i + k]], p_category
    from generate_series(0, 3) as k;

    v_i := v_i + 4;
  end loop;

  return query select v_room_ids, v_n;
end;
$$;
grant execute on function public.mj_site_admin_log_rank_batch(uuid, date, text[], integer[], text, text) to anon, authenticated;

create or replace function public.mj_site_admin_undo_rank_batch(p_room_ids uuid[], p_admin_password text)
returns integer
language plpgsql
security definer
set search_path to 'public'
as $$
declare v_count int;
begin
  if not sz_admin_check_password(p_admin_password) then
    raise exception 'Unauthorized';
  end if;

  delete from public.mj_score_entries where room_id = any(p_room_ids);
  delete from public.mj_score_rooms where id = any(p_room_ids);
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;
grant execute on function public.mj_site_admin_undo_rank_batch(uuid[], text) to anon, authenticated;
