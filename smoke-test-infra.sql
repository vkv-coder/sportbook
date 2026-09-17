-- Dedicated, isolated fixtures + RPCs for the automated mahjong-flow smoke
-- test (smoke-test-mahjong-flow.mjs). Fixed, recognizable UUIDs so this data
-- is never mistaken for a real club/player in any dashboard or export.
--
-- smoke_test_login/smoke_test_cleanup are deliberately narrow: login only
-- ever mints a session for one of the 4 hardcoded smoke-test player ids
-- (never an arbitrary id - this is NOT a general "become any player" tool),
-- and cleanup only ever deletes rows belonging to the one hardcoded
-- smoke-test club. Both are safe to call with the public anon key.

insert into mj_clubs (id, club_name, owner_name, status)
values ('eeeeeeee-0000-0000-0000-000000000000', '__SMOKE_TEST_CLUB__ (auto-created, do not delete)', 'Smoke Test', 'active')
on conflict (id) do nothing;

insert into sp_members (id, name, mobile, status)
values
  ('eeeeeeee-0000-0000-0000-000000000001', '__SmokeTest Player 1__', '9999900001', 'active'),
  ('eeeeeeee-0000-0000-0000-000000000002', '__SmokeTest Player 2__', '9999900002', 'active'),
  ('eeeeeeee-0000-0000-0000-000000000003', '__SmokeTest Player 3__', '9999900003', 'active'),
  ('eeeeeeee-0000-0000-0000-000000000004', '__SmokeTest Player 4__', '9999900004', 'active')
on conflict (id) do nothing;

create or replace function public.smoke_test_login(p_member_id uuid)
returns uuid
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_token uuid;
begin
  if p_member_id not in (
    'eeeeeeee-0000-0000-0000-000000000001',
    'eeeeeeee-0000-0000-0000-000000000002',
    'eeeeeeee-0000-0000-0000-000000000003',
    'eeeeeeee-0000-0000-0000-000000000004'
  ) then
    raise exception 'smoke_test_login: not a smoke-test member id';
  end if;

  v_token := gen_random_uuid();
  insert into sp_member_sessions (token, member_id, expires_at)
  values (v_token, p_member_id, now() + interval '15 minutes');

  return v_token;
end;
$function$;

create or replace function public.smoke_test_cleanup(p_room_id uuid)
returns void
language plpgsql
security definer
set search_path to 'public'
as $function$
begin
  if not exists (
    select 1 from mj_score_rooms
    where id = p_room_id and club_id = 'eeeeeeee-0000-0000-0000-000000000000'
  ) then
    raise exception 'smoke_test_cleanup: room does not belong to the smoke-test club, refusing to delete';
  end if;

  delete from mj_score_confirmations where room_id = p_room_id;
  delete from mj_score_entries where room_id = p_room_id;
  delete from mj_score_rooms where id = p_room_id;
end;
$function$;
