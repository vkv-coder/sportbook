-- Sportbook (sz_) — add a real, working password check to the admin
-- actions that were locked down in
-- supabase-fix-unauthenticated-admin-rpcs.sql.
--
-- Mirrors this same developer's own rm_admin_secret /
-- rm_admin_check_password pattern (Reminders app) exactly, for
-- consistency. Replaces the old Cloudflare-Worker PIN check, which was
-- never actually connected to these four actions in the first place.
--
-- Run PART 1 as-is. PART 2 (setting the actual password) is a
-- separate file you run yourself with the real value filled in — never
-- pasted into chat.

-- ── PART 1 — safe to apply as-is, no secret involved ──────────────

create table if not exists sz_admin_secret (
  id boolean primary key default true,
  password_hash text,
  constraint sz_admin_secret_single_row check (id)
);

alter table sz_admin_secret enable row level security;
-- No policies at all -> fully deny-all for anon/authenticated, same as
-- every other *_admin_secret table in this portfolio. Only
-- SECURITY DEFINER functions (which bypass RLS) can read it.

create or replace function public.sz_admin_check_password(p_password text)
returns boolean
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $$
declare v_hash text;
begin
  select password_hash into v_hash from sz_admin_secret where id = true;
  return v_hash is not null and v_hash = crypt(p_password, v_hash);
end;
$$;

revoke all on function public.sz_admin_check_password(text) from public;
grant execute on function public.sz_admin_check_password(text) to anon, authenticated;

-- Re-create the four functions with a p_admin_password parameter that
-- must check out before anything happens. EXECUTE is re-granted to
-- anon/authenticated afterward - safe now, since the real gate is the
-- password check inside the function body, not the grant.

drop function if exists public.sz_admin_approve_owner(uuid);
create or replace function public.sz_admin_approve_owner(p_id uuid, p_admin_password text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;
  update public.sz_owners set is_approved = true where id = p_id;
  return found;
end; $$;

drop function if exists public.sz_admin_revoke_owner(uuid);
create or replace function public.sz_admin_revoke_owner(p_id uuid, p_admin_password text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;
  update public.sz_owners set is_approved = false where id = p_id;
  return found;
end; $$;

drop function if exists public.sz_admin_delete_owner(uuid);
create or replace function public.sz_admin_delete_owner(p_id uuid, p_admin_password text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;
  delete from public.sz_owners where id = p_id;
  return found;
end; $$;

drop function if exists public.sz_admin_add_owner(text, text, text, text, text, text);
create or replace function public.sz_admin_add_owner(p_name text, p_venue text, p_city text, p_phone text, p_email text, p_password text, p_admin_password text)
returns uuid
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $$
declare v_zone_id uuid; v_owner_id uuid;
begin
  if not sz_admin_check_password(p_admin_password) then raise exception 'Unauthorized'; end if;

  insert into public.sz_zones (name, city, address, sports, is_active)
  values (p_venue, trim(split_part(p_city, ',', array_length(string_to_array(p_city, ','), 1))), p_city, '{}', true)
  returning id into v_zone_id;

  insert into public.sz_owners (owner_name, venue_name, city, phone, email, password, zone_id, is_approved)
  values (p_name, p_venue, p_city, p_phone, p_email, crypt(p_password, gen_salt('bf')), v_zone_id, true)
  returning id into v_owner_id;

  return v_owner_id;
end; $$;

grant execute on function public.sz_admin_approve_owner(uuid, text) to anon, authenticated;
grant execute on function public.sz_admin_revoke_owner(uuid, text) to anon, authenticated;
grant execute on function public.sz_admin_delete_owner(uuid, text) to anon, authenticated;
grant execute on function public.sz_admin_add_owner(text, text, text, text, text, text, text) to anon, authenticated;
