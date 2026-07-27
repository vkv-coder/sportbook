-- Server-side auth for mj_clubs. Passwords are bcrypt-hashed (pgcrypto) and
-- never compared or written from the client in plaintext; all three flows
-- (login, register, reset) go through SECURITY DEFINER RPCs so the anon key
-- never needs write access to admin_password.

create extension if not exists pgcrypto;

-- ---------- login ----------
-- Explicit column list (not `select *`) so admin_password - even hashed -
-- never round-trips back to the client.
create or replace function mj_verify_login(p_email text, p_password text)
returns table(
  id uuid, club_name text, owner_name text, email text, mobile text,
  city text, address text, total_tables int, gender_condition text,
  status text, upi_id text, whatsapp_no text, created_at timestamp,
  cancellation_policy text, cancellation_hours int, banner_url text,
  code_prefix text, telegram_admin_id text
)
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  return query
    select c.id, c.club_name, c.owner_name, c.email, c.mobile, c.city, c.address,
           c.total_tables, c.gender_condition, c.status, c.upi_id, c.whatsapp_no,
           c.created_at, c.cancellation_policy, c.cancellation_hours, c.banner_url,
           c.code_prefix, c.telegram_admin_id
    from mj_clubs c
    where c.email = p_email
      and c.admin_password = crypt(p_password, c.admin_password);
end;
$$;

revoke all on function mj_verify_login(text, text) from public;
grant execute on function mj_verify_login(text, text) to anon, authenticated;

-- ---------- register ----------
create or replace function mj_register_club(
  p_club_name text, p_city text, p_address text, p_total_tables int,
  p_gender_condition text, p_owner_name text, p_email text,
  p_whatsapp_no text, p_telegram_admin_id text, p_password text
)
returns uuid
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  new_id uuid;
begin
  if exists (select 1 from mj_clubs where email = p_email) then
    raise exception 'EMAIL_TAKEN';
  end if;

  insert into mj_clubs (
    club_name, city, address, total_tables, gender_condition,
    owner_name, email, whatsapp_no, telegram_admin_id, admin_password, status
  ) values (
    p_club_name, p_city, p_address, p_total_tables, p_gender_condition,
    p_owner_name, p_email, p_whatsapp_no, p_telegram_admin_id,
    crypt(p_password, gen_salt('bf')), 'pending'
  ) returning id into new_id;

  return new_id;
end;
$$;

revoke all on function mj_register_club(text,text,text,int,text,text,text,text,text,text) from public;
grant execute on function mj_register_club(text,text,text,int,text,text,text,text,text,text) to anon, authenticated;

-- ---------- password reset ----------
create or replace function mj_reset_password(p_token text, p_new_password text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  reset_row mj_password_resets;
begin
  select * into reset_row from mj_password_resets
    where token = p_token and used = false and expires_at > now();

  if not found then
    return false;
  end if;

  update mj_clubs set admin_password = crypt(p_new_password, gen_salt('bf'))
    where id = reset_row.club_id;

  update mj_password_resets set used = true where id = reset_row.id;

  return true;
end;
$$;

revoke all on function mj_reset_password(text, text) from public;
grant execute on function mj_reset_password(text, text) to anon, authenticated;

-- ---------- close the direct account-takeover hole ----------
-- Previously anon could PATCH admin_password directly on any club row via
-- the open REST API/RLS (qual:true), bypassing the reset-token flow
-- entirely. Only the RPCs above (SECURITY DEFINER) may change it now.
--
-- A column-level REVOKE alone doesn't work here: anon already has a
-- table-level UPDATE grant (from the original wide-open setup), and a
-- broader table-level grant overrides a narrower column-level revoke. So
-- the table-level grant has to be revoked first, then re-granted only for
-- the columns that should stay writable directly.
revoke update on mj_clubs from anon, authenticated;
grant update (
  club_name, owner_name, email, mobile, city, address, total_tables,
  gender_condition, status, upi_id, whatsapp_no, cancellation_policy,
  cancellation_hours, banner_url, code_prefix, telegram_admin_id
) on mj_clubs to anon, authenticated;
