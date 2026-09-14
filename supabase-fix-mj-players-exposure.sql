-- Mahjong (mj_) — close the most severe exposure found: mj_players had
-- DELETE/INSERT/UPDATE granted to anon/authenticated (no SELECT), which
-- meant anyone could directly overwrite ANY player's otp/otp_verified
-- columns with no authentication at all - a real account-takeover path,
-- not just a data-integrity issue (an attacker only needs a player's id,
-- obtainable from other openly-readable tables like mj_bookings/
-- mj_score_entries that reference player_id).
--
-- Confirmed safe: mj_players has ZERO references anywhere in the live
-- web app's code (sportbook/mahjong/*.html) - the app's actual player
-- identity data lives in mj_members instead. The only plausible
-- consumer is a separate Telegram bot backend (mj_bot_state exists,
-- suggesting one), which would use its own elevated key and is
-- unaffected by revoking anon/authenticated grants here.
--
-- NOT fixed here (separate, larger task - needs a design conversation,
-- not a quick patch): mj_clubs, mj_bookings, mj_score_entries, mj_slots,
-- mj_table_sessions, mj_waitlist, and several others are ALL wide open
-- (USING(true)/WITH CHECK(true), "allow_all") to anon/authenticated for
-- full read+write+delete, and unlike mj_players, these ARE actively used
-- by the live app with a "trust the client-supplied id/filter" pattern -
-- there's no real per-player or per-club scoping concept in this schema
-- at all (no auth.uid()/session-token check anywhere). Locking these
-- down requires actually redesigning how the app identifies "which
-- player/club is this request for" server-side, not just tightening a
-- policy - doing that blind risks breaking the already-registered,
-- currently-working club's real usage.

revoke insert, update, delete on public.mj_players from anon, authenticated;

-- mj_club_admins already has zero anon/authenticated grants despite RLS
-- being disabled, so it's not currently reachable via the public API -
-- but re-enabling RLS here is a good defense-in-depth step regardless
-- (protects against a future grant being added without RLS also being
-- turned back on).
alter table public.mj_club_admins enable row level security;
