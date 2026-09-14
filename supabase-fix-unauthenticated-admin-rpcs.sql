-- Sportbook (sz_) — close unauthenticated admin RPC access.
--
-- Found during a portfolio-wide check: sz_admin_add_owner,
-- sz_admin_approve_owner, sz_admin_delete_owner, and
-- sz_admin_revoke_owner are all SECURITY DEFINER but perform NO
-- authorization check inside their own body at all - unlike this same
-- developer's rm_admin_* functions elsewhere, which call
-- rm_admin_check_password() first. All four had EXECUTE granted to
-- PUBLIC/anon/authenticated.
--
-- admin/index.html's "PIN" login screen (checkPin against a separate
-- Cloudflare Worker) has NO connection to these RPC calls whatsoever -
-- confirmed by reading the code: the PIN check and the sz_admin_*
-- calls are two entirely independent fetch calls. The PIN screen is a
-- UI gate only; anyone who calls these RPCs directly (browser console,
-- curl) bypasses it completely. Combined with sz_owners' SELECT being
-- open to anon (owner IDs are fully enumerable), this meant literally
-- anyone, unauthenticated, could delete or approve/revoke ANY venue
-- owner's account on the platform.
--
-- THIS FIX BREAKS THE ADMIN PANEL'S approve/revoke/delete/add-owner
-- BUTTONS until a real server-side check is added - a broken admin
-- button is a far better failure mode than open account deletion, so
-- this is applied immediately rather than left exposed while a proper
-- fix is designed. Follow-up needed: either (a) get the actual PIN/
-- secret the Worker checks and add a matching password check inside
-- each function body (mirroring rm_admin_check_password), or (b) route
-- these four actions through that same Worker using service_role
-- instead of calling them as RPCs from the client.

revoke execute on function public.sz_admin_add_owner(text, text, text, text, text, text) from public, anon, authenticated;
revoke execute on function public.sz_admin_approve_owner(uuid) from public, anon, authenticated;
revoke execute on function public.sz_admin_delete_owner(uuid) from public, anon, authenticated;
revoke execute on function public.sz_admin_revoke_owner(uuid) from public, anon, authenticated;
