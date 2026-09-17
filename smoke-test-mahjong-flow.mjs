// Smoke test for the Green Mahjong Circle score-confirmation flow.
//
// Exercises the exact sequence a real game night uses, through the exact
// same public REST endpoints + anon key the app itself uses (mahjong/scores.html)
// - not a privileged DB connection - so it actually exercises live RLS
// policies, the same way a customer's phone does. This is what would have
// caught the 2026-09-17 "new row violates row-level security policy for
// table mj_score_confirmations" bug before a real customer hit it.
//
// Uses 4 dedicated, isolated __SmokeTest Player N__ accounts and one
// __SMOKE_TEST_CLUB__ (see smoke-test-infra.sql) - never touches real
// player/club data. Cleans up everything it creates on both success and
// failure. On any failure, posts an alert to the same Telegram relay the
// app itself uses for admin notifications.
//
// Run: node smoke-test-mahjong-flow.mjs
// Exit code 0 = pass, 1 = fail (alert already sent).

const SB_URL = 'https://jqqnnkzozjskziaizajg.supabase.co';
const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImpxcW5ua3pvempza3ppYWl6YWpnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5Mjk1ODAsImV4cCI6MjA4ODUwNTU4MH0.sEYeWnm0dvuw8bLSVnQhqmgV8LB-pELjpuVIa3Us1Gg';
const TELEGRAM_RELAY = 'https://telegram-notify.unigoods2026.workers.dev/';
const CLUB_ID = 'eeeeeeee-0000-0000-0000-000000000000';
const PLAYER_IDS = [
  'eeeeeeee-0000-0000-0000-000000000001',
  'eeeeeeee-0000-0000-0000-000000000002',
  'eeeeeeee-0000-0000-0000-000000000003',
  'eeeeeeee-0000-0000-0000-000000000004',
];

let createdRoomId = null;

function fail(step, detail) {
  throw new Object.assign(new Error(`[${step}] ${detail}`), { step, detail });
}

async function rest(path, method, token, body) {
  const headers = {
    apikey: SB_KEY,
    Authorization: 'Bearer ' + SB_KEY,
    'Content-Type': 'application/json',
  };
  if (token) headers['x-session-token'] = token;
  if (method === 'POST') headers['Prefer'] = 'return=representation';
  const res = await fetch(SB_URL + '/rest/v1/' + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  return { ok: res.ok, status: res.status, data };
}

async function login(memberId) {
  const r = await rest('rpc/smoke_test_login', 'POST', null, { p_member_id: memberId });
  if (!r.ok || !r.data) fail('login', `member ${memberId}: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  return r.data; // uuid token
}

async function alertTelegram(msg) {
  try {
    await fetch(TELEGRAM_RELAY, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ msg }),
    });
  } catch (e) {
    console.error('Telegram alert itself failed to send:', e.message);
  }
}

async function cleanup() {
  if (!createdRoomId) return;
  try {
    await rest('rpc/smoke_test_cleanup', 'POST', null, { p_room_id: createdRoomId });
  } catch (e) {
    console.error('Cleanup failed (non-fatal):', e.message);
  }
}

async function main() {
  console.log('Logging in 4 smoke-test players...');
  const tokens = [];
  for (const id of PLAYER_IDS) tokens.push(await login(id));
  const [t1, t2, t3, t4] = tokens;
  const [p1, p2, p3, p4] = PLAYER_IDS;

  console.log('Creating match room (as player 1, the "creator")...');
  const roomRes = await rest('mj_score_rooms', 'POST', t1, {
    club_id: CLUB_ID,
    session_date: new Date().toISOString().slice(0, 10),
    table_number: 999,
    created_by: p1,
    player1_id: p1,
    player2_id: p2,
    player3_id: p3,
    player4_id: p4,
    status: 'pending_confirm',
    playing_category: 'beginner',
  });
  if (!roomRes.ok || !roomRes.data || !roomRes.data[0]) {
    fail('create-room', `HTTP ${roomRes.status} ${JSON.stringify(roomRes.data)}`);
  }
  createdRoomId = roomRes.data[0].id;
  console.log('  room id:', createdRoomId);

  console.log('Inserting score entries for all 4 players...');
  const scores = [40000, 35000, 35000, 30000];
  for (let i = 0; i < 4; i++) {
    const r = await rest('mj_score_entries', 'POST', t1, {
      room_id: createdRoomId,
      player_id: PLAYER_IDS[i],
      starting_points: 35000,
      final_points: scores[i],
      playing_category: 'beginner',
    });
    if (!r.ok) fail('insert-entries', `player ${i + 1}: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  }

  console.log('Seeding pending confirmations for the 3 non-creator players (this is exactly what broke on 2026-09-17)...');
  for (const pid of [p2, p3, p4]) {
    const r = await rest('mj_score_confirmations', 'POST', t1, {
      room_id: createdRoomId,
      player_id: pid,
      status: 'pending',
    });
    if (!r.ok) fail('seed-confirmations', `player ${pid}: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  }

  console.log('Confirming as players 2, 3, 4 (each using their own session)...');
  for (let i = 1; i < 4; i++) {
    const existing = await rest(
      `mj_score_confirmations?room_id=eq.${createdRoomId}&player_id=eq.${PLAYER_IDS[i]}&select=id`,
      'GET',
      tokens[i]
    );
    if (!existing.ok || !existing.data || !existing.data[0]) {
      fail('confirm-lookup', `player ${i + 1}: HTTP ${existing.status} ${JSON.stringify(existing.data)}`);
    }
    const patchRes = await fetch(
      `${SB_URL}/rest/v1/mj_score_confirmations?id=eq.${existing.data[0].id}`,
      {
        method: 'PATCH',
        headers: {
          apikey: SB_KEY,
          Authorization: 'Bearer ' + SB_KEY,
          'Content-Type': 'application/json',
          'x-session-token': tokens[i],
        },
        body: JSON.stringify({ status: 'confirmed', confirmed_at: new Date().toISOString() }),
      }
    );
    if (!patchRes.ok) fail('confirm-patch', `player ${i + 1}: HTTP ${patchRes.status}`);
  }

  console.log('Verifying final state...');
  const finalRes = await rest(
    `mj_score_confirmations?room_id=eq.${createdRoomId}&select=player_id,status`,
    'GET',
    t1
  );
  if (!finalRes.ok) fail('verify', `HTTP ${finalRes.status}`);
  const confirmedCount = finalRes.data.filter((r) => r.status === 'confirmed').length;
  if (confirmedCount !== 3) fail('verify', `expected 3 confirmed rows, got ${confirmedCount}`);

  console.log('PASS: full create-match -> seed-confirmations -> confirm-as-each-player flow works end to end.');
}

main()
  .then(async () => {
    await cleanup();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error('SMOKE TEST FAILED:', err.message);
    await alertTelegram(
      `🚨 <b>Sportbook smoke test FAILED</b>\n\nStep: ${err.step || 'unknown'}\nDetail: ${err.detail || err.message}\n\nThe real mahjong score-confirmation flow is likely broken for real customers right now.`
    );
    await cleanup();
    process.exit(1);
  });
