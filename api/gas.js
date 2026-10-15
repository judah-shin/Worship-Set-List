// ================================================================
//  Worship Set List — api/gas.js  (Vercel API Route)
//  Code.gs → Node.js + Supabase 이식
// ================================================================

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ── Supabase 클라이언트 ──────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const MAX_SETS_PER_DAY = 5;

// ================================================================
//  ★ 보안 — 입장권(토큰) 발급·확인 (찬양팀 코드 방식)
//   역할 네 가지
//     op : 운영자 (ADMIN_PASSWORD) — 팀 만들기·코드 발급·정지·삭제만, 팀 자료는 보지 않음
//     ta : 팀 관리자 (관리자 코드) — 자기 팀의 Set List·악보·통계 관리, 팀원·부관리자 코드 관리
//     ts : 부관리자 (부관리자 코드) — 관리자가 켜고 끔. Set List 작성·삭제, 악보 추가·수정, 통계
//     tm : 팀원     (팀원 코드)   — 자기 팀의 Set List·악보 보기
//   · 입장권 모양: 역할.팀번호.코드버전.만료시각.서명
//     (부관리자는 코드버전 자리에 "팀코드버전s부관리자버전" — 부관리자를 끄거나 새로 만들면 부관리자만 무효)
//   · 코드를 재발급하면 코드버전이 올라가 옛 입장권은 자동으로 무효
//   · 팀이 정지되면 그 팀의 입장권은 모두 거절
//   · 운영자 입장권은 ADMIN_PASSWORD로 서명 → 비밀번호를 바꾸면 운영자 입장권만 무효
//   · 팀 코드는 SUPABASE_SERVICE_KEY로 암호화 → 운영자 비밀번호를 바꿔도 팀 코드는 그대로
// ================================================================
const OP_TOKEN_HOURS   = 24;          // 운영자: 하루
const TEAM_TOKEN_DAYS  = 180;         // 팀 관리자·팀원: 기기에 기억 (코드 재발급 전까지 유지)

function _opSecret() {
  return crypto.createHash('sha256')
    .update('op|' + (process.env.SUPABASE_SERVICE_KEY || '') + '|' + (process.env.ADMIN_PASSWORD || ''))
    .digest();
}
function _teamSecret() {
  return crypto.createHash('sha256')
    .update('team|' + (process.env.SUPABASE_SERVICE_KEY || ''))
    .digest();
}
function _hmac(secret, text) {
  return crypto.createHmac('sha256', secret).update(text).digest('hex');
}

// 길이가 달라도 시간 차이로 내용을 추측할 수 없게 비교
function _safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// 코드 → 저장용 암호화 값 (같은 코드는 항상 같은 값 → 조회 가능, 원래 코드로 되돌릴 수 없음)
function hashCode(code) {
  return _hmac(_teamSecret(), 'code|' + String(code));
}

// ── 12자리 코드 자동 생성 — 영문 대·소문자 + 숫자 + 특수문자, 헷갈리는 글자(0 O 1 l I) 제외 ──
const CODE_SETS = [
  'ABCDEFGHJKLMNPQRSTUVWXYZ',
  'abcdefghijkmnopqrstuvwxyz',
  '23456789',
  '!@#$%?&',
];
function generateCode(len = 12) {
  const all = CODE_SETS.join('');
  const chars = CODE_SETS.map(set => set[crypto.randomInt(set.length)]);   // 종류별로 최소 1개
  while (chars.length < len) chars.push(all[crypto.randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {                               // 섞기
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// 역할별 입장권 버전 — 부관리자는 팀 코드버전과 부관리자 버전을 함께 확인
function _verOf(role, team) {
  return role === 'ts' ? `${team.code_version}s${team.sub_version}` : String(team.code_version);
}

function issueToken(role, teamId, ver) {
  const ms = role === 'op' ? OP_TOKEN_HOURS * 3600e3 : TEAM_TOKEN_DAYS * 86400e3;
  const body = [role, teamId || 0, ver || 0, Date.now() + ms].join('.');
  const secret = role === 'op' ? _opSecret() : _teamSecret();
  return body + '.' + _hmac(secret, body);
}

// 서명·만료만 확인 (팀 상태·코드버전은 resolveSession에서 DB로 확인)
function parseToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 5) return null;
  const [role, teamId, ver, exp, sig] = parts;
  if (!['op', 'ta', 'ts', 'tm'].includes(role)) return null;
  if (!Number(exp) || Number(exp) < Date.now()) return null;
  const secret = role === 'op' ? _opSecret() : _teamSecret();
  if (!_safeEqual(sig, _hmac(secret, parts.slice(0, 4).join('.')))) return null;
  return { role, teamId: Number(teamId), ver: String(ver) };
}

// 입장권 → 실제 권한 (팀이 정지됐거나 코드가 재발급됐으면 null)
async function resolveSession(token) {
  const t = parseToken(token);
  if (!t) return null;
  if (t.role === 'op') return { role: 'op', teamId: null };
  const { data: team, error } = await supabase
    .from('teams').select('id, display_name, code_version, status, sub_code_hash, sub_version')
    .eq('id', t.teamId).maybeSingle();
  if (error || !team) return null;
  if (team.status !== 'active' || t.ver !== _verOf(t.role, team)) return null;
  if (t.role === 'ts' && !team.sub_code_hash) return null;   // 부관리자가 꺼져 있으면 거절
  return { role: t.role, teamId: team.id, teamName: team.display_name, subEnabled: !!team.sub_code_hash };
}

// 기능별 필요한 권한
//   PUBLIC : 입장 전에도 가능
//   MEMBER : 팀원 이상 (팀 관리자 포함)
//   TEAM_ADMIN : 팀 관리자만
//   OPERATOR : 운영자만
const PUBLIC     = new Set(['verifyAdminPassword', 'enterCode']);
const MEMBER     = new Set(['whoami', 'getSetListsByDate', 'getDatesWithSetList', 'fetchFileAsBase64']);
// 관리자와 부관리자 모두
const EDITOR     = new Set([
  'saveSetList', 'updateSetList', 'deleteSetList', 'searchSongs',
  'adminAddSong', 'adminUpdateSong', 'getAllScores', 'getSongStats',
]);
// 관리자만 (악보 삭제, 코드 관리)
const TEAM_ADMIN = new Set([
  'adminDeleteSong', 'reissueMemberCode', 'createSubCode', 'disableSubCode',
]);
const OPERATOR   = new Set([
  'opWhoami', 'listTeams', 'createTeam', 'setTeamStatus',
  'reissueTeamCodes', 'deleteTeam', 'claimLegacyData',
]);

// ── 비밀번호 반복 시도 제한 (같은 접속 주소에서 10분 안에 5번 틀리면 10분간 차단) ──
//   Vercel 서버는 여러 대로 나뉘어 돌기 때문에 완벽한 차단은 아니며,
//   틀릴 때마다 1.5초씩 늦게 답하는 장치와 함께 자동 추측을 크게 늦추는 역할을 한다
const FAIL_LIMIT = 5;
const FAIL_WINDOW_MS = 10 * 60 * 1000;
const _failLog = new Map();   // ip → [실패 시각, ...]

function _recentFails(ip) {
  const now = Date.now();
  const list = (_failLog.get(ip) || []).filter(t => now - t < FAIL_WINDOW_MS);
  _failLog.set(ip, list);
  return list;
}

// ================================================================
//  헬퍼 — 날짜 정규화 (YYYY-MM-DD)
// ================================================================
function normDate(val) {
  if (!val && val !== 0) return '';
  if (typeof val === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(val.trim())) return val.trim();
  const d = val instanceof Date ? val : new Date(val);
  if (isNaN(d.getTime())) return String(val);
  return d.toISOString().slice(0, 10);
}

// ================================================================
//  헬퍼 — MIME 감지 / 파일 분류
// ================================================================
function detectMime(url) {
  // ?쿼리 파라미터 제거 후 확장자 추출
  const ext = (url || '').split('?')[0].split('.').pop().toLowerCase();
  const map = {
    pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    png: 'image/png', gif: 'image/gif', webp: 'image/webp',
    bmp: 'image/bmp', tiff: 'image/tiff', tif: 'image/tiff', svg: 'image/svg+xml',
  };
  return map[ext] || 'application/octet-stream';
}

function classifyType(mime, url, originalUrl) {
  // MIME 타입 앞부분만 추출 ('; charset=UTF-8' 등 제거)
  const m = (mime || '').split(';')[0].trim().toLowerCase();

  if (m === 'application/pdf') return 'pdf';
  if (m.startsWith('image/')) return 'image';

  // MIME으로 판단 못한 경우 → 원본 파일명 확장자로 추측
  // Google Drive 변환 URL은 확장자가 없으므로 originalUrl 사용
  const checkUrl = originalUrl || url || '';
  const ext = checkUrl.split('?')[0].split('.').pop().toLowerCase();
  if (ext === 'pdf') return 'pdf';
  if (['jpg','jpeg','png','gif','webp','bmp','tiff','tif','svg'].includes(ext)) return 'image';

  return 'unknown';
}

// ================================================================
//  CORS 헤더 설정
// ================================================================
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

// ================================================================
//  1. 관리자 비밀번호 검증
// ================================================================
async function verifyAdminPassword(inputPw, ctx) {
  try {
    const ip = (ctx && ctx.ip) || 'unknown';
    if (_recentFails(ip).length >= FAIL_LIMIT) {
      return { ok: false, message: '비밀번호를 여러 번 틀렸습니다. 10분 뒤에 다시 시도해 주세요.' };
    }

    const stored = process.env.ADMIN_PASSWORD || '';
    const ok = stored !== '' && typeof inputPw === 'string' && _safeEqual(inputPw, stored);

    if (!ok) {
      _recentFails(ip).push(Date.now());
      await new Promise(r => setTimeout(r, 1500));   // 자동 추측 속도 늦추기
      return { ok: false };
    }

    _failLog.delete(ip);
    return { ok: true, role: 'op', token: issueToken('op') };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  2. Set List 저장
// ================================================================
async function saveSetList(payload, ctx) {
  try {
    const targetDate = normDate(payload.worship_date);

    // 같은 팀·같은 날짜의 기존 set_id 수 확인
    const { data: existing, error: cntErr } = await supabase
      .from('set_list')
      .select('set_id')
      .eq('team_id', ctx.teamId)
      .eq('worship_date', targetDate);

    if (cntErr) throw new Error(cntErr.message);

    const uniqueSetIds = new Set((existing || []).map(r => r.set_id));
    if (uniqueSetIds.size >= MAX_SETS_PER_DAY) {
      return {
        ok: false,
        message: `해당 날짜에는 최대 ${MAX_SETS_PER_DAY}개의 Set List만 저장할 수 있습니다. (현재 ${uniqueSetIds.size}개)`,
      };
    }

    const now = new Date().toISOString();
    // ★ Set List 번호는 서버가 만든다 — 팀이 많아져도 겹치지 않게 (날짜 + 무작위 10자리)
    const setId = 'SET_' + targetDate.replace(/-/g, '') + '_' + crypto.randomBytes(5).toString('hex').toUpperCase();
    const rows = payload.songs.map(song => ({
      team_id:      ctx.teamId,
      set_id:       setId,
      group_title:  payload.group_title,
      worship_date: targetDate,
      song_order:   song.song_order,
      song_title:   song.song_title,
      file_name:    song.file_name,
      file_url:     song.file_url,
      created_by:   payload.created_by || '',
      created_at:   now,
      is_admin:     payload.is_admin || false,
    }));

    const { error } = await supabase.from('set_list').insert(rows);
    if (error) throw new Error(error.message);

    return { ok: true, message: 'Set List 저장 완료' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  3. 날짜별 Set List 조회
// ================================================================
async function getSetListsByDate(date, ctx) {
  try {
    const targetDate = normDate(date);

    const { data: rows, error } = await supabase
      .from('set_list')
      .select('*')
      .eq('team_id', ctx.teamId)
      .eq('worship_date', targetDate)
      .order('set_id')
      .order('song_order');

    if (error) throw new Error(error.message);

    // set_id 기준으로 그룹화
    const groups = {};
    (rows || []).forEach(r => {
      if (!groups[r.set_id]) {
        groups[r.set_id] = {
          set_id:       r.set_id,
          group_title:  r.group_title,
          worship_date: r.worship_date,
          created_by:   r.created_by,
          created_at:   r.created_at,
          songs: [],
        };
      }
      groups[r.set_id].songs.push({
        song_order: r.song_order,
        song_title: r.song_title,
        file_name:  r.file_name,
        file_url:   r.file_url,
      });
    });

    const list = Object.values(groups);
    list.forEach(g => g.songs.sort((a, b) => a.song_order - b.song_order));

    return { ok: true, data: list, count: list.length, max: MAX_SETS_PER_DAY };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  4. 캘린더 dot용 — Set List 존재 날짜 목록
// ================================================================
async function getDatesWithSetList(month, ctx) {
  try {
    if (!month || !/^\d{4}-\d{2}$/.test(month)) {
      return { ok: false, message: '월 형식이 올바르지 않습니다. (YYYY-MM)' };
    }

    const { data: rows, error } = await supabase
      .from('set_list')
      .select('worship_date')
      .eq('team_id', ctx.teamId)
      .like('worship_date', `${month}%`);

    if (error) throw new Error(error.message);

    const dates = [...new Set((rows || []).map(r => r.worship_date))];
    return { ok: true, data: dates };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  5. Set List 삭제
// ================================================================
// ================================================================
//  ★ Set List 수정 — 제목과 예배 날짜 변경 (곡 구성은 그대로)
//   · 날짜를 옮길 때 그 날짜의 하루 개수 제한(MAX_SETS_PER_DAY)을 확인
//   · Set List 번호(set_id)는 기본 키라 바꾸지 않음
// ================================================================
async function updateSetList(payload, ctx) {
  try {
    const setId = String((payload && payload.set_id) || '').trim();
    const title = String((payload && payload.group_title) || '').trim();
    const date  = normDate(payload && payload.worship_date);
    if (!setId) return { ok: false, message: '수정할 Set List가 없습니다.' };
    if (!title) return { ok: false, message: 'Set List 제목을 입력하세요.' };
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return { ok: false, message: '날짜 형식이 올바르지 않습니다.' };

    const { data: cur, error: e1 } = await supabase
      .from('set_list').select('worship_date')
      .eq('team_id', ctx.teamId).eq('set_id', setId).limit(1);
    if (e1) throw new Error(e1.message);
    if (!cur || !cur.length) return { ok: false, message: '해당 Set List를 찾을 수 없습니다.' };

    if (normDate(cur[0].worship_date) !== date) {
      const { data: same, error: e2 } = await supabase
        .from('set_list').select('set_id')
        .eq('team_id', ctx.teamId).eq('worship_date', date);
      if (e2) throw new Error(e2.message);
      const ids = new Set((same || []).map(r => r.set_id));
      ids.delete(setId);
      if (ids.size >= MAX_SETS_PER_DAY) {
        return { ok: false, message: `${date}에는 이미 Set List가 ${ids.size}개 있어 옮길 수 없습니다. (최대 ${MAX_SETS_PER_DAY}개)` };
      }
    }

    const { data, error } = await supabase
      .from('set_list').update({ group_title: title, worship_date: date })
      .eq('team_id', ctx.teamId).eq('set_id', setId).select('set_id');
    if (error) throw new Error(error.message);
    return { ok: true, rows: (data || []).length, worship_date: date };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

async function deleteSetList(set_id, ctx) {
  try {
    if (!set_id || String(set_id).trim() === '') {
      return { ok: false, message: '삭제할 Set ID가 없습니다.' };
    }
    const targetId = String(set_id).trim();

    const { data, error } = await supabase
      .from('set_list')
      .delete()
      .eq('team_id', ctx.teamId)
      .eq('set_id', targetId)
      .select();

    if (error) throw new Error(error.message);
    if (!data || data.length === 0) {
      return { ok: false, message: '해당 Set List를 찾을 수 없습니다. (ID: ' + targetId + ')' };
    }

    return { ok: true, message: data.length + '행 삭제 완료' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  6. 악보 검색 (scores 테이블)
// ================================================================
async function searchSongs(query, ctx) {
  try {
    const keyword = (query || '').toLowerCase().trim();
    if (!keyword) return { ok: true, data: [] };

    const { data: rows, error } = await supabase
      .from('scores')
      .select('song_title, file_name, file_url')
      .eq('team_id', ctx.teamId)
      .ilike('song_title', `%${keyword}%`)
      .limit(50);

    if (error) throw new Error(error.message);
    return { ok: true, data: rows || [] };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  7. 악보 등록 (관리자)
// ================================================================
async function adminAddSong(song, ctx) {
  try {
    if (!song.song_title || !song.file_name || !song.file_url) {
      return { ok: false, message: '곡 제목, 파일명, URL을 모두 입력해 주세요.' };
    }

    // 파일명 중복 확인
    const { data: dup } = await supabase
      .from('scores')
      .select('file_name')
      .eq('team_id', ctx.teamId)
      .eq('file_name', song.file_name.trim())
      .maybeSingle();

    if (dup) {
      return { ok: false, message: '동일한 파일명이 이미 등록되어 있습니다: ' + song.file_name };
    }

    const { error } = await supabase.from('scores').insert({
      team_id:     ctx.teamId,
      song_title:  song.song_title,
      file_name:   song.file_name,
      file_url:    song.file_url,
      uploaded_by: song.uploaded_by || 'admin',
      uploaded_at: new Date().toISOString(),
    });

    if (error) throw new Error(error.message);
    return { ok: true, message: '악보 등록 완료' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  8. 악보 삭제 (관리자)
// ================================================================
async function adminDeleteSong(file_name, ctx) {
  try {
    if (!file_name || file_name.trim() === '') {
      return { ok: false, message: '삭제할 파일명이 없습니다.' };
    }
    const target = file_name.trim();

    const { data, error } = await supabase
      .from('scores')
      .delete()
      .eq('team_id', ctx.teamId)
      .eq('file_name', target)
      .select();

    if (error) throw new Error(error.message);
    if (!data || data.length === 0) {
      return { ok: false, message: '악보를 찾을 수 없습니다: ' + target };
    }

    return { ok: true, message: '악보 삭제 완료' };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  ★ 8-2. 악보 정보 수정 (관리자)
//   - song_title, file_url 만 수정 가능 (file_name은 식별자라 변경 안 함)
//   - 같은 file_name을 가진 set_list 항목들의 song_title, file_url도 함께 업데이트
//     → URL 변경 시 기존 셋리스트도 즉시 새 URL 사용
// ================================================================
async function adminUpdateSong(payload, ctx) {
  try {
    const { file_name, song_title, file_url } = payload || {};
    if (!file_name || !song_title || !file_url) {
      return { ok: false, message: '곡 제목, 파일명, URL을 모두 입력해 주세요.' };
    }

    const target = file_name.trim();

    // 1) scores 테이블 업데이트
    const { data: scoreData, error: scoreErr } = await supabase
      .from('scores')
      .update({ song_title: song_title.trim(), file_url: file_url.trim() })
      .eq('team_id', ctx.teamId)
      .eq('file_name', target)
      .select();

    if (scoreErr) throw new Error(scoreErr.message);
    if (!scoreData || scoreData.length === 0) {
      return { ok: false, message: '악보를 찾을 수 없습니다: ' + target };
    }

    // 2) set_list 테이블의 같은 file_name 항목들도 함께 업데이트 (정합성 유지)
    const { data: setData, error: setErr } = await supabase
      .from('set_list')
      .update({ song_title: song_title.trim(), file_url: file_url.trim() })
      .eq('team_id', ctx.teamId)
      .eq('file_name', target)
      .select();

    if (setErr) {
      console.warn('[adminUpdateSong] set_list 동기화 실패:', setErr.message);
      return {
        ok: true,
        message: '악보 정보 수정 완료 (단, 기존 셋리스트 동기화 실패)',
      };
    }

    const updatedSets = (setData || []).length;
    return {
      ok: true,
      message: updatedSets > 0
        ? `악보 정보 수정 완료 (셋리스트 ${updatedSets}건도 함께 업데이트됨)`
        : '악보 정보 수정 완료',
    };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  9. 악보 전체 목록 조회 (관리자)
// ================================================================
async function getAllScores(_payload, ctx) {
  try {
    const { data: rows, error } = await supabase
      .from('scores')
      .select('song_title, file_name, file_url, uploaded_by, uploaded_at')
      .eq('team_id', ctx.teamId)
      .order('uploaded_at', { ascending: false });

    if (error) throw new Error(error.message);
    return { ok: true, data: rows || [] };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  10. 파일 fetch — CORS 프록시 (fetchFileAsBase64)
//  ※ 큰 파일은 api/fetch-file.js로 분리됨
//     여기서는 gas() 라우터 호환용으로 fetch-file API를 내부 호출
//
//  ★ 진단 강화 (v3.1):
//   - 모든 단계에서 Vercel 로그 출력 (어떤 URL이 어떤 응답을 받았는지)
//   - HTML 응답 감지 — driveFileId 없어도 감지 (Google Drive 일반 URL 케이스)
//   - 1회 자동 재시도 (Google Drive 일시 장애 대응, 2초 대기)
//   - 에러 메시지에 시도한 URL 일부 포함
// ================================================================
async function _tryFetch(url, originalUrl, driveFileId, attempt) {
  console.log(`[fetchFile] 시도 ${attempt} URL=${url}`);

  const resp = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0',
      'Accept': 'application/pdf,image/*,*/*',
    },
    redirect: 'follow',
  });

  console.log(`[fetchFile] 응답 status=${resp.status} content-type=${resp.headers.get('content-type')}`);

  if (!resp.ok) {
    return { ok: false, status: resp.status, message: `HTTP ${resp.status} (시도 ${attempt})` };
  }

  const contentType = resp.headers.get('content-type') || '';

  // ★ HTML 응답 감지 강화 — driveFileId 유무 무관하게 감지
  //   Google Drive가 PDF/이미지 대신 HTML(로그인 페이지, 바이러스 검사 페이지 등)을 반환하는 케이스
  if (contentType.includes('text/html')) {
    // 응답 본문 일부 확인 — 어떤 HTML인지 로그에 남김
    const sample = await resp.text();
    const head = sample.slice(0, 300).replace(/\s+/g, ' ');
    console.log(`[fetchFile] HTML 응답 본문 일부: ${head}`);
    return {
      ok: false,
      isHtml: true,
      message: 'Google Drive가 HTML 페이지를 반환했습니다 (파일 직접 다운로드 실패). 파일 형식 또는 권한을 확인해 주세요.',
    };
  }

  const buf    = await resp.arrayBuffer();
  const base64 = Buffer.from(buf).toString('base64');
  const mime   = contentType || detectMime(url);

  console.log(`[fetchFile] 성공 size=${buf.byteLength} bytes mime=${mime}`);

  return {
    ok:       true,
    base64,
    mimeType: mime,
    fileType: classifyType(mime, url, originalUrl),
  };
}

async function fetchFileAsBase64(fileUrl, ctx) {
  try {
    if (!fileUrl || fileUrl.trim() === '') {
      return { ok: false, message: '파일 URL이 없습니다.' };
    }

    const originalUrl = fileUrl.trim();
    let url = originalUrl;

    console.log(`[fetchFile] 원본 URL: ${originalUrl}`);

    // ★ 보안 — 앱에 등록된 악보 주소만 가져온다 (아무 주소나 대신 받아 주는 통로로 쓰이지 않게)
    if (!/^https:\/\//i.test(originalUrl)) {
      return { ok: false, message: 'https 주소만 사용할 수 있습니다.' };
    }
    const candidates = Array.from(new Set([fileUrl, originalUrl]));
    const { data: inScores, error: e1 } = await supabase
      .from('scores').select('file_url').eq('team_id', ctx.teamId).in('file_url', candidates).limit(1);
    if (e1) throw new Error(e1.message);
    if (!inScores || inScores.length === 0) {
      const { data: inSets, error: e2 } = await supabase
        .from('set_list').select('file_url').eq('team_id', ctx.teamId).in('file_url', candidates).limit(1);
      if (e2) throw new Error(e2.message);
      if (!inSets || inSets.length === 0) {
        console.warn(`[fetchFile] 등록되지 않은 주소 요청 거절: ${originalUrl}`);
        return { ok: false, message: '등록된 악보가 아닙니다.' };
      }
    }

    // OneDrive URL 변환
    if (url.includes('1drv.ms') || url.includes('onedrive.live.com')) {
      url += (url.includes('?') ? '&' : '?') + 'download=1';
    }

    // Google Drive URL 변환
    let driveFileId = null;
    const driveMatch1 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (driveMatch1) driveFileId = driveMatch1[1];
    if (!driveFileId) {
      const driveMatch2 = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
      if (driveMatch2 && url.includes('drive.google.com')) driveFileId = driveMatch2[1];
    }
    if (driveFileId) {
      url = `https://drive.google.com/uc?export=download&confirm=t&id=${driveFileId}`;
      console.log(`[fetchFile] Drive ID 추출: ${driveFileId} → 변환된 URL: ${url}`);
    } else if (originalUrl.includes('drive.google.com') || originalUrl.includes('docs.google.com')) {
      console.warn(`[fetchFile] Google Drive URL이지만 file ID 추출 실패: ${originalUrl}`);
    }

    // 1차 시도
    let result = await _tryFetch(url, originalUrl, driveFileId, 1);
    if (result.ok) return result;

    // ★ 1차 실패 시 자동 재시도 (2초 대기) — Google Drive 일시 장애 대응
    //   단, HTML 응답은 재시도해도 같은 결과이므로 재시도 안 함
    if (!result.isHtml) {
      console.log(`[fetchFile] 1차 실패 (${result.message}), 2초 후 재시도`);
      await new Promise(r => setTimeout(r, 2000));
      result = await _tryFetch(url, originalUrl, driveFileId, 2);
      if (result.ok) return result;
    }

    // 최종 실패 — 어떤 URL이 실패했는지 메시지에 포함
    const urlTail = originalUrl.length > 60 ? '...' + originalUrl.slice(-60) : originalUrl;
    return {
      ok: false,
      message: `${result.message}\nURL: ${urlTail}`,
    };
  } catch (e) {
    console.error('[fetchFile] 예외:', e);
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  선곡 통계 — 최근 6개월 set_list 집계 (신규 추가, 기존 함수 무수정)
//  · 같은 날 여러 Set List에 담긴 곡은 담긴 횟수만큼 그대로 계산
//  · 기간 내 사용 이력이 없는 곡은 포함하지 않음 (set_list 단일 조회)
//  · 1개월·3개월 필터는 프론트에서 처리하므로 항상 6개월치를 반환
// ================================================================
async function getSongStats(_payload, ctx) {
  try {
    const MONTHS = 6;
    const PAGE   = 1000;

    // 한국 시간 기준 오늘 날짜 산출 (서버는 UTC이므로 +9시간 보정)
    const kst  = new Date(Date.now() + 9 * 60 * 60 * 1000);
    const pad  = n => String(n).padStart(2, '0');
    const fmt  = d => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    const y = kst.getUTCFullYear(), m = kst.getUTCMonth(), d = kst.getUTCDate();

    const to   = fmt(new Date(Date.UTC(y, m, d)));
    const from = fmt(new Date(Date.UTC(y, m - MONTHS, d)));

    // ── 페이징 조회 — Supabase 기본 1,000행 상한 회피 ──────────
    let rows = [];
    for (let offset = 0; offset < 20000; offset += PAGE) {
      const { data, error } = await supabase
        .from('set_list')
        .select('song_title, file_name, worship_date')
        .eq('team_id', ctx.teamId)
        .gte('worship_date', from)
        .lte('worship_date', to)
        .order('worship_date', { ascending: false })
        .order('set_id')        // ★ 같은 날짜 안에서도 순서를 고정 — 페이지 경계에서 행이 빠지거나 겹치지 않게
        .order('song_order')
        .range(offset, offset + PAGE - 1);

      if (error) throw new Error(error.message);
      rows = rows.concat(data || []);
      if (!data || data.length < PAGE) break;
    }

    // ── ★ 곡 기준 집계 — 조(코드)와 확장자가 달라도 같은 곡이면 합침 ──
    //   예) D-은혜가 풍성한 하나님은.jpg / E-은혜가 풍성한 하나님은.png → 한 곡
    //   · 확장자 제거, 맨 앞의 조 표시(D-, E-, F#-, Bb-, Am- 등) 제거
    //   · 앞뒤·중복 공백 정리, 대소문자 무시, 맥 방식 한글(자모 분리)도 같은 글자로 맞춤 (NFC)
    //   · 파일명이 없는 옛 기록은 곡 제목으로 묶음
    const KEY_RE = /^\s*([A-Ga-g](?:#|b|♯|♭)?m?)\s*[-_]\s*/;
    const splitName = raw => {
      const noExt = String(raw || '').trim().replace(/\.[a-z0-9]{2,5}$/i, '').normalize('NFC');
      const m = noExt.match(KEY_RE);
      return m ? { key: m[1].charAt(0).toUpperCase() + m[1].slice(1), name: noExt.slice(m[0].length).trim() }
               : { key: '', name: noExt.trim() };
    };
    const map = new Map();   // 묶음 키 → { dates, names:{이름:마지막날짜}, keys:Set }
    rows.forEach(r => {
      const src = splitName(r.file_name || r.song_title);
      const fromTitle = splitName(r.song_title);
      const groupKey = src.name.replace(/\s+/g, ' ').toLowerCase();
      if (!groupKey) return;
      const date = normDate(r.worship_date);
      if (!map.has(groupKey)) map.set(groupKey, { dates: [], names: new Map(), keys: new Set() });
      const g = map.get(groupKey);
      g.dates.push(date);
      if (src.key) g.keys.add(src.key);
      const shown = fromTitle.name || src.name;   // 화면 표시용 이름 (조 표시 뺀 곡 제목)
      if (!g.names.has(shown) || g.names.get(shown) < date) g.names.set(shown, date);
    });

    const songs = Array.from(map.values())
      .map(g => {
        g.dates.sort((a, b) => b.localeCompare(a));   // 최신 날짜가 앞
        // 화면에 보일 이름 — 가장 최근에 쓴 곡 제목 + 불렀던 조 목록
        let name = '', best = '';
        g.names.forEach((d, t) => { if (d > best || (d === best && t < name)) { best = d; name = t; } });
        const keys = Array.from(g.keys).sort();
        const title = keys.length ? `${name} (${keys.join('·')})` : name;
        return { title, dates: g.dates, count: g.dates.length, lastDate: g.dates[0] };
      })
      .filter(s => s.title)
      .sort((a, b) => b.count - a.count || a.title.localeCompare(b.title));

    // ── ★ 6개월간 한 번도 부르지 않은 곡 — 팀에 등록된 악보 중 위 집계에 없는 곡 ──
    //   (조·확장자가 달라도 같은 곡으로 묶는 규칙은 위와 동일)
    let scoreRows = [];
    for (let offset = 0; offset < 20000; offset += PAGE) {
      const { data, error } = await supabase
        .from('scores')
        .select('id, song_title, file_name')
        .eq('team_id', ctx.teamId)
        .order('id')
        .range(offset, offset + PAGE - 1);
      if (error) throw new Error(error.message);
      scoreRows = scoreRows.concat(data || []);
      if (!data || data.length < PAGE) break;
    }
    // 앞으로 부를 곡(오늘 이후 날짜로 미리 만든 Set List)도 "안 부른 곡"에서는 제외 — 이미 선곡된 곡이므로
    const planned = new Set();
    for (let offset = 0; offset < 20000; offset += PAGE) {
      const { data, error } = await supabase
        .from('set_list')
        .select('song_title, file_name, worship_date')
        .eq('team_id', ctx.teamId)
        .gt('worship_date', to)
        .order('worship_date')
        .order('set_id')
        .order('song_order')
        .range(offset, offset + PAGE - 1);
      if (error) throw new Error(error.message);
      (data || []).forEach(r => planned.add(splitName(r.file_name || r.song_title).name.replace(/\s+/g, ' ').toLowerCase()));
      if (!data || data.length < PAGE) break;
    }

    const unusedMap = new Map();   // 묶음 키 → { name, keys:Set }
    scoreRows.forEach(r => {
      const src = splitName(r.file_name || r.song_title);
      const groupKey = src.name.replace(/\s+/g, ' ').toLowerCase();
      if (!groupKey || map.has(groupKey) || planned.has(groupKey)) return;   // 6개월 안에 불렀거나 앞으로 부를 곡은 제외
      if (!unusedMap.has(groupKey)) {
        unusedMap.set(groupKey, { name: splitName(r.song_title).name || src.name, keys: new Set() });
      }
      if (src.key) unusedMap.get(groupKey).keys.add(src.key);
    });
    const unused = Array.from(unusedMap.values())
      .map(g => {
        const keys = Array.from(g.keys).sort();
        return { title: keys.length ? `${g.name} (${keys.join('·')})` : g.name };
      })
      .sort((a, b) => a.title.localeCompare(b.title, 'ko'));

    return { ok: true, from, to, today: to, totalRows: rows.length, songs, unused };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  ★ 찬양팀 입장 — 코드 하나로 팀과 역할(관리자·팀원)을 찾는다
// ================================================================
async function enterCode(code, ctx) {
  try {
    const ip = (ctx && ctx.ip) || 'unknown';
    if (_recentFails(ip).length >= FAIL_LIMIT) {
      return { ok: false, message: '코드를 여러 번 틀렸습니다. 10분 뒤에 다시 시도해 주세요.' };
    }
    const c = String(code || '').trim();
    if (c.length < 8) {
      _recentFails(ip).push(Date.now());
      return { ok: false, message: '코드를 다시 확인해 주세요.' };
    }
    const h = hashCode(c);
    const { data: rows, error } = await supabase
      .from('teams')
      .select('id, display_name, code_version, status, admin_code_hash, member_code_hash, sub_code_hash, sub_version')
      .or(`admin_code_hash.eq.${h},member_code_hash.eq.${h},sub_code_hash.eq.${h}`)
      .limit(1);
    if (error) throw new Error(error.message);
    const team = rows && rows[0];
    if (!team) {
      _recentFails(ip).push(Date.now());
      await new Promise(r => setTimeout(r, 1500));   // 자동 추측 속도 늦추기
      return { ok: false, message: '코드를 다시 확인해 주세요.' };
    }
    if (team.status !== 'active') {
      return { ok: false, message: '사용이 정지된 팀입니다. 운영자에게 문의해 주세요.' };
    }
    _failLog.delete(ip);
    const role = team.admin_code_hash === h ? 'ta' : team.sub_code_hash === h ? 'ts' : 'tm';
    await supabase.from('teams').update({ last_used_at: new Date().toISOString() }).eq('id', team.id);
    return {
      ok: true,
      role,
      teamName: team.display_name,
      subEnabled: !!team.sub_code_hash,
      token: issueToken(role, team.id, _verOf(role, team)),
    };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// 기기에 기억된 입장권이 아직 유효한지 확인 (앱을 열 때)
async function whoami(_payload, ctx) {
  try {
    await supabase.from('teams').update({ last_used_at: new Date().toISOString() }).eq('id', ctx.teamId);
  } catch (e) { /* 최근 사용일 기록 실패는 무시 */ }
  return { ok: true, role: ctx.role, teamName: ctx.teamName, subEnabled: ctx.subEnabled };
}

// ── 팀 관리자: 팀원 코드 재발급 (관리자 코드는 그대로) ──
//   팀원 코드만 바뀌므로 코드버전은 올리지 않는다 → 이미 들어와 있는 팀원 기기는 그대로 유지
//   (팀원을 모두 내보내야 할 때는 운영자에게 "코드 재발급"을 요청 → 모든 기기 로그아웃)
async function reissueMemberCode(_payload, ctx) {
  try {
    const memberCode = generateCode();
    const { error } = await supabase.from('teams')
      .update({ member_code_hash: hashCode(memberCode) }).eq('id', ctx.teamId);
    if (error) throw new Error(error.message);
    return { ok: true, memberCode };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ── 팀 관리자: 부관리자 코드 만들기 / 끄기 ──
//   만들 때마다 부관리자 버전이 올라가 예전 부관리자 기기는 로그아웃됨
async function _bumpSub(teamId, newHash) {
  const { data: team, error: e1 } = await supabase
    .from('teams').select('sub_version').eq('id', teamId).maybeSingle();
  if (e1) throw new Error(e1.message);
  if (!team) throw new Error('팀을 찾을 수 없습니다.');
  const { error } = await supabase.from('teams')
    .update({ sub_code_hash: newHash, sub_version: (team.sub_version || 0) + 1 }).eq('id', teamId);
  if (error) throw new Error(error.message);
}
async function createSubCode(_payload, ctx) {
  try {
    const subCode = generateCode();
    await _bumpSub(ctx.teamId, hashCode(subCode));
    return { ok: true, subCode };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}
async function disableSubCode(_payload, ctx) {
  try {
    await _bumpSub(ctx.teamId, null);
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  ★ 운영자 기능 — 팀 만들기·목록·정지·코드 재발급·삭제
//   운영자는 팀의 Set List·악보 내용은 보지 않는다 (개수만 표시)
// ================================================================
async function opWhoami() {
  return { ok: true, role: 'op' };
}

async function listTeams() {
  try {
    const { data: teams, error } = await supabase
      .from('teams')
      .select('id, team_name, church_name, display_name, status, created_at, last_used_at')
      .order('created_at', { ascending: true });
    if (error) throw new Error(error.message);

    // 팀별 악보·Set List 개수 (내용은 가져오지 않음)
    const counts = {};
    for (const t of teams || []) {
      const [{ count: sc }, { count: lc }] = await Promise.all([
        supabase.from('scores').select('id', { count: 'exact', head: true }).eq('team_id', t.id),
        supabase.from('set_list').select('set_id', { count: 'exact', head: true }).eq('team_id', t.id),
      ]);
      counts[t.id] = { scores: sc || 0, setRows: lc || 0 };
    }
    // 아직 팀이 정해지지 않은 예전 자료 개수
    const [{ count: ls }, { count: ll }] = await Promise.all([
      supabase.from('scores').select('id', { count: 'exact', head: true }).is('team_id', null),
      supabase.from('set_list').select('set_id', { count: 'exact', head: true }).is('team_id', null),
    ]);

    return {
      ok: true,
      teams: (teams || []).map(t => Object.assign({}, t, counts[t.id])),
      legacy: { scores: ls || 0, setRows: ll || 0 },
    };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

async function createTeam(payload) {
  try {
    const teamName   = String((payload && payload.team_name)   || '').trim();
    const churchName = String((payload && payload.church_name) || '').trim();
    if (!teamName || !churchName) {
      return { ok: false, message: '찬양팀 이름과 교회 이름을 모두 입력해 주세요.' };
    }
    if (teamName.length > 40 || churchName.length > 40) {
      return { ok: false, message: '이름은 40자 이내로 입력해 주세요.' };
    }
    const displayName = `${teamName}(${churchName})`;
    const adminCode  = generateCode();
    let   memberCode = generateCode();
    while (memberCode === adminCode) memberCode = generateCode();

    const { data, error } = await supabase.from('teams').insert({
      team_name: teamName, church_name: churchName, display_name: displayName,
      admin_code_hash: hashCode(adminCode), member_code_hash: hashCode(memberCode),
    }).select('id').single();
    if (error) throw new Error(error.message);

    // 코드는 이번 한 번만 돌려준다 (서버에는 암호화된 값만 남음)
    return { ok: true, teamId: data.id, displayName, adminCode, memberCode };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

async function setTeamStatus(payload) {
  try {
    const id = Number(payload && payload.team_id);
    const status = payload && payload.status;
    if (!id || !['active', 'suspended'].includes(status)) {
      return { ok: false, message: '요청이 올바르지 않습니다.' };
    }
    const { data, error } = await supabase.from('teams').update({ status }).eq('id', id).select('id');
    if (error) throw new Error(error.message);
    if (!data || !data.length) return { ok: false, message: '팀을 찾을 수 없습니다.' };
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// 관리자·팀원 코드 모두 재발급 + 코드버전 증가 → 그 팀의 모든 기기가 로그아웃됨
async function reissueTeamCodes(payload) {
  try {
    const id = Number(payload && payload.team_id);
    const { data: team, error: e1 } = await supabase
      .from('teams').select('id, display_name, code_version, sub_version').eq('id', id).maybeSingle();
    if (e1) throw new Error(e1.message);
    if (!team) return { ok: false, message: '팀을 찾을 수 없습니다.' };

    const adminCode  = generateCode();
    let   memberCode = generateCode();
    while (memberCode === adminCode) memberCode = generateCode();
    const { error } = await supabase.from('teams').update({
      admin_code_hash: hashCode(adminCode),
      member_code_hash: hashCode(memberCode),
      code_version: team.code_version + 1,
      sub_code_hash: null,                          // 부관리자도 꺼짐 (관리자가 다시 만들어야 함)
      sub_version: (team.sub_version || 0) + 1,
    }).eq('id', id);
    if (error) throw new Error(error.message);
    return { ok: true, displayName: team.display_name, adminCode, memberCode };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// 팀 삭제 — 실수 방지를 위해 표시 이름을 정확히 입력해야 함. 팀의 악보·Set List도 함께 삭제
async function deleteTeam(payload) {
  try {
    const id = Number(payload && payload.team_id);
    const confirmName = String((payload && payload.confirm_name) || '').trim();
    const { data: team, error: e1 } = await supabase
      .from('teams').select('id, display_name').eq('id', id).maybeSingle();
    if (e1) throw new Error(e1.message);
    if (!team) return { ok: false, message: '팀을 찾을 수 없습니다.' };
    if (confirmName !== team.display_name) {
      return { ok: false, message: '팀 이름이 일치하지 않아 삭제하지 않았습니다.' };
    }
    const r1 = await supabase.from('set_list').delete().eq('team_id', id);
    if (r1.error) throw new Error(r1.error.message);
    const r2 = await supabase.from('scores').delete().eq('team_id', id);
    if (r2.error) throw new Error(r2.error.message);
    const r3 = await supabase.from('teams').delete().eq('id', id);
    if (r3.error) throw new Error(r3.error.message);
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// 팀이 정해지지 않은 예전 자료(전환 전 자료)를 지정한 팀으로 옮긴다 — 한 번만 쓰는 기능
async function claimLegacyData(payload) {
  try {
    const id = Number(payload && payload.team_id);
    const { data: team } = await supabase.from('teams').select('id').eq('id', id).maybeSingle();
    if (!team) return { ok: false, message: '팀을 찾을 수 없습니다.' };
    const r1 = await supabase.from('scores').update({ team_id: id }).is('team_id', null).select('id');
    if (r1.error) throw new Error(r1.error.message);
    const r2 = await supabase.from('set_list').update({ team_id: id }).is('team_id', null).select('set_id');
    if (r2.error) throw new Error(r2.error.message);
    return { ok: true, scores: (r1.data || []).length, setRows: (r2.data || []).length };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  핸들러 라우터
// ================================================================
const handlers = {
  verifyAdminPassword,
  saveSetList,
  getSetListsByDate,
  getDatesWithSetList,
  updateSetList,
  deleteSetList,
  searchSongs,
  adminAddSong,
  adminDeleteSong,
  adminUpdateSong,
  getAllScores,
  fetchFileAsBase64,
  getSongStats,
  enterCode,
  whoami,
  reissueMemberCode,
  createSubCode,
  disableSubCode,
  opWhoami,
  listTeams,
  createTeam,
  setTeamStatus,
  reissueTeamCodes,
  deleteTeam,
  claimLegacyData,
};

// ================================================================
//  Vercel API Route 진입점
// ================================================================
module.exports = async function handler(req, res) {
  setCors(res);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Method Not Allowed' });
  }

  const { fn, payload, token } = req.body || {};

  if (!fn || !Object.prototype.hasOwnProperty.call(handlers, fn)) {
    return res.status(400).json({ ok: false, message: '알 수 없는 함수: ' + fn });
  }

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
          || (req.socket && req.socket.remoteAddress) || 'unknown';

  try {
    // ★ 보안 — 매 요청마다 입장권으로 역할·팀을 확인하고, 기능별 권한을 검사
    let ctx = { ip };
    if (!PUBLIC.has(fn)) {
      const session = await resolveSession(token);
      const r = session && session.role;
      const allowed = session && (
        (OPERATOR.has(fn)   && r === 'op') ||
        (TEAM_ADMIN.has(fn) && r === 'ta') ||
        (EDITOR.has(fn)     && (r === 'ta' || r === 'ts')) ||
        (MEMBER.has(fn)     && (r === 'ta' || r === 'ts' || r === 'tm'))
      );
      if (!allowed) {
        return res.json({
          ok: false,
          authRequired: true,
          message: session ? '이 기능을 사용할 권한이 없습니다.'
                           : '입장이 만료되었거나 코드가 바뀌었습니다. 코드를 다시 입력해 주세요.',
        });
      }
      ctx = Object.assign(ctx, session);
    }

    const result = await handlers[fn](payload, ctx);
    return res.json(result);
  } catch (e) {
    console.error('[gas.js] 오류:', fn, e);
    return res.status(500).json({ ok: false, message: e.message });
  }
}
