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
//  ★ 보안 — 관리자 입장권(토큰) 발급·확인
//   · 비밀번호가 맞으면 24시간 유효한 입장권을 발급한다
//   · 저장·삭제·등록·수정·통계 요청은 매번 입장권을 확인한다 (화면에서 버튼을 숨기는 것만으로는 막을 수 없음)
//   · 서명 열쇠는 이미 Vercel에 있는 값(SUPABASE_SERVICE_KEY + ADMIN_PASSWORD)에서 만든다
//     → 새 설정값이 필요 없고, 비밀번호를 바꾸면 기존 입장권은 모두 자동으로 무효가 된다
// ================================================================
const TOKEN_HOURS = 24;

function _tokenSecret() {
  return crypto.createHash('sha256')
    .update((process.env.SUPABASE_SERVICE_KEY || '') + '|' + (process.env.ADMIN_PASSWORD || ''))
    .digest();
}

function _sign(text) {
  return crypto.createHmac('sha256', _tokenSecret()).update(text).digest('hex');
}

// 길이가 달라도 시간 차이로 내용을 추측할 수 없게 비교
function _safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function issueAdminToken() {
  const exp = Date.now() + TOKEN_HOURS * 60 * 60 * 1000;
  const body = 'admin.' + exp;
  return body + '.' + _sign(body);
}

function isValidAdminToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'admin') return false;
  const exp = Number(parts[1]);
  if (!exp || exp < Date.now()) return false;
  return _safeEqual(parts[2], _sign(parts[0] + '.' + parts[1]));
}

// 관리자만 실행할 수 있는 기능 목록
const ADMIN_ONLY = new Set([
  'saveSetList', 'deleteSetList',
  'adminAddSong', 'adminDeleteSong', 'adminUpdateSong',
  'getAllScores', 'getSongStats',
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
    return { ok: true, token: issueAdminToken() };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

// ================================================================
//  2. Set List 저장
// ================================================================
async function saveSetList(payload) {
  try {
    const targetDate = normDate(payload.worship_date);

    // 같은 날짜의 기존 set_id 수 확인
    const { data: existing, error: cntErr } = await supabase
      .from('set_list')
      .select('set_id')
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
    const rows = payload.songs.map(song => ({
      set_id:       payload.set_id,
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
async function getSetListsByDate(date) {
  try {
    const targetDate = normDate(date);

    const { data: rows, error } = await supabase
      .from('set_list')
      .select('*')
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
async function getDatesWithSetList(month) {
  try {
    if (!month || !/^\d{4}-\d{2}$/.test(month)) {
      return { ok: false, message: '월 형식이 올바르지 않습니다. (YYYY-MM)' };
    }

    const { data: rows, error } = await supabase
      .from('set_list')
      .select('worship_date')
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
async function deleteSetList(set_id) {
  try {
    if (!set_id || String(set_id).trim() === '') {
      return { ok: false, message: '삭제할 Set ID가 없습니다.' };
    }
    const targetId = String(set_id).trim();

    const { data, error } = await supabase
      .from('set_list')
      .delete()
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
async function searchSongs(query) {
  try {
    const keyword = (query || '').toLowerCase().trim();
    if (!keyword) return { ok: true, data: [] };

    const { data: rows, error } = await supabase
      .from('scores')
      .select('song_title, file_name, file_url')
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
async function adminAddSong(song) {
  try {
    if (!song.song_title || !song.file_name || !song.file_url) {
      return { ok: false, message: '곡 제목, 파일명, URL을 모두 입력해 주세요.' };
    }

    // 파일명 중복 확인
    const { data: dup } = await supabase
      .from('scores')
      .select('file_name')
      .eq('file_name', song.file_name.trim())
      .maybeSingle();

    if (dup) {
      return { ok: false, message: '동일한 파일명이 이미 등록되어 있습니다: ' + song.file_name };
    }

    const { error } = await supabase.from('scores').insert({
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
async function adminDeleteSong(file_name) {
  try {
    if (!file_name || file_name.trim() === '') {
      return { ok: false, message: '삭제할 파일명이 없습니다.' };
    }
    const target = file_name.trim();

    const { data, error } = await supabase
      .from('scores')
      .delete()
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
async function adminUpdateSong(payload) {
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
async function getAllScores() {
  try {
    const { data: rows, error } = await supabase
      .from('scores')
      .select('song_title, file_name, file_url, uploaded_by, uploaded_at')
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

async function fetchFileAsBase64(fileUrl) {
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
      .from('scores').select('file_url').in('file_url', candidates).limit(1);
    if (e1) throw new Error(e1.message);
    if (!inScores || inScores.length === 0) {
      const { data: inSets, error: e2 } = await supabase
        .from('set_list').select('file_url').in('file_url', candidates).limit(1);
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
async function getSongStats() {
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

    return { ok: true, from, to, today: to, totalRows: rows.length, songs };
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
  deleteSetList,
  searchSongs,
  adminAddSong,
  adminDeleteSong,
  adminUpdateSong,
  getAllScores,
  fetchFileAsBase64,
  getSongStats,
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

  // ★ 보안 — 관리자 기능은 매 요청마다 입장권 확인
  if (ADMIN_ONLY.has(fn) && !isValidAdminToken(token)) {
    return res.json({
      ok: false,
      authRequired: true,
      message: '관리자 인증이 필요합니다. 로그아웃한 뒤 관리자로 다시 입장해 주세요.',
    });
  }

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()
          || (req.socket && req.socket.remoteAddress) || 'unknown';

  try {
    const result = await handlers[fn](payload, { ip });
    return res.json(result);
  } catch (e) {
    console.error('[gas.js] 오류:', fn, e);
    return res.status(500).json({ ok: false, message: e.message });
  }
}
