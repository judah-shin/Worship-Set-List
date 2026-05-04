// ================================================================
//  Worship Set List — api/gas.js  (Vercel API Route)
//  Code.gs → Node.js + Supabase 이식
// ================================================================

const { createClient } = require('@supabase/supabase-js');

// ── Supabase 클라이언트 ──────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const MAX_SETS_PER_DAY = 5;

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
  const ext = (url || '').split('?')[0].split('.').pop().toLowerCase();
  const map = {
    pdf: 'application/pdf', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    png: 'image/png', gif: 'image/gif', webp: 'image/webp',
    bmp: 'image/bmp', tiff: 'image/tiff', tif: 'image/tiff', svg: 'image/svg+xml',
  };
  return map[ext] || 'application/octet-stream';
}

function classifyType(mime, url) {
  const m = mime || detectMime(url || '');
  if (m === 'application/pdf') return 'pdf';
  if (m.startsWith('image/')) return 'image';
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
async function verifyAdminPassword(inputPw) {
  try {
    const stored = process.env.ADMIN_PASSWORD || '';
    return { ok: inputPw === stored };
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
// ================================================================
async function fetchFileAsBase64(fileUrl) {
  try {
    if (!fileUrl || fileUrl.trim() === '') {
      return { ok: false, message: '파일 URL이 없습니다.' };
    }

    let url = fileUrl.trim();

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
    }

    const resp = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'application/pdf,image/*,*/*',
      },
      redirect: 'follow',
    });

    if (!resp.ok) return { ok: false, message: 'HTTP ' + resp.status };

    const contentType = resp.headers.get('content-type') || '';

    // 구글 드라이브 HTML 페이지 반환 감지
    if (contentType.includes('text/html') && driveFileId) {
      return {
        ok: false,
        message: '구글 드라이브 파일을 가져올 수 없습니다.\n파일 공유 설정을 "링크가 있는 모든 사용자"로 변경해 주세요.',
      };
    }

    const buf    = await resp.arrayBuffer();
    const base64 = Buffer.from(buf).toString('base64');
    const mime   = contentType || detectMime(url);

    return {
      ok:       true,
      base64,
      mimeType: mime,
      fileType: classifyType(mime, url),
    };
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
  getAllScores,
  fetchFileAsBase64,
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

  const { fn, payload } = req.body || {};

  if (!fn || !handlers[fn]) {
    return res.status(400).json({ ok: false, message: '알 수 없는 함수: ' + fn });
  }

  try {
    const result = await handlers[fn](payload);
    return res.json(result);
  } catch (e) {
    console.error('[gas.js] 오류:', fn, e);
    return res.status(500).json({ ok: false, message: e.message });
  }
}
