// ================================================================
//  Worship Set List — api/fetch-file.js  (Vercel API Route)
//  OneDrive / Google Drive CORS 프록시
//  큰 파일은 /api/gas의 fetchFileAsBase64 대신 이 라우트를 사용합니다.
// ================================================================

// ── MIME / 파일 분류 헬퍼 ────────────────────────────────────
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
//  Vercel API Route 진입점
// ================================================================
module.exports = async function handler(req, res) {
  // CORS 헤더
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, message: 'Method Not Allowed' });
  }

  const { fileUrl } = req.body || {};

  if (!fileUrl || !fileUrl.trim()) {
    return res.status(400).json({ ok: false, message: '파일 URL이 없습니다.' });
  }

  try {
    let url = fileUrl.trim();

    // ── OneDrive 단축 URL / 공유 URL → 직접 다운로드 URL로 변환 ──
    if (url.includes('1drv.ms') || url.includes('onedrive.live.com')) {
      url += (url.includes('?') ? '&' : '?') + 'download=1';
    }

    // ── Google Drive URL → 직접 다운로드 URL로 변환 ──────────────
    // 지원하는 링크 형식:
    //   형식 1) https://drive.google.com/file/d/FILE_ID/view
    //   형식 2) https://drive.google.com/file/d/FILE_ID/view?usp=sharing
    //   형식 3) https://drive.google.com/open?id=FILE_ID
    //   형식 4) https://docs.google.com/uc?id=FILE_ID
    //   형식 5) https://drive.google.com/uc?id=FILE_ID (이미 변환된 형식)

    let driveFileId = null;

    // 형식 1, 2 — /file/d/FILE_ID/
    const driveMatch1 = url.match(/\/file\/d\/([a-zA-Z0-9_-]+)/);
    if (driveMatch1) driveFileId = driveMatch1[1];

    // 형식 3 — open?id=FILE_ID
    if (!driveFileId) {
      const driveMatch2 = url.match(/[?&]id=([a-zA-Z0-9_-]+)/);
      if (driveMatch2 && url.includes('drive.google.com')) driveFileId = driveMatch2[1];
    }

    if (driveFileId) {
      // confirm=t → 대용량 파일 바이러스 검사 경고 페이지 우회
      url = `https://drive.google.com/uc?export=download&confirm=t&id=${driveFileId}`;
    }

    const resp = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WorshipApp/1.0)',
        // 구글 드라이브 쿠키 우회용 헤더
        'Accept': 'application/pdf,image/*,*/*',
      },
      redirect: 'follow',
    });

    // ── 구글 드라이브 바이러스 검사 HTML 페이지 감지 ─────────────
    // 대용량 파일에서 confirm=t 로도 HTML이 반환될 경우 대비
    const contentType = resp.headers.get('content-type') || '';
    if (contentType.includes('text/html') && driveFileId) {
      return res.status(502).json({
        ok: false,
        message: '구글 드라이브 파일을 가져올 수 없습니다.\n'
               + '파일 공유 설정을 "링크가 있는 모든 사용자"로 변경하거나\n'
               + 'OneDrive 링크를 사용해 주세요.',
      });
    }

    if (!resp.ok) {
      return res.status(502).json({ ok: false, message: 'HTTP ' + resp.status });
    }

    const buf    = await resp.arrayBuffer();
    const base64 = Buffer.from(buf).toString('base64');
    const mime   = contentType || detectMime(url);

    return res.json({
      ok:       true,
      base64,
      mimeType: mime,
      fileType: classifyType(mime, url),
    });
  } catch (e) {
    console.error('[fetch-file.js] 오류:', e);
    return res.status(500).json({ ok: false, message: e.message });
  }
}

// ── Vercel 설정: 최대 실행 시간 연장 (Pro 플랜 이상) ─────────
//    무료 플랜은 10초 제한 — 큰 PDF 처리 시 주의
export const config = {
  api: {
    responseLimit: false,       // 응답 크기 제한 해제 (기본 4MB)
    bodyParser: {
      sizeLimit: '2mb',         // 요청 body 2MB 제한
    },
  },
};
