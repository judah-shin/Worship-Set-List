// 사용하지 않는 예전 악보 프록시 경로 — 보안을 위해 닫아 둠 (악보는 /api/gas의 fetchFileAsBase64가 처리)
// ================================================================
//  Worship Set List — api/fetch-file.js
//  ★ 이 경로는 앱 화면에서 쓰이지 않습니다.
//    예전에는 아무 주소나 대신 내려받아 주는 통로였기 때문에,
//    외부에서 악용되지 않도록 모든 요청을 거절합니다.
//    악보 불러오기는 /api/gas 의 fetchFileAsBase64 (등록된 악보만 허용)가 담당합니다.
// ================================================================

module.exports = async function handler(req, res) {
  return res.status(410).json({
    ok: false,
    message: '이 경로는 더 이상 사용하지 않습니다.',
  });
};
