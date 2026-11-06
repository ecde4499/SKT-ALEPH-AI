'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const sampleBtn = $('sampleBtn'), uploadBtn = $('uploadBtn'), fileInput = $('fileInput');
  const analyzeBtn = $('analyzeBtn'), downloadBtn = $('downloadBtn');
  const errorBox = $('errorBox');
  let selectedMode = 'sample', lastAlerts = [], lastComplete = false, requestVersion = 0;
  function mode(type) {
    clearResults('입력 방식을 바꿨습니다. 새 데이터를 분석해 주세요.');
    selectedMode = type;
    sampleBtn.classList.toggle('selected', type === 'sample');
    uploadBtn.classList.toggle('selected', type === 'upload');
    sampleBtn.setAttribute('aria-pressed', String(type === 'sample'));
    uploadBtn.setAttribute('aria-pressed', String(type === 'upload'));
    $('uploadArea').hidden = type === 'sample';
    hideError();
  }
  function hideError() { errorBox.hidden = true; errorBox.textContent = ''; }
  function clearResults(message = '새 데이터를 분석하면 이곳에 결과가 표시됩니다.') {
    // Ignore a delayed response if the user changes input or starts another analysis.
    requestVersion += 1;
    lastAlerts = [];
    lastComplete = false;
    downloadBtn.disabled = true;
    for (const id of ['metricTotal','metricAlerts','metricHigh','metricMedium']) $(id).textContent = '—';
    $('alertCount').textContent = '대기 중';
    $('resultSummary').textContent = message;
    const body = $('alertsBody');
    body.replaceChildren();
    const row = child(body,'tr'); const cell = child(row,'td',message,'empty'); cell.colSpan = 5;
  }
  function error(text) { errorBox.textContent = text; errorBox.hidden = false; }
  sampleBtn.addEventListener('click', () => mode('sample'));
  uploadBtn.addEventListener('click', () => mode('upload'));
  fileInput.addEventListener('change', () => {
    const f = fileInput.files && fileInput.files[0];
    $('selectedFile').textContent = f ? `${f.name} · ${(f.size / 1024).toFixed(1)}KB` : '선택한 파일 없음';
    clearResults('선택한 파일을 분석하려면 분석 실행을 눌러 주세요.');
    hideError();
  });
  const t = (tag, content, className) => {
    const el = document.createElement(tag);
    if (content != null) el.textContent = String(content);
    if (className) el.className = className;
    return el;
  };
  const child = (parent, tag, value, cls) => { const el = t(tag, value, cls); parent.appendChild(el); return el; };
  const formatTime = (iso) => iso ? iso.replace('T', ' ').replace('+09:00', '') : '—';
  function fill(result) {
    lastAlerts = result.alerts || [];
    lastComplete = true;
    $('metricTotal').textContent = String(result.total_events ?? 0);
    $('metricAlerts').textContent = String(result.total_alerts ?? 0);
    $('metricHigh').textContent = String(result.by_severity?.['높음'] ?? 0);
    $('metricMedium').textContent = String(result.by_severity?.['보통'] ?? 0);
    $('resultSummary').textContent = `총 ${result.total_events}건의 로그에서 ${result.total_alerts}건의 징후를 발견했습니다. 실제 공격 확정은 아닙니다.`;
    $('alertCount').textContent = `${lastAlerts.length} DETECTED`;
    downloadBtn.disabled = false;
    const body = $('alertsBody'); body.replaceChildren();
    if (!lastAlerts.length) { const row = child(body,'tr'); const cell = child(row,'td','조건에 해당하는 이상징후가 없습니다.','empty'); cell.colSpan = 5; return; }
    for (const a of lastAlerts) {
      const row = child(body, 'tr');
      child(row,'td',formatTime(a.timestamp));
      const rule = child(row,'td'); child(rule,'strong',a.title); child(rule,'small',a.code,'cell-sub');
      const severity = child(row,'td'); child(severity,'span',a.severity,'risk '+(a.severity==='높음'?'risk-high':a.severity==='보통'?'risk-medium':'risk-low'));
      const identity = child(row,'td'); child(identity,'span',a.user); child(identity,'span',a.src_ip,'cell-sub');
      const evidence = child(row,'td'); child(evidence,'span',a.evidence); child(evidence,'small',a.detail,'cell-sub');
    }
  }
  analyzeBtn.addEventListener('click', async () => {
    hideError();
    clearResults('분석 중입니다…');
    const startedVersion = requestVersion;
    const body = new FormData();
    if (selectedMode === 'sample') body.append('sample','true');
    else {
      const f = fileInput.files && fileInput.files[0];
      if (!f) { error('분석할 CSV 파일을 선택해 주세요.'); return; }
      if (f.size > 256 * 1024) { error('CSV 파일은 256KB 이하만 분석할 수 있습니다.'); return; }
      if (!f.name.toLowerCase().endsWith('.csv')) { error('CSV 확장자 파일을 선택해 주세요.'); return; }
      body.append('file',f);
    }
    analyzeBtn.disabled = true; analyzeBtn.textContent = '분석하고 있습니다…';
    try {
      const res = await fetch('/api/analyze',{method:'POST',body});
      const data = await res.json();
      if (startedVersion !== requestVersion) return; // User changed the input while waiting.
      if (!res.ok) throw new Error(data.error || '분석에 실패했습니다.');
      fill(data);
      $('results').scrollIntoView({behavior:'smooth'});
    } catch (e) { if (startedVersion === requestVersion) error(e.message || '연결에 문제가 있습니다. 다시 시도해 주세요.'); }
    finally { analyzeBtn.disabled = false; analyzeBtn.innerHTML = '이상징후 분석 실행 <span>↗</span>'; }
  });
  const safeCsv = (value) => {
    let v = String(value ?? '');
    // Prevent formula evaluation when exported CSV is opened in spreadsheet programs.
    if (/^[\s]*[=+\-@\t\r]/.test(v)) v = "'" + v;
    return '"' + v.replaceAll('"','""') + '"';
  };
  downloadBtn.addEventListener('click', () => {
    if (!lastComplete) return;
    const columns=['id','timestamp','code','severity','title','user','src_ip','evidence','detail'];
    const lines=[columns.join(','),...lastAlerts.map(a=>columns.map(c=>safeCsv(a[c])).join(','))];
    const blob=new Blob(['\uFEFF'+lines.join('\r\n')],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob); const link=document.createElement('a');
    link.href=url;link.download='logscope_report.csv';document.body.appendChild(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
})();
