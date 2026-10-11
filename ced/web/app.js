const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

/* ---------- 公共小工具 ---------- */
/** 服务端单条请求上限（ced/web/server.py 的 MAX_PAYLOAD）。
/** 单条请求的字节上限（与服务端同一个口径）。
    放前端只为**早点报人话**：几十 MB 的文件没必要先读进内存，再被服务端礼貌拒绝。
    判定权仍在服务端，这里只是提前拦。 */
const fmtBytes = n => n < 1024 ? n + ' B'
  : n < 1048576 ? (n / 1024).toFixed(1) + ' KB'
  : (n / 1048576).toFixed(1) + ' MB';
function tooBig(file){
  if (!file || file.size <= MAX_BYTES) return '';
  return '这个文件 ' + fmtBytes(file.size) + '，超过上限 ' + fmtBytes(MAX_BYTES)
       + '。本工具面向**单条请求**，不是整个流量包：请先从抓包里切出目标请求再拖进来。';
}

/* ---------- 载入领域（矩阵扫描面板用） ---------- */
let DOMAINS = [];
fetch('/api/domains').then(r => r.json()).then(d => {
  DOMAINS = d.domains || [];
  const opts = DOMAINS.map(x =>
    `<option value="${esc(x.name)}">${esc(x.name)}（${x.impls} 实现 · ${x.pairs} 对轴）</option>`).join('');
  const scanDomainSel = $('#scan-domain');
  if (scanDomainSel) scanDomainSel.innerHTML = opts;
}).catch(() => {});

function obsTable(observations, diffKeys, leftLabel, rightLabel){
  const keys = new Set(diffKeys || []);
  const rows = Object.entries(observations || {}).map(([k, v]) => {
    const d = keys.has(k) ? ' class="diff"' : '';
    const vals = Array.isArray(v) ? v : [v, ''];
    return `<tr${d}><td>${esc(k)}</td><td>${esc(JSON.stringify(vals[0]))}</td>` +
           `<td>${esc(JSON.stringify(vals[1]))}</td></tr>`;
  }).join('');
  return `<table><tr><th>观测字段</th><th>${esc(leftLabel)}</th>` +
         `<th>${esc(rightLabel)}</th></tr>${rows}</table>`;
}

function renderFinding(r){
  const mini = r.minimized_repr
    ? `<div class="kv"><span class="k">最小复现</span>${r.payload_len} → ${r.minimized_len} 字节</div>
       <pre>${esc(r.minimized_repr)}</pre>` : '';

  return `<div class="finding ${r.level === 'security' ? '' : 'unknown'}">
    <h3>${esc(r.left)} ↔ ${esc(r.right)}
        <span class="badge ${esc(r.level)}">${esc(r.level)}</span>
        <span style="color:var(--dim);font-weight:400;font-size:12px">（${esc(r.kind)}）</span></h3>
    ${obsTable(r.observations, r.diff_keys, r.left, r.right)}
    <div class="kv"><span class="k">判定理由</span>${esc(r.reason)}</div>
    ${r.ablation ? `<div class="kv"><span class="k">消融证据</span>${esc(r.ablation)}</div>` : ''}
    ${r.cwe ? `<div class="kv"><span class="k">CWE</span>${esc(r.cwe)}
        ${r.scenario ? '　场景 <b>' + esc(r.scenario) + '</b>' : ''}</div>` : ''}
    <div class="kv"><span class="k">安全后果</span>${esc(r.effect)}</div>
    <div class="kv"><span class="k">修复建议</span>${esc(r.fix)}</div>
    ${mini}
  </div>`;
}

/* ---------- 内置案例 ---------- */
fetch('/api/cases').then(r => r.json()).then(d => {
  $('#casecount').textContent = d.cases.length;
  $('#caselist').innerHTML = d.cases.map(c =>
    `<div class="caseitem" data-id="${esc(c.id)}">
       <div class="id">${esc(c.id)}</div>
       <div class="meta">${esc(c.axis)}　${c.payload_len} 字节</div>
     </div>`).join('');
  document.querySelectorAll('.caseitem').forEach(el => el.onclick = () => {
    document.querySelectorAll('.caseitem').forEach(x =>
      x.classList.toggle('sel', x === el));
    loadCase(el.dataset.id);
  });
}).catch(() => {});

async function loadCase(id){
  const box = $('#casedetail');
  box.innerHTML = '加载中…';
  let d;
  try {
    d = await (await fetch('/api/case?id=' + encodeURIComponent(id))).json();
  } catch (err) {
    return box.innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
  }
  if (d.error) return box.innerHTML = '<div class="err">' + esc(d.error) + '</div>';
  const c = d.case, r = d.result;
  box.innerHTML = `
    <div class="kv"><span class="k">案例</span><b>${esc(c.id)}</b></div>
    <div class="kv"><span class="k">分歧轴</span>${esc(c.axis)}</div>
    <div class="kv"><span class="k">对照</span>${esc(c.left)} ↔ ${esc(c.right)}</div>
    <div class="kv"><span class="k">出处</span>${esc(c.reference || '—')}</div>
    <div class="kv"><span class="k">说明</span>${esc(c.note || '—')}</div>
    <div class="kv"><span class="k">回归</span>
      <b class="${d.regression.passed ? 'ok' : 'no'}">
      ${d.regression.passed ? 'PASS' : 'FAIL'}</b>　${esc(d.regression.detail)}</div>
    <div class="kv" style="margin-top:10px"><span class="k">原始字节</span></div>
    <pre>${esc(d.payload_repr)}</pre>
    ${r.diverged ? renderFinding(r) : '<div class="note">两侧理解一致</div>'}`;
}

/* ---------- 失败原因要讲清楚 ---------- */
/* 三类失败处置完全不同，混成一句「请求失败」会让人以为是程序算错：
     ① 连不上（服务停了 / 浏览器或系统代理还指着已停止的自动捕获端口）
     ② HTTP 4xx/5xx（服务端拒绝了，响应体里有原因）
     ③ 返回不是 JSON（老版本服务端异常时回一页 HTML —— 现在服务端也回 JSON 了）
   服务端配套：ced/web/server.py 的 _fail()。 */
function fetchFailReason(err){
  const s = String(err);
  if (/Failed to fetch|NetworkError|Load failed|ERR_CONNECTION|ERR_PROXY|ERR_EMPTY|ERR_NAME/.test(s))
    return '连不上本机服务 —— 请求根本没到服务端。检查启动它的那个窗口还在不在；'
         + '若浏览器 / 系统代理曾被指向「自动捕获」的端口（默认 18081），停止捕获后要改回去，'
         + '否则本页所有请求都会失败。原始错误：' + s;
  return s;
}
function fetchFailText(err){ return '请求失败：' + fetchFailReason(err); }
function fetchFailHint(err){ return esc('请求失败：' + fetchFailReason(err)); }
/** 统一走这里取 JSON：HTTP 状态与响应体都带进错误信息，别再只报「请求失败」。 */
async function apiJson(url, opts){
  const resp = await fetch(url, opts);
  const text = await resp.text();
  if (!resp.ok){
    let detail = text.slice(0, 400);
    try { const j = JSON.parse(text); detail = j.error || j.detail || detail; } catch (e) {}
    throw new Error('HTTP ' + resp.status + '：' + detail);
  }
  try { return JSON.parse(text); }
  catch (e) { throw new Error('返回不是 JSON（HTTP ' + resp.status + '）：' + text.slice(0, 200)); }
}

/* ---------- 自检 ---------- */
$('#runchk').onclick = async () => {
  const box = $('#checkresult');
  box.innerHTML = '跑中…';
  $('#runchk').disabled = true;
  let d;
  try {
    d = await apiJson('/api/regression', {method:'POST'});
    if (d.error) throw new Error(d.error);
  } catch (err) {
    box.innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
    $('#runchk').disabled = false;
    return;
  }
  const ok = d.passed === d.total;
  box.innerHTML = `<div class="summary">
      <span><span class="k">结果</span>
        <b class="${ok?'good':'bad'}">${d.passed}/${d.total} 通过</b></span></div>` +
    d.items.map(i => `<div class="checkitem">
        <b class="${i.passed?'ok':'no'}">${i.passed?'PASS':'FAIL'}</b>
        ${esc(i.name)}　<span style="color:var(--dim)">${esc(i.detail)}</span></div>`).join('');
  $('#runchk').disabled = false;
};

/* ================= 扫描控制台 ================= */
const LEVEL_RANK = {security:0, unknown:1, compatibility:2};
const LEVEL_LABEL = {security:'安全级', unknown:'待复核', compatibility:'兼容性'};
const STATE_LABEL = {pending:'排队中', running:'运行中', done:'已完成',
                     failed:'失败', aborted:'已中止'};
function levelLabel(l){ return LEVEL_LABEL[l] || l || '未知'; }
function stateLabel(s){ return STATE_LABEL[s] || s || '—'; }
function numOr(el, dflt){
  const v = parseInt(el.value, 10);
  return isFinite(v) ? v : dflt;
}
function cmpFinding(a, b){
  const la = LEVEL_RANK[a.level] == null ? 3 : LEVEL_RANK[a.level];
  const lb = LEVEL_RANK[b.level] == null ? 3 : LEVEL_RANK[b.level];
  if (la !== lb) return la - lb;
  const ca = a.controllable ? 1 : 0, cb = b.controllable ? 1 : 0;
  if (ca !== cb) return cb - ca;
  return String(a.case_id).localeCompare(String(b.case_id));
}

let scanES = null, scanJobId = '', scanFindings = [], scanSel = null, scanPocs = {};
let scanClusters = [], scanRedundancy = 1;   // 同类归并：同一对实现 + 同一分歧类型只留一条代表

function scanErr(msg){
  const box = $('#scan-err');
  if (box) box.innerHTML = '<div class="err">' + esc(msg) + '</div>';
}
function scanLog(text, kind){
  const box = $('#scan-log');
  if (!box) return;
  const line = document.createElement('div');
  line.className = 'l' + (kind === true ? ' ok' : kind === false ? ' no' : '');
  line.textContent = text;
  box.appendChild(line);
  while (box.childElementCount > 200) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}
function closeScanES(){
  if (scanES){ scanES.close(); scanES = null; }
}
function setScanProgress(p){
  const done = p.done == null ? 0 : p.done;
  const total = p.total == null ? 0 : p.total;
  const pct = total > 0 ? Math.round(done / total * 100) : 0;
  $('#scan-bar').style.width = pct + '%';
  $('#scan-prog').textContent = done + ' / ' + total + ' 组用例';
  if (p.cases != null) $('#scan-cases').textContent = p.cases;
  if (p.divergences != null) $('#scan-div').textContent = p.divergences;
  if (p.security != null) $('#scan-sec').textContent = p.security;
  if (p.elapsed != null) $('#scan-elapsed').textContent = Number(p.elapsed).toFixed(1);
}

function handleScanEvent(d){
  if (d.type === 'stage'){
    $('#scan-stage').textContent = d.stage + (d.detail ? ' — ' + d.detail : '');
    scanLog('[' + d.stage + '] ' + (d.detail || ''));
  } else if (d.type === 'progress'){
    setScanProgress(d);
  } else if (d.type === 'done'){
    closeScanES();
    $('#scan-stage').textContent = '结束：' + stateLabel(d.state);
    $('#scan-abort').disabled = true;
    $('#scan-go').disabled = false;
    $('#scan-hint').textContent = '任务 ' + scanJobId + ' ' + stateLabel(d.state);
    scanLog('任务结束：' + stateLabel(d.state));
    loadScanResult(scanJobId);
    loadScanJobs();
  } else if (d.type === 'error'){
    closeScanES();
    scanLog('错误：' + d.text, false);
    scanErr(d.text);
    $('#scan-abort').disabled = true;
    $('#scan-go').disabled = false;
  }
}

function subscribeScan(jobId){
  closeScanES();
  const es = new EventSource('/api/scan/events?job_id=' + encodeURIComponent(jobId));
  scanES = es;
  es.onmessage = ev => {
    let d;
    try { d = JSON.parse(ev.data); } catch (e) { return; }
    handleScanEvent(d);
  };
  es.onerror = () => {
    if (scanES === es && es.readyState === 2){
      scanLog('事件流已断开', false);
    }
  };
}

$('#scan-go').onclick = async () => {
  if (scanES) return;
  $('#scan-err').innerHTML = '';
  $('#scan-go').disabled = true;
  const body = {
    domain: $('#scan-domain') ? $('#scan-domain').value : 'http1-framing',
    mode: $('#scan-mode').value,
    limit: numOr($('#scan-limit'), 60),
    seed: numOr($('#scan-seed'), 42),
    topology: $('#scan-topology').value.trim()
  };
  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const d = await res.json();
    if (d.error){
      scanErr(d.error);
      $('#scan-go').disabled = false;
      return;
    }
    scanJobId = d.job_id;
    scanFindings = []; scanSel = null; scanPocs = {};
    $('#scan-bar').style.width = '0%';
    $('#scan-prog').textContent = '0 / 0 组用例';
    $('#scan-log').innerHTML = '';
    $('#scan-hint').textContent = '任务 ' + d.job_id + ' 运行中';
    $('#scan-abort').disabled = false;
    scanLog('已启动任务 ' + d.job_id);
    subscribeScan(d.job_id);
  } catch (err) {
    scanErr(fetchFailText(err));
    $('#scan-go').disabled = false;
  }
};

$('#scan-abort').onclick = async () => {
  if (!scanJobId) return;
  $('#scan-abort').disabled = true;
  try {
    const res = await fetch('/api/scan/abort', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({job_id: scanJobId})
    });
    const d = await res.json();
    scanLog(d.ok ? '已发送中止请求' : ('中止失败：' + (d.error || '')), d.ok);
  } catch (err) {
    scanLog('中止请求失败：' + err, false);
  }
};

$('#scan-group').onchange = () => renderScanEvList();

async function loadScanJobs(){
  const box = $('#scan-jobs');
  box.innerHTML = '<div class="note">加载中…</div>';
  try {
    const res = await fetch('/api/scan/jobs');
    const d = await res.json();
    if (d.error){ box.innerHTML = '<div class="err">' + esc(d.error) + '</div>'; return; }
    const jobs = d.jobs || [];
    $('#jobs-count').textContent = jobs.length;
    if (!jobs.length){ box.innerHTML = '<div class="note">暂无扫描任务</div>'; return; }
    box.innerHTML = '<table><tr><th>任务号</th><th>状态</th><th>用例</th>' +
      '<th>分歧</th><th>安全级</th><th></th></tr>' + jobs.map(j => {
        const c = j.live ? ' class="clickable"' : '';
        const n = v => v == null ? '—' : v;
        return `<tr${c} data-id="${esc(j.job_id)}">
          <td>${esc(j.job_id)}</td>
          <td>${esc(stateLabel(j.state))}</td>
          <td>${n(j.total_cases)}</td>
          <td>${n(j.n_divergence)}</td>
          <td>${n(j.n_security)}</td>
          <td class="note">${j.live ? '' : '结果已不在内存'}</td></tr>`;
      }).join('') + '</table>';
    box.querySelectorAll('tr.clickable').forEach(tr => tr.onclick = () => {
      $('#scan-hint').textContent = '载入任务 ' + tr.dataset.id;
      loadScanResult(tr.dataset.id);
    });
  } catch (err) {
    box.innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
  }
}

async function loadScanResult(jobId){
  if (!jobId) return;
  const box = $('#scan-evidence');
  box.className = 'note';
  box.innerHTML = '加载结果…';
  try {
    const res = await fetch('/api/scan/result?job_id=' + encodeURIComponent(jobId));
    const d = await res.json();
    if (d.error){ box.innerHTML = '<div class="err">' + esc(d.error) + '</div>'; return; }
    const r = d.result || {};
    scanFindings = (r.findings || []).slice().sort(cmpFinding);
    scanSel = null;
    scanPocs = {};
    scanClusters = r.clusters || [];
    scanRedundancy = r.redundancy || 1;
    (r.pocs || []).forEach(p => { scanPocs[p.case_id] = p; });
    renderScanEvList();
    renderScanEvidence(null);
    loadScanMetrics(jobId);
    loadScanHeatmap(jobId);
  } catch (err) {
    box.innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
  }
}

/* ---------- 指标卡片 ---------- */
function metricCard(label, value, hint){
  return `<div class="statcard" title="${esc(hint)}">
    <div class="v">${value}</div><div class="k">${esc(label)}</div></div>`;
}
function metricPct(v){
  return (v == null || isNaN(v)) ? '—' : (Number(v) * 100).toFixed(1) + '%';
}
async function loadScanMetrics(jobId){
  const box = $('#scan-metrics');
  if (!box) return;
  box.innerHTML = '<div class="note">加载中…</div>';
  try {
    const res = await fetch('/api/scan/metrics?job_id=' + encodeURIComponent(jobId));
    const d = await res.json();
    if (d.error){ box.innerHTML = '<div class="err">' + esc(d.error) + '</div>'; return; }
    const m = d.metrics || {};
    const iv = v => esc(String(v == null ? 0 : v));
    const avg = m.avg_seconds_per_case == null
      ? '—' : esc(String(m.avg_seconds_per_case)) + ' 秒';
    box.innerHTML =
      metricCard('用例数', iv(m.total_cases), '本次扫描实际执行的候选用例数') +
      metricCard('实现对', iv(m.jobs), '实际比对的实现组合数（axis 模式 = 定向轴 + 未覆盖实现的交叉对照）') +
      metricCard('分歧数', iv(m.divergences), '同一份字节两侧结构理解不一致的条数（分级判定前的原始差分）') +
      metricCard('安全级', iv(m.security), '分歧中由攻击者可控字节承载、具备安全影响结构性前提的条数') +
      metricCard('安全占比', metricPct(m.security_share), 'security 级发现 / 分歧总数') +
      metricCard('消融定位率', metricPct(m.controllable_rate), 'security 级发现中通过消融实验定位到承载字节的比例') +
      metricCard('唯一化压缩比', metricPct(m.unique_case_ratio), '唯一 case_id 数 / 分歧数，反映同一份字节的重复计入程度') +
      metricCard('最小化压缩比', metricPct(m.minimize_ratio), '最小化后字节数 / 原始字节数（仅统计已最小化发现），数值越低样本越精炼') +
      metricCard('单用例平均耗时', avg, '总用时 / 用例数，反映扫描吞吐；无用例时不显示');
  } catch (err) {
    box.innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
  }
}

/* ---------- 交叉矩阵热力图 ---------- */
const HEAT_RGB = {security:[217,59,59], unknown:[200,129,26], compatibility:[107,116,128]};

function heatCellStyle(cell, max){
  const n = cell.count || 0;
  if (!n) return 'background:#fff';
  const rgb = HEAT_RGB[cell.level] || HEAT_RGB.compatibility;
  const t = max > 0 ? Math.min(1, n / max) : 1;
  return `background:rgba(${rgb[0]},${rgb[1]},${rgb[2]},${(0.14 + 0.6 * t).toFixed(3)})`;
}
function renderHeatmap(d){
  const impls = d.impls || [], cells = d.cells || [], max = d.max || 1;
  let h = '<table class="heat"><tr><th>左 \\ 右</th>' +
    impls.map(x => `<th>${esc(x)}</th>`).join('') + '</tr>';
  impls.forEach((rowName, i) => {
    h += `<tr><th>${esc(rowName)}</th>`;
    impls.forEach((colName, j) => {
      const c = ((cells[i] || [])[j]) || {count:0};
      const ids = (c.case_ids || []).join('、');
      const title = c.count
        ? [c.kind || '未分类', ids].filter(Boolean).join('：')
        : '无分歧';
      const cls = (c.count || c.level) ? '' : ' class="diag"';
      h += `<td${cls} style="${heatCellStyle(c, max)}" title="${esc(title)}">` +
           `${esc(String(c.count || 0))}</td>`;
    });
    h += '</tr>';
  });
  h += '</table><div class="note">读法：格子越深，这对实现在同一份字节上的结构分歧越多；' +
       '红=安全级（可衍生请求走私）。对角线为空。</div>';
  return h;
}
async function loadScanHeatmap(jobId){
  const box = $('#scan-heatmap');
  if (!box) return;
  box.innerHTML = '<div class="note">加载中…</div>';
  try {
    const res = await fetch('/api/scan/heatmap?job_id=' + encodeURIComponent(jobId));
    const d = await res.json();
    if (d.error){ box.innerHTML = '<div class="err">' + esc(d.error) + '</div>'; return; }
    box.innerHTML = renderHeatmap(d);
  } catch (err) {
    box.innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
  }
}

/* 同类归并：同一对实现 + 同一分歧类型 = 同一类事实，只留后端选出的那条代表。
   键与后端 ced/report/cluster.py 完全一致（左, 右, kind），代表用 case_id 对齐。 */
function clusterMap(){
  const m = {};
  scanClusters.forEach(c => { m[c.left + '\u0000' + c.right + '\u0000' + c.kind] = c; });
  return m;
}
function clusterOf(f, map){
  return map[f.left + '\u0000' + f.right + '\u0000' + f.kind];
}
function grouping(){
  const box = $('#scan-group');
  return !!(box && box.checked && scanClusters.length);
}

function filteredFindings(){
  const filt = $('#scan-filter').value;
  const q = $('#scan-search').value.trim().toLowerCase();
  let items = scanFindings.filter(f => {
    if (filt === 'security' && f.level !== 'security') return false;
    if (!q) return true;
    const hay = [f.case_id, f.left, f.right, f.kind, f.axis]
      .map(v => String(v == null ? '' : v).toLowerCase()).join(' ');
    return hay.indexOf(q) >= 0;
  });
  if (grouping()){
    const map = clusterMap();
    items = items.filter(f => { const c = clusterOf(f, map); return !!c && c.case_id === f.case_id; });
  }
  return items;
}

function renderScanEvList(){
  const items = filteredFindings();
  const map = clusterMap();
  const on = grouping();
  $('#scan-count').textContent = on
    ? items.length + ' 类 / 共 ' + scanFindings.length + ' 条'
      + '（同一类事实只列一条代表，冗余 ' + scanRedundancy + '×）'
    : items.length + ' 条 / 共 ' + scanFindings.length + ' 条';
  const box = $('#scan-evlist');
  if (!items.length){
    box.innerHTML = '<div class="note" style="padding:12px">没有匹配的发现</div>';
    return;
  }
  box.innerHTML = items.map(f => {
    const i = scanFindings.indexOf(f);
    const sel = scanSel && scanSel.case_id === f.case_id ? ' sel' : '';
    const c = clusterOf(f, map);
    const times = (c && c.count > 1)
      ? ` <span class="badge" title="同一对实现 + 同一分歧类型共 ${c.count} 条，这里只列代表">×${c.count}</span>`
      : '';
    return `<div class="evitem${sel}" data-i="${i}">
      <div class="id">${esc(f.case_id)}
        <span class="badge ${esc(f.level)}">${esc(levelLabel(f.level))}</span>${times}</div>
      <div class="meta">${esc(f.axis)}　${esc(f.left)} ↔ ${esc(f.right)}</div>
      <div class="meta">${esc(f.kind)}${f.controllable ? '　<span class="bad">可控</span>' : ''}</div>
    </div>`;
  }).join('');
  box.querySelectorAll('.evitem').forEach(el => el.onclick = () => {
    scanSel = scanFindings[parseInt(el.dataset.i, 10)];
    renderScanEvList();
    renderScanEvidence(scanSel);
  });
}

function renderScanEvidence(f){
  const box = $('#scan-evidence');
  if (!f){
    box.className = 'note';
    box.innerHTML = '← 请选择左侧发现条目';
    return;
  }
  box.className = '';
  const diffKeys = Object.keys(f.diffs || {});
  const obs = (f.observations && Object.keys(f.observations).length) ? f.observations : (f.diffs || {});
  let h = `<div class="finding ${f.level === 'security' ? '' : 'unknown'}">
    <h3>${esc(f.case_id)}
      <span class="badge ${esc(f.level)}">${esc(levelLabel(f.level))}</span>
      <span style="color:var(--dim);font-weight:400;font-size:12px">（${esc(f.kind)}）</span></h3>
    <div class="kv"><span class="k">对照</span>${esc(f.left)} ↔ ${esc(f.right)}
      　<span class="k">分歧轴</span>${esc(f.axis)}</div>
    <div class="kv"><span class="k">可控</span>${f.controllable
      ? '<span class="bad">是（攻击者可直接发送）</span>' : '否'}</div>
    <div class="boundary">已证实 · 内核产出</div>`;

  /* 同类归并说明 —— 这条代表着一整类事实，别让它看起来像孤例 */
  const cls = clusterOf(f, clusterMap());
  if (cls && cls.count > 1){
    h += `<div class="note" style="margin-top:8px">同类归并：同一对实现 + 同一分歧类型共
      <b>${cls.count}</b> 条，本条是代表（其余同类样本见报告 JSON / 结果库）</div>`;
  }

  /* 双侧观测表 */
  h += `<div class="sect"><div class="note"><b>双侧观测</b></div>`;
  h += obsTable(obs, diffKeys, f.left, f.right);
  h += `</div>`;

  /* 消融证据 */
  h += `<div class="sect"><div class="note"><b>消融证据</b></div>`;
  h += f.ablation
    ? `<div class="kv">${esc(f.ablation)}</div>
       <div class="note">→ 该分歧由攻击者可直接发送的字节承载</div>`
    : `<div class="kv warn">未知（未定位到可控承载）</div>`;
  h += `</div>`;

  /* 判定 */
  h += `<div class="sect"><div class="note"><b>判定</b></div>
    <div class="kv"><span class="k">判定理由</span>${esc(f.reason)}</div>
    <div class="kv"><span class="k">安全后果</span>${esc(f.effect)}</div>
    <div class="kv"><span class="k">CWE</span>${esc(f.cwe || '—')}</div>
    <div class="kv"><span class="k">场景</span>${esc(f.scenario || '—')}</div>
    <div class="kv"><span class="k">修复建议</span>${esc(f.fix)}</div>
  </div>`;

  /* 最小复现样本 */
  h += `<div class="sect"><div class="note"><b>最小复现样本</b></div>`;
  if (f.minimized_repr){
    h += `<div class="kv">${f.original_len} → ${f.minimized_len} 字节</div>
      <pre>${esc(f.minimized_repr)}</pre>`;
  } else {
    h += `<div class="kv">${f.original_len} 字节　<span class="note">未最小化</span></div>
      <pre>${esc(f.payload_repr)}</pre>`;
  }
  h += `</div>`;

  /* 链路量化（各领域口径不同：分帧=被夹带字节数，路径=资源错位） */
  h += `<div class="sect"><div class="note"><b>链路量化（前置 → 后端）</b></div>
    <div class="kv">${f.chain_evidence ? esc(f.chain_evidence) : '—'}</div></div>`;

  /* 攻击场景与端到端 PoC —— 属"已证实"栏：量化由领域模型算出，不是模型说的 */
  const poc = scanPocs[f.case_id];
  if (poc){
    h += `<div class="sect"><div class="note"><b>攻击场景与复现步骤</b></div>
      <div class="kv"><b>${esc(poc.title)}</b>　<span class="note">${esc(poc.scenario)}　CWE ${esc(poc.cwe || '—')}</span></div>`;
    if (poc.quant && poc.quant.verified){
      const q = poc.quant;
      const vals = Object.entries(q.values || {})
        .filter(([k]) => k !== 'front' && k !== 'back')
        .map(([k, v]) => `<span class="k">${esc(k)}</span><b>${esc(v)}</b>`).join('　');
      h += `<div class="kv"><span class="k">${esc(q.label)}</span>${vals}</div>`;
      h += `<div class="kv">${esc(q.describe)}</div>`;
    } else {
      h += `<div class="kv warn">无法量化（两侧含非本地实现，或本机算不出）—— 需在真实拓扑上复现</div>`;
    }
    h += `<div class="kv"><span class="k">影响</span>${esc(poc.impact)}</div>`;
    h += `<ol style="margin:8px 0 0 18px;padding:0">` +
         (poc.steps || []).map(s => `<li>${esc(s)}</li>`).join('') + `</ol>`;
    h += `<div class="kv"><span class="k">脚本</span><code>${esc(poc.file_name)}</code>
      <span class="note">（已写入结果目录；离线算字节账，加 --send HOST:PORT --i-am-authorized 可真发）</span></div>`;
    h += `<details><summary class="note">展开可执行 PoC 脚本</summary>
      <pre>${esc(poc.script || '')}</pre></details>`;
    h += `</div>`;
  }

  h += `</div>`;
  box.innerHTML = h;
}

/* ================= 模型状态 ================= */
let assistAvailable = false;

/* 侧栏左下角显示模型状态 —— 解读依赖它，别让人跑完才发现没配 */
function setAssistLine(html){
  const line = document.getElementById('assist-status');
  if (line) line.innerHTML = html;
}

async function loadAssistStatus(){
  try {
    const res = await fetch('/api/assist/status');
    const d = await res.json();
    assistAvailable = !!d.available;
    const dtLlm = $('#dt-llm');          // 注意：这里的 el() 是另一个闭包里的，用 $ 取
    if (dtLlm){
      dtLlm.disabled = !assistAvailable;      // 没配模型就别让人勾了个永远不生效的框
      dtLlm.parentElement.title = assistAvailable
        ? '检测完成后让模型把证据翻译成人话；判定字段不受影响'
        : '未配置模型（在「设置…」里填 base_url 与 model 后可用）；不影响检测本身';
    }
    setAssistLine(assistAvailable
      ? '<b>' + esc(d.model || '模型已配置') + '</b>｜可用'
      : '<span class="warn">模型未配置</span>');
  } catch (err) {
    assistAvailable = false;
    const dtLlm = $('#dt-llm');
    if (dtLlm) dtLlm.disabled = true;
    setAssistLine('<span class="warn">模型状态检查失败</span>');
  }
}

/* ================= 单页钩子 ================= */
/* ---------- 单页结构：标签页已去掉 ----------
   扫描任务列表开页就加载。 */
loadScanJobs();
/* 模型状态开页就查一次：侧栏左下角要显示它，检测页的「使用模型解读」也要按它决定能不能勾 */
loadAssistStatus();
/* 「设置…」小窗：原生 dialog，控件沿用原 id，既有读写逻辑一行没动 */
function openSettings(){
  const dlg = $('#set-dlg');
  if (typeof dlg.showModal === 'function') dlg.showModal();
  else dlg.setAttribute('open', '');
  loadAssistStatus();
}
$('#set-open').onclick = openSettings;
$('#set-dlg-x').onclick = () => $('#set-dlg').close();
$('#set-dlg-close').onclick = () => $('#set-dlg').close();

/* ===== 单一入口：检测（自动识别 + 自动编排 + DAG + 实时报告）与设置 ===== */
(function(){
  const el = id => document.getElementById(id);
  const NODES = [["identify","识别输入"],["extract","按领域取段"],["diff","逐对差分"],
                 ["judge","消融判定"],["poc","升级 / PoC"],["report","出报告"]];
  let es = null, lines = [], findings = [], lastReport = "";

  function initDag(){
    el('dt-dag').innerHTML = NODES.map((pair, i) =>
      (i ? '<span class="arrow">→</span>' : '') +
      `<div class="node" data-node="${pair[0]}"><div class="t"><span class="dot"></span>${esc(pair[1])}</div><div class="s">待运行</div></div>`
    ).join('');
  }
  let chainStart = 0, ticker = null;
  function setChain(state, text){
    const box = el('dt-chain');
    box.className = 'state ' + state;
    box.textContent = text;
    const fs = el('dt-flow-s');
    if (fs) fs.textContent = text;         // 收起时标题行也要能看出跑到哪一步了
  }
  function startTicker(){
    chainStart = Date.now();
    if (ticker) clearInterval(ticker);
    ticker = setInterval(() => {
      el('dt-elapsed').textContent = '已用 ' + ((Date.now() - chainStart) / 1000).toFixed(1) + ' 秒';
    }, 200);
  }
  function stopTicker(){
    if (ticker){ clearInterval(ticker); ticker = null; }
    if (chainStart){
      const ms = Date.now() - chainStart;
      el('dt-elapsed').textContent = '用时 '
        + (ms < 1000 ? ms + ' 毫秒' : (ms / 1000).toFixed(1) + ' 秒');
    }
  }
  function setNode(node, state, detail){
    const box = el('dt-dag').querySelector(`.node[data-node="${node}"]`);
    if (!box) return;
    box.classList.toggle('running', state === 'running');
    box.classList.toggle('done', state === 'done');
    if (detail){
      const text = String(detail);
      const short = text.length > 22 ? text.slice(0,22) + '…' : text;
      const sub = box.querySelector('.s');
      sub.textContent = short;
      box.title = text;                 // 截断了就靠悬浮补全，别丢信息
      el('dt-dag-detail').textContent = node + '：' + text;
      // 流程收起时，标题行跟着显示当前阶段 —— 收起也能看出跑到哪了
      if (state === 'running'){
        const fs = el('dt-flow-s');
        if (fs) fs.textContent = text;
      }
    }
  }
  function badge(f){
    if (f.verdict){
      return {confirmed:'<span class="badge security">已证实</span>',
              refuted:'<span class="badge compatibility">未证实</span>',
              unverifiable:'<span class="badge unknown">证不了</span>'}[f.verdict] || '';
    }
    return {security:'<span class="badge security">安全级</span>',
            unknown:'<span class="badge unknown">疑点</span>',
            compatibility:'<span class="badge compatibility">兼容性</span>'}[f.level] || '';
  }
  function titleOf(f){
    return f.domain ? (f.domain + '｜' + f.left + ' ↔ ' + f.right + '｜' + (f.kind || ''))
                    : (f.target || '');
  }
  function visibleFindings(){
    const mode = el('dt-filter').value;
    if (mode === 'all') return findings;
    const wanted = mode === 'flagged' ? ['security', 'confirmed']
                                      : ['unknown', 'unverifiable', 'refuted'];
    return findings.filter(f => wanted.indexOf(f.level || f.verdict) >= 0);
  }
  function renderLevels(){
    const counts = {};
    findings.forEach(f => {
      const key = f.level || f.verdict || '—';
      counts[key] = (counts[key] || 0) + 1;
    });
    const label = {security:'安全级', unknown:'疑点', compatibility:'兼容性',
                   confirmed:'已证实', refuted:'未证实', unverifiable:'证不了'};
    const cls = {security:'bad', confirmed:'bad', unknown:'warn', unverifiable:'warn',
                 refuted:'good', compatibility:''};
    el('dt-levels').innerHTML = Object.keys(counts).map(key =>
      `<span class="lv ${cls[key] || ''}">${esc(label[key] || key)} ${counts[key]}</span>`).join('');
  }
  function renderFindings(){
    renderLevels();
    const shown = visibleFindings();
    el('dt-count').textContent = findings.length
      ? (shown.length + ' / ' + findings.length + ' 条') : '0 条';
    const box = el('dt-list');
    if (!shown.length){
      box.innerHTML = findings.length
        ? '<div class="empty"><b>当前筛选下没有结果</b>请调整筛选条件</div>'
        : '<div class="empty"><b>暂无结果</b>请先点击「开始检测」</div>';
      return;
    }
    box.innerHTML = shown.map(f =>
      `<div class="evitem" data-i="${findings.indexOf(f)}"><div class="id">${esc(titleOf(f)).slice(0, 46)}</div>
        <div class="meta">${badge(f)}　${esc(String(f.kind || f.detail || '')).slice(0, 44)}</div></div>`
    ).join('');
    box.querySelectorAll('.evitem').forEach(node => node.onclick = () => {
      box.querySelectorAll('.evitem').forEach(x => x.classList.remove('sel'));
      node.classList.add('sel');
      showEvidence(findings[parseInt(node.dataset.i, 10)]);
    });
  }
  window.__dtLoad = arr => {                // 工作区侧栏：切换回某次检测的发现集合
    findings = arr; renderFindings();
    renderInterpret();
    foldFlow(!hasInterpret());               // 有解读就收起过程，没有就照常展开
    const rs = el('dt-reportcard-s');
    if (rs) rs.textContent = findings.length ? (findings.length + ' 条发现') : '无发现';
  };
  let shownFinding = null;
  function showEvidence(f){
    if (!f) return;
    shownFinding = f;
    let h = `<div class="kv"><span class="k">对象</span>${esc(titleOf(f))}</div>`;
    if (f.cwe) h += `<div class="kv"><span class="k">CWE</span>${esc(f.cwe)}　<span class="k">场景</span>${esc(f.scenario || '—')}</div>`;
    if (f.reason) h += `<div class="kv"><span class="k">判定理由</span>${esc(f.reason)}</div>`;
    if (f.ablation) h += `<div class="kv"><span class="k">消融证据</span>${esc(f.ablation)}</div>`;
    if (f.evidence) h += `<div class="kv"><span class="k">证据</span>${esc(f.evidence)}</div>`;
    if (f.detail) h += `<div class="kv"><span class="k">说明</span>${esc(f.detail)}</div>`;
    if (f.effect) h += `<div class="kv"><span class="k">安全后果</span>${esc(f.effect)}</div>`;
    if (f.fix) h += `<div class="kv"><span class="k">修复建议</span>${esc(f.fix)}</div>`;
    const interp = f.interpret;
    if (interp && interp.ok){
      h += `<div class="sect"><div class="note"><b>模型解读（非判定）</b>
        <span class="hint">${esc(interp.model || '模型')} 把已有证据翻译成人话，仅供参考</span></div>
        <div class="clue">
          <div class="kv"><span class="k">影响</span>${esc(interp.impact || '—')}</div>`
        + (interp.cwe_hint ? `<div class="kv"><span class="k">CWE 建议</span>${esc(interp.cwe_hint)}</div>` : '')
        + (interp.fix ? `<div class="kv"><span class="k">修复建议</span>${esc(interp.fix)}</div>` : '')
        + `<div class="note">上面是<b>模型的转述</b>，不是判定 —— 级别、CWE、证据仍以上面内核给出的为准。</div>
        </div></div>`;
    } else if (interp && interp.error){
      h += `<div class="sect"><div class="note"><b>模型解读</b>
        <span class="hint">未产出：${esc(interp.error)}　（不影响上面的判定）</span></div></div>`;
    }
    if (f.minimized_repr) h += `<pre>${esc(f.minimized_repr)}</pre>`;
    if (f.poc){
      h += `<div class="sect"><div class="note"><b>端到端 PoC｜${esc(f.poc.title || '')}</b></div>`;
      if (f.poc.chain_desc) h += `<div class="kv"><span class="k">链路</span>${esc(f.poc.chain_desc)}</div>`;
      if (f.poc.steps && f.poc.steps.length)
        h += `<div class="kv"><span class="k">复现步骤</span>${f.poc.steps.map(esc).join('　→　')}</div>`;
      if (f.poc.script) h += `<pre>${esc(f.poc.script)}</pre>`;
      h += `</div>`;
    } else if (f.level === 'security'){
      h += `<div class="note">该领域这条没生成 PoC（按口径只对 security 级生成）。</div>`;
    }
    const box = el('dt-evidence'); box.className = ''; box.innerHTML = h;
  }

  /* ---- 模型解读：采纳后它升为主内容，流程 / 报告自动收起 ----
     判定仍是内核给的；这里只是把「已定的证据」翻成人话摆到前面，
     让读者先看结论、再按需展开过程。 */
  function renderInterpret(){
    const sect = el('dt-interp'), body = el('dt-interp-body');
    if (!sect || !body) return;
    const items = findings.filter(f => f.interpret && f.interpret.ok);
    if (!items.length){ sect.hidden = true; body.innerHTML = ''; return; }
    body.innerHTML = items.map(f => {
      const it = f.interpret;
      return `<article class="interp-item">
        <div class="interp-q"><span class="qt">${esc(titleOf(f))}</span><span class="qb">${badge(f)}</span></div>
        <div class="interp-a">
          <p class="interp-lead">${esc(it.impact || '—')}</p>`
        + (it.cwe_hint ? `<div class="kv"><span class="k">CWE 建议</span>${esc(it.cwe_hint)}</div>` : '')
        + (it.fix ? `<div class="kv"><span class="k">修复建议</span>${esc(it.fix)}</div>` : '')
        + `<div class="interp-note">以上是<b>模型的转述</b>，不是判定 —— 级别、CWE 与证据仍以上面内核给出的为准。`
        + `模型：${esc(it.model || '—')}</div>
        </div></article>`;
    }).join('');
    sect.hidden = false;
  }
  function hasInterpret(){ return findings.some(f => f.interpret && f.interpret.ok); }
  function foldFlow(open){
    const flow = el('dt-flow'), rep = el('dt-reportcard');
    if (flow) flow.open = open;
    if (rep) rep.open = open;
  }
  function closeStream(){ if (es){ es.close(); es = null; } }
  function handle(ev){
    if (ev.type === 'stage'){
      setNode(ev.node, ev.state, ev.detail);
    } else if (ev.type === 'report'){
      lines.push(ev.line);
      const pre = el('dt-report');
      pre.textContent = lines.join('\n');
      pre.scrollTop = pre.scrollHeight;
    } else if (ev.type === 'finding'){
      findings.push(ev); renderFindings();
    } else if (ev.type === 'interpret'){
      const key = String(ev.key || '');
      const target = findings.find(f => String(f.case_id || f.target || '') === key);
      if (target){
        target.interpret = ev.interpret;
        renderFindings();
        if (shownFinding === target) showEvidence(target);   // 正在看这条就就地刷新
        renderInterpret();
        if (hasInterpret()) foldFlow(false);                 // 解读出来了就把过程收起来
      }
    } else if (ev.type === 'done'){
      closeStream(); renderFindings(); setChain('done', '已完成');
      stopTicker();
      if (ev.result && ev.result.report) lastReport = ev.result.report;
      el('dt-reportcard-s').textContent = findings.length
        ? (findings.length + ' 条发现') : '无发现';
      renderInterpret();
      if (hasInterpret()) foldFlow(false);
    } else if (ev.type === 'error'){
      el('dt-err').innerHTML = '<div class="err">' + esc(ev.error) + '</div>';
      setChain('error', '失败'); stopTicker();
      closeStream();
    }
  }
  async function go(){
    const text = exact ? latin1(exact) : el('dt-text').value;
    if (!text.trim()){
      el('dt-err').innerHTML = '<div class="err">先粘一份输入进来（或用下面的自动捕获）</div>';
      return;
    }
    el('dt-err').innerHTML = ''; lines = []; findings = []; lastReport = '';
    if (window.sideAddDetect) window.sideAddDetect(findings);
    checkMangled();
    el('dt-interp').hidden = true; el('dt-interp-body').innerHTML = '';
    el('dt-reportcard-s').textContent = '运行中…';
    foldFlow(true);                          // 新一轮先展开过程；解读出来再自动收起
    el('dt-report').textContent = ''; el('dt-list').innerHTML = '';
    el('dt-evidence').className = 'note'; el('dt-evidence').textContent = '← 请选择左侧条目';
    initDag(); renderFindings();
    setChain('running', '运行中'); el('dt-elapsed').textContent = ''; startTicker();
    const body = {text: text};
    // 解读是可选加法：勾了才让模型把证据翻译成人话（服务端还会再确认模型可用）
    if (el('dt-llm')) body.interpret = el('dt-llm').checked;
    const domain = el('dt-domain').value;
    if (domain) body.domains = [domain];
    try {
      const resp = await fetch('/api/detect', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      const info = await resp.json();
      if (info.error){
        el('dt-err').innerHTML = '<div class="err">' + esc(info.error).replace(/\n/g, '<br>') + '</div>';
        return;
      }
      el('dt-hint').textContent = '识别为 ' + info.kind + '：' + info.why;
      closeStream();
      es = new EventSource('/api/detect/events?job_id=' + encodeURIComponent(info.job_id));
      es.onmessage = m => { try { handle(JSON.parse(m.data)); } catch (e) { /* 半条消息忽略 */ } };
    } catch (err){
      el('dt-err').innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>';
    }
  }
  el('dt-go').onclick = go;
  el('dt-filter').onchange = renderFindings;
  el('dt-file-btn').onclick = () => el('dt-file').click();
  // textarea 的 value 会被浏览器规范化（CR 全被吃掉）—— 所以原始字节**另存一份**：
  // 文件按字节读进来之后，送检的是这份 exact，而不是文本框里的文本。
  let exact = null;
  function latin1(bytes){
    let text = '';
    for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
    return text;
  }
  el('dt-file').onchange = e => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const bad = tooBig(file);
    if (bad){ e.target.value = ''; el('dt-err').innerHTML = '<div class="err">' + esc(bad) + '</div>'; return; }
    el('dt-err').innerHTML = '';
    // 按**字节**读入：用 readAsText('utf-8') 会改掉非 ASCII 字节，等于自己造字节（本项目的红线）。
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result);
      exact = bytes;
      el('dt-text').value = latin1(bytes);      // 仅作显示
      el('dt-hint').textContent = '已按字节读入 ' + bytes.length + ' 字节：' + file.name
        + '（文本框仅用于显示，送检用的是原始字节）';
      checkMangled();
    };
    reader.readAsArrayBuffer(file);
  };
  function checkMangled(){
    if (exact){
      el('dt-warn').innerHTML = '<div class="alert alert-info">这份输入是按<b>字节</b>读入的（'
        + exact.length + ' 字节）：送检的就是原始字节，不会被规范化。</div>';
      return;
    }
    const text = el('dt-text').value;
    const first = (text.split('\n')[0] || '');
    const looksRequest = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) \S+ HTTP\/1\.[01]/.test(first);
    const mangled = looksRequest && text.indexOf('\n') >= 0 && text.indexOf('\r') < 0;
    el('dt-warn').innerHTML = mangled
      ? ('<div class="alert alert-warn">这份输入<b>只有 LF、没有 CR</b>：浏览器会把粘贴框里的 CRLF 规范化成 LF，'
         + '原始字节已不保真。要测真实字节，请改用「选择文件」（抓包导出的 .bin/.txt）或下面的「自动捕获」。'
         + '下面照实分析这份 LF 版本。</div>')
      : '';
  }
  el('dt-text').oninput = () => { exact = null; checkMangled(); };

  /* 拖文件到输入框（卡片上也写了"粘/拖"）：按字节读入，进 exact 缓冲 */
  const ta = el('dt-text');
  ['dragenter','dragover'].forEach(name => ta.addEventListener(name, ev => {
    ev.preventDefault(); ta.classList.add('drop-on');
  }));
  ['dragleave','drop'].forEach(name => ta.addEventListener(name, ev => {
    ev.preventDefault(); ta.classList.remove('drop-on');
  }));
  ta.addEventListener('drop', ev => {
    const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (!file) return;
    const bad = tooBig(file);
    if (bad){ el('dt-err').innerHTML = '<div class="err">' + esc(bad) + '</div>'; return; }
    el('dt-err').innerHTML = '';
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result);
      exact = bytes;
      ta.value = latin1(bytes);
      el('dt-hint').textContent = '已拖入 ' + bytes.length + ' 字节：' + file.name + '（按字节送检）';
      checkMangled();
    };
    reader.readAsArrayBuffer(file);
  });
  ta.addEventListener('keydown', ev => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter'){ ev.preventDefault(); go(); }
  });
  el('dt-download').onclick = () => {
    const text = lastReport || lines.join('\n');
    if (!text) return;
    const url = URL.createObjectURL(new Blob([text], {type: 'text/markdown;charset=utf-8'}));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'ced-report.md';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  };

  /* 载入示例：samples/ 下的样本按字节取回，同样进 exact 缓冲（原始请求要保真） */
  (async function fillSamples(){
    try {
      const data = await (await fetch('/api/samples')).json();
      (data.samples || []).forEach(item => {
        const opt = document.createElement('option');
        opt.value = item.name;
        opt.textContent = item.name + '（' + item.size + ' 字节）';
        el('dt-sample').appendChild(opt);
      });
    } catch (e) { /* 没有样本目录也不影响主流程 */ }
  })();
  el('dt-sample').onchange = async e => {
    const name = e.target.value;
    if (!name) return;
    const url = '/samples/' + name.split('/').map(encodeURIComponent).join('/');
    try {
      const bytes = new Uint8Array(await (await fetch(url)).arrayBuffer());
      exact = bytes;
      el('dt-text').value = latin1(bytes);
      el('dt-hint').textContent = '已载入示例：' + name + '（' + bytes.length + ' 字节，按字节送检）';
      checkMangled();
    } catch (err){
      el('dt-err').innerHTML = '<div class="err">载入示例失败：' + esc(err) + '</div>';
    }
  };
  el('dt-copy').onclick = async () => {
    try { await navigator.clipboard.writeText(lastReport || lines.join('\n')); el('dt-copy').textContent = '已复制'; }
    catch (e) { el('dt-copy').textContent = '复制失败'; }
    setTimeout(() => { el('dt-copy').textContent = '复制报告'; }, 1500);
  };
  initDag();

  (async function fillDomains(){
    try {
      const data = await (await fetch('/api/domains')).json();
      (data.domains || []).forEach(item => {
        [el('dt-domain'), el('set-scan-domain')].forEach(sel => {
          if (!sel || sel.querySelector('option[value="' + item.name + '"]')) return;
          const opt = document.createElement('option');
          opt.value = item.name;
          opt.textContent = item.name + '（' + item.impls + ' 实现）';
          sel.appendChild(opt);
        });
      });
    } catch (e) { /* 拿不到领域列表也不影响主流程 */ }
  })();

  /* ---------- 设置 ---------- */
  function fillSettings(s){
    el('set-llm-base').value = s.llm.base_url || '';
    el('set-llm-model').value = s.llm.model || '';
    el('set-llm-key').value = '';
    el('set-llm-keyhint').textContent = s.llm.api_key_set
      ? ('已保存：' + s.llm.api_key + '（留空 = 不改）') : '尚未设置';
    el('set-llm-timeout').value = s.llm.timeout;
    el('set-llm-temp').value = s.llm.temperature;
    el('set-llm-tokens').value = s.llm.max_tokens;
    el('set-cap-port').value = s.capture.port;
    el('set-cap-upstream').value = s.capture.upstream || '';
    el('set-cap-jsonl').value = s.capture.jsonl || '';
    el('set-cap-all').checked = !!s.capture.analyze_all;
    el('set-scan-domain').value = s.scan.domain;
    el('set-scan-mode').value = s.scan.mode;
    el('set-scan-limit').value = s.scan.limit;
    el('set-scan-seed').value = s.scan.seed;
    el('set-detect-llm').checked = !!(s.detect && s.detect.interpret);
    // 检测页那个勾选框按设置预填（解读默认关，勾了才会有模型那一段）
    el('dt-llm').checked = !!(s.detect && s.detect.interpret);
    el('set-poc-dir').value = s.paths.poc_dir;
    el('set-report-dir').value = s.paths.report_dir;
    el('set-state').textContent = '配置文件：' + s.path;
    // 捕获的默认值同步到检测页那几个控件（捕获在跑时不动，别把现场值盖了）
    if (el('cap-state').textContent.indexOf('运行中') !== 0){
      el('cap-port').value = s.capture.port;
      el('cap-all').checked = !!s.capture.analyze_all;
      el('cap-jsonl').value = s.capture.jsonl || '';
      el('cap-upstream').value = s.capture.upstream || '';
      const doms = s.capture.domains || [];
      el('cap-domain').value = doms.length === 1 ? doms[0] : '';
      if (window.refreshCapSummary) window.refreshCapSummary();
    }
    el('cap-default-hint').textContent = '默认值：端口 ' + s.capture.port
      + '，领域 ' + ((s.capture.domains || []).join(' / ') || '全部 5 个')
      + '，静态资源 ' + (s.capture.analyze_all ? '也分析' : '跳过')
      + (s.capture.jsonl ? ('，记录写 ' + s.capture.jsonl) : '，不写记录文件');
  }
  el('cap-save-default').onclick = async () => {
    const dom = el('cap-domain').value;
    const jsonl = el('cap-jsonl').value.trim();
    const payload = {capture: {port: parseInt(el('cap-port').value, 10) || 18081,
                               analyze_all: el('cap-all').checked,
                               jsonl: jsonl,
                               upstream: el('cap-upstream').value.trim(),
                               domains: dom ? [dom] : []}};
    try {
      const resp = await fetch('/api/settings', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      const info = await resp.json();
      if (info.error){
        el('cap-dlg-msg').innerHTML = '<span class="err">保存失败：' + esc(info.error) + '</span>';
        return;
      }
      fillSettings(info.settings);
      el('cap-dlg-msg').textContent = '已存为默认（端口 ' + payload.capture.port
        + '）；下次开页、服务端起捕获都用它';
    } catch (err){
      el('cap-dlg-msg').innerHTML = '<span class="err">保存失败：' + esc(err) + '</span>';
    }
  };
  async function loadSettings(){
    try { fillSettings(await (await fetch('/api/settings')).json()); }
    catch (e) { el('set-err').innerHTML = '<div class="err">读取设置失败：' + esc(e) + '</div>'; }
  }
  el('set-reload').onclick = loadSettings;
  el('set-save').onclick = async () => {
    el('set-err').innerHTML = '';
    const payload = {
      llm: {base_url: el('set-llm-base').value.trim(),
            model: el('set-llm-model').value.trim(),
            timeout: parseFloat(el('set-llm-timeout').value) || 60,
            temperature: parseFloat(el('set-llm-temp').value) || 0.3,
            max_tokens: parseInt(el('set-llm-tokens').value, 10) || 32768},
      capture: {port: parseInt(el('set-cap-port').value, 10) || 18081,
                jsonl: el('set-cap-jsonl').value.trim(),
                upstream: el('set-cap-upstream').value.trim(),
                analyze_all: el('set-cap-all').checked},
      detect: {interpret: el('set-detect-llm').checked},
      scan: {domain: el('set-scan-domain').value,
             mode: el('set-scan-mode').value,
             limit: parseInt(el('set-scan-limit').value, 10) || 60,
             seed: parseInt(el('set-scan-seed').value, 10) || 42},
      paths: {poc_dir: el('set-poc-dir').value.trim(),
              report_dir: el('set-report-dir').value.trim()}
    };
    const key = el('set-llm-key').value.trim();
    if (key) payload.llm.api_key = key;      // 留空 = 不改动已保存的密钥
    try {
      const resp = await fetch('/api/settings', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      const info = await resp.json();
      if (info.error){
        el('set-err').innerHTML = '<div class="err">' + esc(info.error).replace(/\n/g, '<br>') + '</div>';
        return;
      }
      fillSettings(info.settings);
      el('set-state').textContent = '已保存：' + info.settings.path;
    } catch (err){
      el('set-err').innerHTML = '<div class="err">保存失败：' + esc(err) + '</div>';
    }
  };
  loadSettings();
})();

/* ===== 自动捕获：起/停本机代理 + 实时列表 + 证据 + 一键出 PoC ===== */
(function(){
  const box = id => document.getElementById(id);
  let seq = 0, timer = null, rows = [], sel = null;

  function statCard(label, value, hint){
    return `<div class="statcard" title="${esc(hint)}"><div class="v">${value}</div><div class="k">${esc(label)}</div></div>`;
  }
  function renderStats(s){
    if (!s) return;
    box('cap-stats').innerHTML =
      statCard('请求', s.requests, '代理接收的请求总数（含重复）') +
      statCard('已分析', s.analyzed, '已完成差分检测的请求数') +
      statCard('跳过', s.skipped, '静态资源 / 分析队列饱和 / 无法提取观测对象') +
      statCard('HTTPS 隧道', s.tunnels, '未解密的 CONNECT 隧道（未启用本地证书解密，或客户端拒绝本地证书）') +
      statCard('分歧', s.divergences, '已分析请求的分歧总数（跨 5 个领域）') +
      statCard('安全级请求', s.security_requests, '存在 security 级分歧的请求数');
  }
  function verdictBadge(r){
    if (r.tunnel) return '<span class="badge">HTTPS 隧道</span>';
    if (r.skip) return '<span class="badge">跳过</span>';
    const a = r.analysis;
    if (!a) return '<span class="badge">分析中…</span>';
    if (a.security) return '<span class="badge security">安全级 ' + a.security + '</span>';
    if (a.divergences) return '<span class="badge unknown">疑点 ' + a.divergences + '</span>';
    return '<span class="badge compatibility">已检测·一致</span>';
  }
  function rowHtml(r){
    const times = r.count > 1 ? ` <span class="badge" title="同一份字节又来了">×${r.count}</span>` : '';
    const extra = r.tunnel ? '（未拆包）'
                : (r.skip ? esc(r.skip) : (r.elapsed_ms == null ? '分析中…' : r.elapsed_ms + 'ms'));
    const active = (sel && sel.case_id && sel.case_id === r.case_id) ? ' sel' : '';
    return `<div class="evitem${active}" data-case="${esc(r.case_id || '')}">
      <div class="id">${esc(r.method)} ${esc(r.host)}${esc(r.path || '')}${times}</div>
      <div class="meta">${verdictBadge(r)}　${extra}</div>
    </div>`;
  }
  function matchesFilter(r){
    const mode = (box('cap-filter') || {}).value || 'all';
    if (mode === 'security' && !(r.analysis && r.analysis.security)) return false;
    if (mode === 'divergent' && !(r.analysis && r.analysis.divergences)) return false;
    if (mode === 'skipped' && !(r.skip || r.tunnel)) return false;
    const query = ((box('cap-search') || {}).value || '').trim().toLowerCase();
    if (!query) return true;
    return [r.method, r.host, r.path, r.target].map(
      v => String(v == null ? '' : v).toLowerCase()).join(' ').indexOf(query) >= 0;
  }
  function renderList(){
    window.__capRows = rows;                 // 供工作区侧栏（检测历史）读取
    if (window.__sideSync) window.__sideSync();
    const list = box('cap-list');
    const hits = rows.filter(matchesFilter);
    const view = hits.slice(-200);
    list.innerHTML = view.map(rowHtml).join('') ||
      (rows.length ? '<div class="empty"><b>当前筛选下没有请求</b>请调整筛选条件</div>'
                   : '<div class="empty"><b>暂无请求</b>请确认客户端代理已指向本捕获端口</div>');
    list.querySelectorAll('.evitem').forEach(el => {
      el.onclick = () => {
        const found = rows.find(x => (x.case_id || '') === el.dataset.case);
        if (!found) return;
        sel = found;
        list.querySelectorAll('.evitem').forEach(x => x.classList.remove('sel'));
        el.classList.add('sel');
        detail(found.case_id);
      };
    });
    box('cap-count').textContent =
      (hits.length === rows.length ? '' : hits.length + ' / ') + rows.length + ' 条'
      + (hits.length > view.length ? '（只显示最近 200 条；完整记录在 JSONL 里）' : '');
    if (window.__sideSync) window.__sideSync();   // 侧栏（检测历史）跟着刷新
  }
  function evHtml(d){
    let h = `<div class="kv"><span class="k">请求</span>${esc(d.method)} ${esc(d.host)}${esc(d.path || '')}</div>`;
    h += `<div class="kv"><span class="k">原始长度</span>${d.raw_len} 字节`;
    if (d.normalized) h += `　<span class="note">分析用的是源站形式（代理形式的请求行已归一化）</span>`;
    h += `</div>`;
    const a = d.analysis;
    if (a){
      h += `<div class="sect"><div class="note"><b>各领域</b></div>`;
      Object.keys(a.domains).forEach(name => {
        const row = a.domains[name];
        h += `<div class="kv"><span class="k">${esc(name)}</span>对照 ${row.pairs} 对 · `
           + `分歧 ${row.divergences} · 安全级 ${row.security}`
           + (row.note ? `　<span class="badge">${esc(row.note)}</span>` : '') + `</div>`;
      });
      h += `</div>`;
    }
    const top = a && a.top;
    if (top){
      h += `<div class="sect"><div class="note"><b>最强的一条｜领域 ${esc(top.domain)}</b></div>
        <div class="kv"><span class="k">对照</span>${esc(top.left)} ↔ ${esc(top.right)}　<span class="k">类型</span>${esc(top.kind)}</div>
        <div class="kv"><span class="k">CWE</span>${esc(top.cwe || '—')}　<span class="k">场景</span>${esc(top.scenario || '—')}</div>
        <div class="kv"><span class="k">判定理由</span>${esc(top.reason)}</div>
        <div class="kv"><span class="k">消融证据</span>${esc(top.ablation || '—')}</div>
        <div class="kv"><span class="k">安全后果</span>${esc(top.effect || '—')}</div>
        <div class="kv"><span class="k">修复建议</span>${esc(top.fix || '—')}</div>
        <div class="boundary">已证实 · 内核产出</div>
        <div class="toolbar"><button class="btn btn-primary" id="cap-poc">生成端到端 PoC</button>
          <span class="note" id="cap-poc-out"></span></div>
        <div id="cap-poc-body"></div>
      </div>`;
    } else if (a){
      h += `<div class="note">这条请求在 5 个领域里都没有分歧 —— 按口径不生成 PoC。</div>`;
    }
    h += `<div class="sect"><div class="note"><b>留证的原始字节</b>（客户端原样发的字节）</div>
      <pre>${esc(d.raw_preview || '（已裁剪）')}</pre></div>`;
    return h;
  }
  async function detail(caseId){
    window.__capDetail = detail;            // 工作区侧栏点击时复用
    const ev = box('cap-evidence');
    if (!caseId){ ev.className = 'note'; ev.textContent = '这条是 HTTPS 隧道（未拆包），没有证据可看'; return; }
    ev.className = '';
    ev.innerHTML = '<div class="note">加载中…</div>';
    try {
      const d = await (await fetch('/api/capture/record?case_id=' + encodeURIComponent(caseId))).json();
      if (d.error){ ev.className = 'note'; ev.textContent = d.error; return; }
      ev.innerHTML = evHtml(d);
      const btn = box('cap-poc');
      if (btn) btn.onclick = () => poc(caseId);
    } catch(err){ ev.className = 'note'; ev.textContent = fetchFailText(err); }
  }
  async function poc(caseId){
    const out = box('cap-poc-out'); const body = box('cap-poc-body');
    out.textContent = '生成中…';
    try {
      const d = await (await fetch('/api/capture/poc', {method:'POST',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify({case_id: caseId})})).json();
      if (!d.ok){ out.textContent = ''; body.innerHTML = '<div class="err">' + esc(d.error || '生成失败') + '</div>'; return; }
      out.innerHTML = '脚本：<code>' + esc(d.path) + '</code>';
      body.innerHTML = `<div class="sect"><div class="note"><b>${esc(d.title)}（${esc(d.scenario)} · ${esc(d.cwe)}）</b></div>
        <div class="kv"><span class="k">链路</span>${esc(d.chain_desc)}</div>
        <div class="kv"><span class="k">影响</span>${esc(d.impact)}</div>
        <div class="kv"><span class="k">样本</span>${d.sample_len} 字节</div>
        <div class="kv"><span class="k">复现步骤</span>${d.steps.map(esc).join('　→　')}</div></div>`;
    } catch(err){ out.textContent = fetchFailText(err); }
  }
  function stopPolling(){ if (timer){ clearInterval(timer); timer = null; } }
  function startPolling(){ stopPolling(); timer = setInterval(poll, 1000); }
  async function poll(){
    try {
      const d = await (await fetch('/api/capture/records?since=' + seq)).json();
      renderStats(d.summary);
      let touched = false;
      if (d.counts){
        Object.keys(d.counts).forEach(cid => {
          const row = rows.find(x => x.case_id === cid);
          if (row && row.count !== d.counts[cid]){ row.count = d.counts[cid]; touched = true; }
        });
      }
      if (d.records && d.records.length){
        rows = rows.concat(d.records);
        seq = d.records[d.records.length - 1].seq;
        touched = true;
      }
      if (touched) renderList();
      if (!d.running) stopPolling();
    } catch(err){ stopPolling(); }
  }
  async function go(){
    box('cap-err').innerHTML = '';
    const port = parseInt(box('cap-port').value, 10);
    const domain = box('cap-domain').value;
    const jsonl = box('cap-jsonl').value.trim();
    const upstream = box('cap-upstream').value.trim();
    const payload = {port: isNaN(port) ? 18081 : port, analyze_all: box('cap-all').checked};
    if (domain) payload.domains = [domain];
    if (jsonl) payload.jsonl = jsonl;
    if (upstream) payload.upstream = upstream;
    try {
      const d = await (await fetch('/api/capture/start', {method:'POST',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)})).json();
      if (!d.ok){ box('cap-err').innerHTML = '<div class="err">' + esc(d.error || '启动失败') + '</div>'; return; }
      rows = []; seq = 0; sel = null;
      box('cap-list').innerHTML = '';
      box('cap-evidence').className = 'note';
      box('cap-evidence').textContent = '← 请选择左侧条目';
      setCapState('运行中：代理 127.0.0.1:' + d.port + (d.mitm === false
        ? '（HTTPS 未拆包：本解释器缺 cryptography —— pip install cryptography 后重启再开捕获）'
        : '（HTTP 明文 + HTTPS 本地 CA 解密）'));
      box('cap-go').disabled = true; box('cap-stop').disabled = false;
      renderStats(d.summary);
      startPolling();
    } catch(err){ box('cap-err').innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>'; }
  }
  async function stop(){
    try {
      const d = await (await fetch('/api/capture/stop', {method:'POST',
        headers:{'Content-Type':'application/json'}, body: '{}'})).json();
      setCapState('已停止' + (d.summary ? '　' + d.summary.requests + ' 条请求 / 分歧 ' + d.summary.divergences : ''));
      box('cap-go').disabled = false; box('cap-stop').disabled = true;
      stopPolling();
      renderStats(d.summary);
    } catch(err){ box('cap-err').innerHTML = '<div class="err">' + fetchFailHint(err) + '</div>'; }
  }
  box('cap-go').onclick = go;
  box('cap-stop').onclick = stop;
  /* ---- 捕获设置小窗：原生 dialog（ESC / 点背景自带关闭），控件沿用原 id ---- */
  function capSummaryText(){
    const port = parseInt(box('cap-port').value, 10) || 18081;
    const sel = box('cap-domain');
    const name = (sel.selectedIndex >= 0
      ? sel.options[sel.selectedIndex].textContent : '全部 5 个领域').replace(/（[^）]*）$/, '');
    const jsonl = box('cap-jsonl').value.trim();
    return '端口 ' + port + ' · ' + name
      + (box('cap-all').checked ? ' · 连静态资源' : ' · 跳过静态资源')
      + (jsonl ? ' · 记录到 ' + jsonl : ' · 不写记录文件');
  }
  function refreshCapSummary(){ box('cap-summary').textContent = capSummaryText(); }
  window.refreshCapSummary = refreshCapSummary;   // 「设置」页保存后要同步这一行
  function setCapState(text){
    const page = box('cap-state');
    if (page) page.textContent = text;
    const dlg = box('cap-dlg-state');
    if (dlg) dlg.textContent = '当前状态：' + text;
  }
  function openCapSettings(){
    box('cap-dlg-msg').textContent = '直接关窗：只影响这一次；点「存为默认」：下次开页也用';
    refreshCapSummary();
    const dlg = box('cap-dlg');
    if (typeof dlg.showModal === 'function') dlg.showModal();
    else dlg.setAttribute('open', '');            // 老浏览器兜底
  }
  document.querySelectorAll('.cap-settings').forEach(b => { b.onclick = openCapSettings; });
  box('cap-dlg-x').onclick = () => box('cap-dlg').close();
  box('cap-dlg-close').onclick = () => box('cap-dlg').close();
  ['cap-port','cap-domain','cap-all','cap-jsonl'].forEach(id => {
    box(id).addEventListener('input', refreshCapSummary);
    box(id).addEventListener('change', refreshCapSummary);
  });
  box('cap-filter').onchange = renderList;
  box('cap-search').oninput = renderList;
  (async function sync(){
    try {
      const doms = await (await fetch('/api/domains')).json();
      (doms.domains || []).forEach(x => {
        const opt = document.createElement('option');
        opt.value = x.name;
        opt.textContent = x.name + '（' + x.impls + ' 实现）';
        box('cap-domain').appendChild(opt);
      });
    } catch(err){ /* 拿不到领域列表也不影响主流程 */ }
    try {
      const d = await (await fetch('/api/capture/state')).json();
      if (d.running){
        box('cap-port').value = d.port;
        setCapState('运行中：代理 127.0.0.1:' + d.port);
        box('cap-go').disabled = true; box('cap-stop').disabled = false;
        renderStats(d.summary);
        startPolling();
      }
    } catch(err){ /* 服务没起来时安静退出 */ }
  })();
})();

/* ===== 三栏工作区：模式切换 + 结果卡 tab + 检测历史侧栏 ===== */
(function(){
  const $id = id => document.getElementById(id);
  let mode = 'manual';
  let sideSel = null;                       // {kind:'cap'|'find', key}
  const dtHistory = [];                     // {ts, title, arr} —— 每次手动检测的发现集合

  /* ---- 模式切换：六个面板互斥显示（状态写入 hash，可深链、可回退）---- */
  const MODE_PANELS = {
    manual: 'mode-manual', capture: 'mode-capture',
    scan: 'panel-scan', check: 'panel-check'
  };
  /* 侧栏选中哪一项，中栏页头就换成哪一项的标题与一句话说明 */
  const MODE_HEAD = {
    manual: ['手动检测', '产品串联处的耦合误差检测 · 判定由确定性引擎给出，全部证据可复核'],
    capture: ['流量接入', '本机代理接管浏览器 / 客户端流量，逐条进同一条检测链路，数据只留本机'],
    scan: ['矩阵扫描', '用内置语料在所选领域上主动搜索定向分歧，命中项自动产出证据链与最小复现样本'],
    check: ['自检与案例库', '引擎有效性回归 · 47 条已知案例的判定依据']
  };
  function setMode(m){
    if (!MODE_PANELS[m]) return;
    mode = m;
    document.querySelectorAll('#mode-tabs .navbtn').forEach(b => {
      const on = b.dataset.mode === m;
      b.classList.toggle('active', on);
      if (b.hasAttribute('role')) b.setAttribute('aria-selected', String(on));  // 读屏要知道当前在哪一栏
    });
    Object.entries(MODE_PANELS).forEach(([k, id]) => {
      const el = $id(id); if (el) el.hidden = k !== m;
    });
    // 流程 / 报告 / 解读是手动检测的产出；其余模式下整块隐藏，避免无关产出挂在面板里
    const out = $id('dt-output');
    if (out) out.hidden = m !== 'manual';
    const head = MODE_HEAD[m] || [];
    if ($id('ws-title')) $id('ws-title').textContent = head[0] || '';
    if ($id('ws-sub')) $id('ws-sub').textContent = head[1] || '';
    // 深链与浏览器前进/后退：写 hash（pushState 语义），replaceState 不会留下历史记录
    if (location.hash.slice(1) !== m) location.hash = m;
  }
  document.querySelectorAll('#mode-tabs .navbtn').forEach(b =>
    b.onclick = () => setMode(b.dataset.mode));
  /* 浏览器前进/后退回到上一个面板 */
  window.addEventListener('hashchange', () => {
    const m = location.hash.slice(1);
    if (MODE_PANELS[m] && m !== mode) setMode(m);
  });
  /* 键盘：↑/↓/Home/End 在侧栏功能键之间移动（tablist 的基本预期） */
  const modeTabs = $id('mode-tabs');
  if (modeTabs) modeTabs.addEventListener('keydown', ev => {
    if (ev.key !== 'ArrowUp' && ev.key !== 'ArrowDown' && ev.key !== 'Home' && ev.key !== 'End') return;
    const btns = [...document.querySelectorAll('#mode-tabs .navbtn')];
    const at = btns.indexOf(document.activeElement);
    if (at < 0) return;
    ev.preventDefault();
    const next = ev.key === 'Home' ? 0 : ev.key === 'End' ? btns.length - 1
      : (at + (ev.key === 'ArrowDown' ? 1 : -1) + btns.length) % btns.length;
    btns[next].focus();
    btns[next].click();
  });

  /* ---- 结果卡 tab：实时报告 / 发现 ---- */
  function showResultTab(name){
    document.querySelectorAll('#res-tabs .tabbtn').forEach(b =>
      b.classList.toggle('active', b.dataset.panel === name));
    $id('panel-report').hidden = name !== 'panel-report';
    $id('panel-findings').hidden = name !== 'panel-findings';
    if ($id('res-acts-report')) $id('res-acts-report').hidden = name !== 'panel-report';
    if ($id('res-acts-findings')) $id('res-acts-findings').hidden = name !== 'panel-findings';
  }
  document.querySelectorAll('#res-tabs .tabbtn').forEach(b =>
    b.onclick = () => showResultTab(b.dataset.panel));

  /* ---- 检测历史侧栏 ---- */
  function dayLabel(ts){
    const d = new Date(ts), now = new Date();
    const day0 = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diff = Math.round((day0(now) - day0(d)) / 86400000);
    if (diff <= 0) return '今天';
    if (diff === 1) return '昨天';
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0')
         + '-' + String(d.getDate()).padStart(2, '0');
  }
  function capBadge(r){
    const a = r.analysis;
    if (r.tunnel) return '<span class="badge">隧道</span>';
    if (!a) return '';
    if (a.security) return '<span class="badge security">' + a.security + '</span>';
    if (a.divergences) return '<span class="badge unknown">' + a.divergences + '</span>';
    return '<span class="badge compatibility">一致</span>';
  }
  function sideRender(){
    const list = $id('side-list');
    if (!list) return;
    const items = [];
    (window.__capRows || []).forEach((r, i) => {
      if (r.tunnel) return;                 // 隧道（未拆包）不进历史
      items.push({kind: 'cap', i, ts: r.ts ? new Date(r.ts) : new Date(0),
        title: (r.method || '') + ' ' + (r.host || '') + (r.path || ''),
        badge: capBadge(r), key: r.case_id || ('cap' + i)});
    });
    dtHistory.forEach((e, i) => items.push({kind: 'find', i, ts: e.ts,
      title: e.title, badge: '', key: 'find' + i}));
    items.sort((a, b) => b.ts - a.ts);
    $id('side-count').textContent = items.length ? items.length + ' 条' : '';
    if (!items.length){
      list.innerHTML = '<div class="side-empty">暂无记录；这里会按日期归档本次会话内的手动检测与流量接入</div>';
      return;
    }
    let html = '', lastDay = '';
    const selKey = sideSel ? sideSel.kind + ':' + sideSel.key : '';
    items.forEach(it => {
      const d = dayLabel(it.ts);
      if (d !== lastDay){ html += '<div class="side-day">' + d + '</div>'; lastDay = d; }
      const sel = selKey === it.kind + ':' + it.key ? ' sel' : '';
      html += '<div class="side-item' + sel + '" data-kind="' + it.kind
            + '" data-i="' + it.i + '" data-key="' + it.key + '">'
            + '<span class="t" title="' + it.title.replace(/"/g, '&quot;') + '">'
            + esc(it.title) + '</span>' + it.badge + '</div>';
    });
    list.innerHTML = html;
    list.querySelectorAll('.side-item').forEach(el => el.onclick = () => {
      const kind = el.dataset.kind, i = parseInt(el.dataset.i, 10);
      sideSel = {kind, key: el.dataset.key};
      if (kind === 'cap'){
        const r = (window.__capRows || [])[i];
        setMode('capture');
        if (r && r.case_id){
          selCap(r); sideRender();
          if (window.__capDetail) window.__capDetail(r.case_id);
        }
      } else {
        const e = dtHistory[i];
        setMode('manual');
        if (window.__dtLoad) window.__dtLoad(e.arr);
        showResultTab('panel-findings');
        const rep = $id('dt-reportcard'); if (rep) rep.open = true;   // 点了历史就得能看见那条
        sideRender();
      }
    });
  }
  function selCap(r){
    const rows = window.__capRows || [];
    const list = $id('cap-list');
    if (list) list.querySelectorAll('.evitem').forEach(x =>
      x.classList.toggle('sel', x.dataset.case === (r.case_id || '')));
  }

  /* 由捕获 / 检测两个模块回调 */
  window.sideAddDetect = arr => {
    const sel = $id('dt-domain');
    const name = sel && sel.selectedIndex >= 0
      ? sel.options[sel.selectedIndex].textContent : '';
    dtHistory.push({ts: new Date(), title: '手动检测 · ' + (name || '全部领域'), arr});
    sideRender();
  };
  window.__sideSync = () => sideRender();   // 捕获轮询里每轮调一次
  sideRender();
  const hashMode = location.hash.slice(1);
  if (MODE_PANELS[hashMode]) setMode(hashMode);          // 深链：/#scan 等直接进对应面板
})();
