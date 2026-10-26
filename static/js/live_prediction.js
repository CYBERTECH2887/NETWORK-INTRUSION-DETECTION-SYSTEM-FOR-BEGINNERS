/* Live & CSV page: drag-drop upload, batch analysis, live sniffing loop */
const $ = id => document.getElementById(id);

/* ---------------- Batch CSV (File Upload & Analysis) ---------------- */
const fileInput = $('csv-file-input'), dropzone = $('dropzone'), runBtn =$('run-batch-btn');
const batchBody = $('batch-table-body'), summaryBox =$('batch-summary');
let selectedFile = null;
const EMPTY_BATCH = '<tr><td colspan="4"><div class="empty"><strong>No results yet</strong>Choose a CSV file, then press Run analysis.</div></td></tr>';

// File select hone par UI update karne ka logic
function pickFile(file) {
  if (!file) return;
  selectedFile = file; 
  $('dz-default').hidden = true; 
  $('dz-selected').hidden = false; 
  $('selected-file-name').textContent = file.name;
}

// Select ki hui file clear karne ka logic
function resetFile() {
  fileInput.value = ''; selectedFile = null; 
  $('dz-default').hidden = false; 
  $('dz-selected').hidden = true;
  batchBody.innerHTML = EMPTY_BATCH; 
  summaryBox.innerHTML = '';
}

// Drag & drop area ke event listeners
dropzone.addEventListener('click', e => { if (!e.target.closest('button')) fileInput.click(); });
dropzone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
fileInput.addEventListener('change', e => pickFile(e.target.files[0]));
$('remove-file').addEventListener('click', e => { e.stopPropagation(); resetFile(); });
['dragenter', 'dragover'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.add('drag'); }));
['dragleave', 'drop'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.remove('drag'); }));
dropzone.addEventListener('drop', e => pickFile(e.dataTransfer.files[0]));

// "Run Analysis" button click karne par CSV file backend me /api/predict_batch par bhejta hai
runBtn.addEventListener('click', async () => {
  if (!selectedFile) return toast('Choose a CSV file first.', 'error');
  runBtn.disabled = true; summaryBox.innerHTML = '';
  batchBody.innerHTML = '<tr><td colspan="4"><div class="empty">Analyzing...</div></td></tr>';
  
  const fd = new FormData(); fd.append('file', selectedFile);
  try {
    const { ok, data } = await api('/api/predict_batch', { method: 'POST', body: fd });
    if (!ok) { 
        batchBody.innerHTML = `<tr><td colspan="4"><div class="notice error">${esc(data.error || 'Analysis failed.')}</div></td></tr>`; 
        return; 
    }
    
    // Results aur summary ko format karke table me insert karta hai
    summaryBox.innerHTML = Object.entries(data.summary).filter(([, n]) => n > 0)
      .map(([k, n]) => `${chip(k)} <b style="margin-right:10px">${n}</b>`).join('') +
      `<span class="muted" style="font-size:.82rem">${data.total} rows analysed${data.shown < data.total ? `, showing first ${data.shown}` : ''}</span>`;
      
    batchBody.innerHTML = data.results.map(r =>
      `<tr class="${r.prediction !== 'Normal' ? 'alert-row' : ''}"><td>#${r.id}</td><td>${esc(r.protocol)}</td><td>${chip(r.prediction)}</td><td>${esc(r.confidence)}</td></tr>`).join('');
  } catch (err) { 
      batchBody.innerHTML = '<tr><td colspan="4"><div class="notice error">Analysis failed. Check that the server is running.</div></td></tr>'; 
  } finally { runBtn.disabled = false; }
});

/* ---------------- Live sniffing (Real-time network monitoring) ---------------- */
const liveBtn = $('start-live-btn'), liveBody = $('live-table-body'), liveDot =$('live-dot');
const EMPTY_LIVE = msg => `<tr><td colspan="7"><div class="empty"><strong>${msg[0]}</strong>${msg[1] || ''}</div></td></tr>`;
let sniffing = false, total = 0, threats = 0;

// Browser notifications ki permission mangna
if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission();
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Dashboard dashboard stats update karta hai
function updateCounters() { $('cnt-total').textContent = total; $('cnt-threat').textContent = threats; }

// Backend API se 1 live packet fetch karta hai aur usko table me lagata hai
async function fetchPacket() {
  const { ok, status, data } = await api('/api/sniff_packet');
  if (status === 404) return true; // Agar traffic nahi mili is second me toh ignore karke aage badho                                          
  if (!ok) { toast(data.error || 'Sniffing failed.', 'error'); return false; }

  total++; 
  const attack = data.prediction !== 'Normal'; 
  if (attack) threats++; 
  updateCounters();
  
  // Agar attack mila hai toh sound bajao aur desktop notification bhejo
  if (attack) {
    playAlert();
    if ('Notification' in window && Notification.permission === 'granted') {
      const n = new Notification(`CRACKA NIDS: ${data.prediction}`, { body: `IP ${data.ip_address} | ${data.protocol} | ${data.confidence}` });
      n.onclick = function () { window.focus(); this.close(); };
    }
  }
  
  // Naye packet ko table me sabse upar insert karta hai (afterbegin)
  liveBody.insertAdjacentHTML('afterbegin',
    `<tr class="${attack ? 'alert-row' : ''}"><td>${data.id}</td><td class="mono">${esc(data.ip_address)}</td><td>${esc(data.protocol)}</td><td>${chip(data.prediction)}</td><td>${esc(data.confidence)}</td><td>${esc(data.date)}</td><td>${esc(data.time)}</td></tr>`);
  
  // Table me max 200 rows rakhta hai taaki browser crash na ho
  while (liveBody.rows.length > 200) liveBody.deleteRow(-1);                 
  return true;
}

// Sniffing loop: Jab tak 'sniffing' true hai, har 400ms me packet check karta rahega
async function loop() {
  while (sniffing) {
    try { if (!(await fetchPacket())) { await stopSniffing(true); break; } } catch (e) { break; }
    await sleep(400);
  }
}

// Sniffing rokta hai aur database me save karne ke liye /api/stop_sniffing ko call karta hai
async function stopSniffing(failed) {
  sniffing = false; liveDot.classList.remove('on');
  liveBtn.disabled = true; liveBtn.textContent = 'Saving session...';
  try {
    const { ok, data } = await api('/api/stop_sniffing', { method: 'POST' });
    toast(data.message || data.error, ok ? 'success' : 'error');
    if (!failed) liveBody.innerHTML = EMPTY_LIVE([data.message || 'Session saved.', 'Press Start sniffing to begin a new session.']);
  } catch (e) {}
  total = 0; threats = 0; updateCounters();
  liveBtn.disabled = false; liveBtn.className = 'btn'; liveBtn.textContent = 'Start sniffing';
}

// "Start Sniffing" button ka click handler
liveBtn.addEventListener('click', async () => {
  if (sniffing) return stopSniffing(false); // Agar chal raha hai toh band kardo
  if ('Notification' in window && Notification.permission === 'default') await Notification.requestPermission();
  
  sniffing = true; liveDot.classList.add('on'); liveBody.innerHTML = '';
  liveBtn.className = 'btn btn-danger'; liveBtn.textContent = 'Stop and save';
  loop(); // Continuous packet fetching loop start kar do
});