/* Manual prediction page: presets, form submit, result board */

// Demonstration ke liye kuch presets jo ek click me form bhar denge
const PRESETS = {
  normal:  { duration: 0,   protocol_type: 'tcp', service: 'http',    flag: 'SF',  src_bytes: 181, dst_bytes: 5450, num_failed_logins: 0 },
  syn:     { duration: 0,   protocol_type: 'tcp', service: 'private', flag: 'S0',  src_bytes: 0,   dst_bytes: 0,    num_failed_logins: 0 },
  scan:    { duration: 0,   protocol_type: 'tcp', service: 'private', flag: 'REJ', src_bytes: 0,   dst_bytes: 0,    num_failed_logins: 0 },
  brute:   { duration: 15,  protocol_type: 'tcp', service: 'ftp',     flag: 'RSTO',src_bytes: 45,  dst_bytes: 45,   num_failed_logins: 5 },
  root:    { duration: 950, protocol_type: 'tcp', service: 'ssh',     flag: 'SF',  src_bytes: 1200, dst_bytes: 900, num_failed_logins: 0 },
};

const form = document.getElementById('prediction-form');

// Preset buttons pe click sunne ka logic, jo inputs me value dal ke directly form submit kar deta hai
document.querySelectorAll('[data-preset]').forEach(btn => btn.addEventListener('click', () => {
  Object.entries(PRESETS[btn.dataset.preset]).forEach(([k, v]) => { document.getElementById(k).value = v; });
  form.requestSubmit();
}));

// Form submit hone par API ko data bhejne aur result UI pe show karne ka logic
form.addEventListener('submit', async e => {
  e.preventDefault(); // Page refresh hone se rokna
  
  const statusText = document.getElementById('traffic-status-text'), confText = document.getElementById('confidence-text');
  const orb = document.getElementById('status-orb'), probBox = document.getElementById('prob-bars'), btn = document.getElementById('analyze-btn');

  // Request jaane se pehle loading state set kar raha hai
  statusText.textContent = 'Analyzing...'; statusText.style.color = ''; orb.className = 'status-orb'; btn.disabled = true;
  
  const val = id => parseFloat(document.getElementById(id).value) || 0;
  
  // HTML form se saari 7 fields ka data JSON me combine karna
  const payload = {
    duration: val('duration'), protocol_type: document.getElementById('protocol_type').value,
    service: document.getElementById('service').value, flag: document.getElementById('flag').value,
    src_bytes: val('src_bytes'), dst_bytes: val('dst_bytes'), num_failed_logins: val('num_failed_logins'),
  };

  try {
    // Backend API par data bhej kar result ka intezaar karna
    const { ok, data } = await api('/api/predict_manual', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    if (!ok || !data.prediction) throw new Error(data.error || 'Prediction failed');
    
    // Result aane par confidence percentage update karna
    confText.textContent = data.confidence;
    const attack = data.prediction !== 'Normal';
    
    // Text aur Orb (gola) ka colour red/green set karna depending on "Attack" vs "Normal"
    statusText.textContent = attack ? `Alert: ${data.prediction}` : 'Normal traffic';
    statusText.style.color = attack ? 'var(--danger)' : 'var(--ok)';
    orb.className = 'status-orb ' + (attack ? 'alert' : 'normal');
    
    // Agar attack tha toh warning sound bajana
    if (attack) playAlert();

    // 5 classes ke probabilities ka progress bar banakar render karna
    const colors = { Normal: 'var(--c-normal)', DoS: 'var(--c-dos)', Probe: 'var(--c-probe)', U2R: 'var(--c-u2r)', R2L: 'var(--c-r2l)' };
    probBox.innerHTML = Object.entries(data.probabilities).map(([name, pct]) =>
      `<div class="bar-row" style="--k:${colors[name]}"><span>${esc(name)}</span><div class="bar"><span style="width:${parseFloat(pct)}%"></span></div><span>${esc(pct)}</span></div>`).join('');
      
  } catch (err) {
    statusText.textContent = 'Could not analyze'; 
    statusText.style.color = 'var(--danger)'; 
    toast(err.message, 'error'); // API fail hui toh error toast
  } finally { 
    btn.disabled = false; // Processing ke baad button wapas enable karna
  }
});