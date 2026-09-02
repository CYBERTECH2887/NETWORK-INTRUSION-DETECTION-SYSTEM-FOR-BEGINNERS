document.getElementById('prediction-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const statusText = document.getElementById('traffic-status-text');
  const confText = document.getElementById('confidence-text');
  const orb = document.getElementById('status-orb');
  const labels = document.getElementById('status-labels');
  
  statusText.innerText = "Analyzing...";
  statusText.style.color = "var(--text-main)";
  orb.className = "status-orb";

  // Form se saari 7 values extract karein
  const payload = {
    duration: parseFloat(document.getElementById('duration').value) || 0,
    protocol_type: document.getElementById('protocol_type').value,
    service: document.getElementById('service').value,
    flag: document.getElementById('flag').value,
    src_bytes: parseFloat(document.getElementById('src_bytes').value) || 0,
    dst_bytes: parseFloat(document.getElementById('dst_bytes').value) || 0,
    num_failed_logins: parseFloat(document.getElementById('num_failed_logins').value) || 0,
    model: 'rf'
  };

  try {
    const response = await fetch('/api/predict_manual', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    
    if (data.prediction) {
      confText.innerText = data.confidence;
      const breakdownDiv = document.getElementById('prob-breakdown');
breakdownDiv.innerHTML = '<strong>Probability Breakdown:</strong><br>';
for (const [className, prob] of Object.entries(data.probabilities)) {
  breakdownDiv.innerHTML += `<span>${className}: ${prob}</span><br>`;
}
      if (data.prediction === 'Normal') {
        statusText.innerText = "NORMAL";
        statusText.style.color = "var(--accent-green)";
        orb.className = "status-orb normal";
        labels.innerHTML = `<span class="highlight-normal">NORMAL</span><br><span style="font-size: 0.9rem; color: var(--text-muted);">or</span><br><span style="color: var(--text-muted); opacity: 0.4;">ALERT</span>`;
      } else {
        statusText.innerText = `ALERT (${data.prediction})`;
        statusText.style.color = "var(--accent-red)";
        orb.className = "status-orb alert";
        labels.innerHTML = `<span style="color: var(--text-muted); opacity: 0.4;">NORMAL</span><br><span style="font-size: 0.9rem; color: var(--text-muted);">or</span><br><span class="highlight-alert">ALERT</span>`;
      }
    }
  } catch (err) {
    statusText.innerText = "Error analyzing";
    console.error(err);
  }
});

