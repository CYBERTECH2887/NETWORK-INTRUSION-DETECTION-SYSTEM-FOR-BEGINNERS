/* Shared behaviour: theme, sidebar, profile menu, password toggle, toasts, API helper, alert sound */
(function () {
  const root = document.documentElement;

  /* ----- Theme Toggle ----- 
     Light aur Dark mode switch karne ka logic. Save ki hui theme localStorage se read hoti hai. */
  function setTheme(t) { 
      root.setAttribute('data-theme', t); 
      try { localStorage.setItem('theme', t); } catch (e) {} 
  }
  document.querySelectorAll('[data-theme-toggle]').forEach(btn =>
    btn.addEventListener('click', () => setTheme(root.getAttribute('data-theme') === 'light' ? 'dark' : 'light')));

  /* ----- Sidebar Control ----- 
     Mobile screens pe sidebar ko bahar nikalne (slide-over) aur desktop pe collapse karne ka logic. */
  const sidebarBtn = document.getElementById('sidebar-toggle');
  if (sidebarBtn) sidebarBtn.addEventListener('click', () =>
    document.body.classList.toggle(window.innerWidth <= 900 ? 'sidebar-open' : 'sidebar-collapsed'));
  
  // Agar mobile me sidebar khula hai aur bahar click kiya, toh sidebar band kar do
  document.addEventListener('click', e => {
    if (document.body.classList.contains('sidebar-open') && !e.target.closest('.sidebar') && !e.target.closest('#sidebar-toggle'))
      document.body.classList.remove('sidebar-open');
  });

  /* ----- Profile Dropdown Menu ----- 
     Top right me user profile pe click karne par menu dikhana aur bahar click karne par chhupana. */
  const pBtn = document.getElementById('profile-btn'), pMenu = document.getElementById('profile-menu');
  if (pBtn && pMenu) {
    pBtn.addEventListener('click', e => { 
        e.stopPropagation(); 
        pMenu.classList.toggle('show'); 
        pBtn.setAttribute('aria-expanded', pMenu.classList.contains('show')); 
    });
    document.addEventListener('click', e => { if (!pMenu.contains(e.target)) pMenu.classList.remove('show'); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') pMenu.classList.remove('show'); });
  }

  /* ----- Show / Hide Password ----- 
     Login/Register form me password dikhane/chupane wala toggle button. */
  document.querySelectorAll('[data-toggle-password]').forEach(btn => btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.togglePassword);
    input.type = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? 'Show' : 'Hide';
  }));

  /* ----- Helpers shared with page scripts ----- 
     XSS attacks rokne ke liye special characters ko escape karne ka function. */
  window.esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  
  // UI me attack name ki color-coded chip (badge) banane ka function
  window.chip = name => `<span class="chip" data-class="${esc(name)}">${esc(name)}</span>`;

  // Screen ke bottom right me chhota sa success/error popup (toast) dikhane ka function
  window.toast = function (msg, type) {
    let zone = document.querySelector('.toast-zone');
    if (!zone) { 
        zone = document.createElement('div'); 
        zone.className = 'toast-zone'; 
        zone.setAttribute('role', 'status'); 
        document.body.appendChild(zone); 
    }
    const t = document.createElement('div'); 
    t.className = 'toast ' + (type || ''); 
    t.textContent = msg; 
    zone.appendChild(t);
    setTimeout(() => t.remove(), 4500); // 4.5 sec baad toast gayab
  };

  /* ----- API Fetch Wrapper ----- 
     Backend se data laane ke liye wrapper. Agar user ka session expire (401 error) ho gaya hai, 
     toh use directly login page par bhej deta hai. */
  window.api = async function (url, options) {
    const res = await fetch(url, options);
    if (res.status === 401) { window.location.href = '/login'; throw new Error('Session expired'); }
    let data = {}; try { data = await res.json(); } catch (e) {}
    return { ok: res.ok, status: res.status, data };
  };

  /* ----- Alert Beep Sound ----- 
     Agar koi attack pakda gaya, toh warning sound bajane ka function.
     Agar mp3 file nahi mili, toh browser me synth sound generate karta hai. */
  let audioCtx;
  window.playAlert = function () {
    const a = new Audio('/static/audio/beep.mp3');
    a.play().catch(() => {
      try {
        audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
        const o = audioCtx.createOscillator(), g = audioCtx.createGain();
        o.type = 'square'; o.frequency.value = 880; g.gain.value = 0.06;
        o.connect(g); g.connect(audioCtx.destination); o.start(); o.stop(audioCtx.currentTime + 0.25);
      } catch (e) {}
    });
  };
})();