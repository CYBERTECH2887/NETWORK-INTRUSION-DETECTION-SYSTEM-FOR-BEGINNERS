/* ========================================== */
/* BLOCK 1: Theme Toggle & Persistence        */
/* ========================================== */
const themeToggle = document.getElementById('theme-toggle');
const currentTheme = localStorage.getItem('theme') || 'dark';

// Apply the saved theme immediately
document.documentElement.setAttribute('data-theme', currentTheme);

if (themeToggle) {
  // Check the slider position based on the saved theme
  themeToggle.checked = currentTheme === 'light';
  
  // Listen for clicks on the toggle switch
  themeToggle.addEventListener('change', (e) => {
    const newTheme = e.target.checked ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  });
}