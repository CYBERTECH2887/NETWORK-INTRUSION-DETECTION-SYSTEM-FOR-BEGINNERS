// Theme Toggle with LocalStorage Persistence
const themeToggle = document.getElementById('theme-toggle');
const currentTheme = localStorage.getItem('theme') || 'dark';

document.documentElement.setAttribute('data-theme', currentTheme);
if (themeToggle) {
  themeToggle.checked = currentTheme === 'light';
  themeToggle.addEventListener('change', (e) => {
    const newTheme = e.target.checked ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
  });
}