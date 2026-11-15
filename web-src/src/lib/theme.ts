import { ref } from 'vue';
export type Theme = 'system' | 'light' | 'dark';
export const theme = ref<Theme>('system');
const media = window.matchMedia('(prefers-color-scheme: dark)');
function render() {
  const dark = theme.value === 'dark' || (theme.value === 'system' && media.matches);
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
}
export function setTheme(value: Theme) {
  theme.value = value;
  try { localStorage.setItem('cftheme', value); } catch { /* Storage can be disabled. */ }
  render();
}
export function initTheme() {
  try {
    const value = localStorage.getItem('cftheme');
    if (value === 'light' || value === 'dark') theme.value = value;
  } catch { /* Use system preference. */ }
  render();
  media.addEventListener('change', render);
}
