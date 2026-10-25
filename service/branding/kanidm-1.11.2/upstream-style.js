function getPreferredTheme() {
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function updateColourScheme() {
  const theme = getPreferredTheme();
  console.debug(`updateColourScheme theme->${theme}`);
  document.documentElement.setAttribute("data-bs-theme", theme);
}

updateColourScheme();
window
  .matchMedia("(prefers-color-scheme: light)")
  .addEventListener("change", updateColourScheme);
window
  .matchMedia("(prefers-color-scheme: dark)")
  .addEventListener("change", updateColourScheme);
document.body.addEventListener("htmx:afterOnLoad", updateColourScheme);
