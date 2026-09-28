/* Apply the saved/system theme before first paint. No clinical data is persisted. */
(() => {
  const saved = localStorage.getItem("ar-theme");
  const theme = saved === "light" || saved === "dark"
    ? saved
    : (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.dataset.theme = theme;
})();
