/**
 * ArogyaRaksha client behaviour. No build step, no dependencies; loaded with the CSP nonce.
 */
document.addEventListener("DOMContentLoaded", () => {
  // Theme preference contains no clinical or identity data and is safe to persist locally.
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      localStorage.setItem("ar-theme", next);
      button.setAttribute("aria-label", `Switch to ${next === "dark" ? "light" : "dark"} theme`);
    });
  });

  // Give immediate, unambiguous feedback while forms are submitted.
  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", () => {
      const submitter = form.querySelector('button[type="submit"]');
      if (!submitter || submitter.dataset.noLoading !== undefined) return;
      submitter.setAttribute("aria-busy", "true");
      submitter.classList.add("is-loading");
    });
  });

  // Mobile navigation drawer
  const toggle = document.getElementById("menu-toggle");
  const sidebar = document.getElementById("app-sidebar");
  if (toggle && sidebar) {
    const setOpen = (open) => {
      sidebar.classList.toggle("is-open", open);
      toggle.setAttribute("aria-expanded", String(open));
    };
    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      setOpen(!sidebar.classList.contains("is-open"));
    });
    document.addEventListener("click", (e) => {
      if (sidebar.classList.contains("is-open") && !sidebar.contains(e.target)) setOpen(false);
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") setOpen(false);
    });
  }

  // Dismissible flash messages
  document.querySelectorAll(".flash-close").forEach((btn) => {
    btn.addEventListener("click", () => btn.closest(".flash")?.remove());
  });

  // Confirmation for destructive or audited actions
  document.querySelectorAll("[data-confirm]").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (!window.confirm(el.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Show / hide password
  document.querySelectorAll("[data-reveal-target]").forEach((btn) => {
    const input = document.getElementById(btn.getAttribute("data-reveal-target"));
    if (!input) return;
    btn.addEventListener("click", () => {
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      btn.textContent = reveal ? "Hide" : "Show";
      btn.setAttribute("aria-pressed", String(reveal));
    });
  });

  // Filter forms: apply select changes immediately
  document.querySelectorAll("form[data-autosubmit] select").forEach((select) => {
    select.addEventListener("change", () => select.form.requestSubmit());
  });
});
