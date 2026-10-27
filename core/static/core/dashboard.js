document.addEventListener("DOMContentLoaded", () => {
  for (const form of document.querySelectorAll("form[data-loading-form]")) {
    form.addEventListener("submit", () => {
      if (!form.checkValidity()) return;
      form.setAttribute("aria-busy", "true");
      const status = form.querySelector(".submit-loading");
      if (status) status.classList.remove("visually-hidden");
      const button = form.querySelector('button[type="submit"]');
      if (button) button.disabled = true;
    });
  }
});
