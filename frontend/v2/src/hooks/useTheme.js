import { useState, useCallback, useEffect } from "react";

function resolveTheme(theme) {
  if (theme === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return theme;
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", resolveTheme(theme));
  localStorage.setItem("theme", theme);
}

export function useTheme() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("theme") || "dark";
    document.documentElement.setAttribute("data-theme", resolveTheme(saved));
    return saved;
  });

  // When theme === "system", react to OS-level changes
  useEffect(() => {
    if (theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => document.documentElement.setAttribute("data-theme", resolveTheme("system"));
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme(prev => {
      const next = prev === "dark" ? "light" : "dark";
      applyTheme(next);
      return next;
    });
  }, []);

  const set = useCallback((value) => {
    applyTheme(value);
    setTheme(value);
  }, []);

  return { theme, toggle, set, isDark: resolveTheme(theme) === "dark" };
}
