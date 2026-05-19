import { useState, useCallback } from "react";

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
}

export function useTheme() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("theme") || "dark";
    // Apply synchronously during init to prevent flash of wrong theme
    document.documentElement.setAttribute("data-theme", saved);
    return saved;
  });

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

  return { theme, toggle, set, isDark: theme === "dark" };
}
