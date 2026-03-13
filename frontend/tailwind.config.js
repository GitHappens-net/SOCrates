/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        "soc-bg": "#f9fafb",
        "soc-surface": "#ffffff",
        "soc-card": "#ffffff",
        "soc-border": "#000000",
        "soc-text": "#111827",
        "soc-muted": "#6b7280",
        crimson: {
          400: "#dc2626",
          500: "#dc2626",
          600: "#b91c1c",
          700: "#991b1b",
          900: "#fef2f2",
        },
        emerald: {
          400: "#16a34a",
          500: "#16a34a",
          600: "#15803d",
        },
        electric: {
          400: "#2563eb",
          500: "#3b82f6",
          600: "#1d4ed8",
        },
      },
    },
  },
  plugins: [],
};
