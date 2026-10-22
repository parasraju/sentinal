import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./popup.html", "./options.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#070d18",
          900: "#0b1220",
          850: "#0e1728",
          800: "#111c31",
          700: "#17253f",
          600: "#1f3152",
        },
        mist: {
          100: "#e8effa",
          200: "#c9d6ea",
          300: "#9fb2cf",
          400: "#7c90b3",
          500: "#5d7192",
        },
        safe: "#34d399",
        caution: "#fbbf24",
        danger: "#f87171",
        sentinel: "#2dd4bf",
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: ["ui-monospace", "SFMono-Regular", "Cascadia Code", "Consolas", "monospace"],
      },
      boxShadow: {
        panel: "0 18px 50px -28px rgba(2, 8, 20, 0.9)",
        glow: "0 0 0 1px rgba(45, 212, 191, 0.25), 0 10px 40px -16px rgba(45, 212, 191, 0.35)",
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-up": "fade-up 220ms ease-out both",
      },
    },
  },
  plugins: [],
};

export default config;
