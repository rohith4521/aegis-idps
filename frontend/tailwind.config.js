/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#090d16',
          card: '#0f172a',
          surface: '#172033',
          border: '#1e293b',
          muted: '#64748b',
          cyan: '#06b6d4',
          neon: '#10b981',
          warning: '#f59e0b',
          danger: '#ef4444',
          purple: '#8b5cf6',
          blue: '#3b82f6',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan': '0 0 15px -3px rgba(6, 182, 212, 0.3)',
        'glow-danger': '0 0 15px -3px rgba(239, 68, 68, 0.4)',
        'glow-neon': '0 0 15px -3px rgba(16, 185, 129, 0.3)',
      }
    },
  },
  plugins: [],
}
