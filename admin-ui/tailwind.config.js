/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{rs,html}",
    "./index.html"
  ],
  theme: {
    extend: {
      colors: {
        primary: 'var(--bg-primary)',
        secondary: 'var(--bg-secondary)',
        tertiary: 'var(--bg-tertiary)',
        card: 'var(--bg-card)',
        accent: {
          DEFAULT: 'var(--accent-primary)',
          secondary: 'var(--accent-secondary)',
          glow: 'var(--accent-glow)'
        },
        default: 'var(--border-color)',
        // Themeable replacement for the hardcoded `blue-*` ramp that ~190
        // call sites used to hardcode. Declared as raw RGB *channel triplets*
        // rather than a plain `var(--x)` colour so Tailwind's opacity modifier
        // keeps working — `rgb(var(--action-500) / <alpha-value>)` accepts
        // `bg-action-500/10`, whereas `var(--action-500)` silently cannot, and
        // the panel already relies on `/10`, `/20`, `/50` and `/90` variants
        // for badge and toast tints.
        //
        // The numbers deliberately mirror Tailwind's blue ramp so the
        // `blue-NNN` -> `action-NNN` migration is 1:1 and appearance-neutral in
        // the default (dark) and light themes. Per-theme overrides live in
        // `tailwind.css`.
        action: {
          300: 'rgb(var(--action-300) / <alpha-value>)',
          400: 'rgb(var(--action-400) / <alpha-value>)',
          500: 'rgb(var(--action-500) / <alpha-value>)',
          600: 'rgb(var(--action-600) / <alpha-value>)',
          700: 'rgb(var(--action-700) / <alpha-value>)',
          900: 'rgb(var(--action-900) / <alpha-value>)'
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace']
      }
    }
  },
  plugins: []
}
