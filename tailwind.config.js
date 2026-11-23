/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./glycon/templates/**/*.html",
    "./glycon/static/js/**/*.js"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'Monaco', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        tactical: {
          950: '#060911',
          900: '#0b101d',
          850: '#101729',
          800: '#161f35',
          700: '#212e4d',
        }
      },
      boxShadow: {
        'glow-emerald': '0 0 20px -3px rgba(16, 185, 129, 0.25)',
        'glow-cyan': '0 0 20px -3px rgba(6, 182, 212, 0.25)',
        'glow-rose': '0 0 20px -3px rgba(244, 63, 94, 0.25)',
      }
    }
  },
  plugins: []
}
