/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: '#0a0a0b',
          dark: '#121214',
          gray: '#1f1f23',
          accent: '#00ff9f',
          critical: '#ff4d4d',
          high: '#ff8c00',
          medium: '#ffcc00',
          low: '#00ccff',
          info: '#a0a0a0',
        }
      }
    },
  },
  plugins: [],
}
