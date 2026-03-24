/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0b1020',
          panel: '#131a2a',
          panelAlt: '#1a2337',
          accent: '#00ffa6',
          muted: '#8ea0c9',
        },
      },
    },
  },
  plugins: [],
};
