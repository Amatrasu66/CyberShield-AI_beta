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
        background: '#13131b',
        surface: '#13131b',
        'surface-lowest': '#0d0d15',
        'surface-low': '#1b1b23',
        'surface-container': '#1f1f27',
        'surface-high': '#292932',
        'surface-bright': '#393841',
        'on-surface': '#e4e1ed',
        'on-surface-variant': '#c7c4d7',
        outline: '#908fa0',
        'outline-variant': '#464554',
        primary: {
          DEFAULT: '#c0c1ff',
          container: '#8083ff',
          foreground: '#1000a9',
        },
        secondary: '#89ceff',
        success: '#72dfa5',
        danger: '#ffb4ab',
        warning: '#ffb783',
      },
      fontFamily: { display: ['Geist', 'sans-serif'], body: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
      borderRadius: { DEFAULT: '0.25rem', lg: '0.5rem', xl: '0.75rem' },
    },
  },
  plugins: [],
}
