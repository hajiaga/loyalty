/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: '#2C5282', // Blue
        success: '#38A169', // Green
        danger: '#E53E3E', // Red
        'primary-dark': '#1A365D',
        'primary-light': '#4A7BA7',
        'success-light': '#68D391',
        'danger-light': '#FC8181',
      },
      fontFamily: {
        sans: ['Inter', 'Roboto', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
