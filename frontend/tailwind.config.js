/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Core Blue-and-White Enterprise Palette
        background: '#F0F6FC',
        surface: '#FFFFFF',
        'surface-subtle': '#E5F0FC',
        'surface-muted': '#F4F8FC',
        border: '#D7E3F0',
        'border-strong': '#B9D1EA',
        'border-focus': '#3478C8',
        navy: {
          950: '#0A1C33',
          900: '#102B4E', // Deep navy
          800: '#153B66', // Primary navy
          700: '#1E4C80',
          600: '#2A5F9E',
        },
        brand: {
          navy: '#153B66',
          'deep-navy': '#102B4E',
          blue: '#2563A6',
          interactive: '#3478C8',
          subtle: '#E5F0FC',
          light: '#F0F6FC',
        },
        accent: {
          DEFAULT: '#2563A6', // Primary blue
          hover: '#1B4D82',
          interactive: '#3478C8',
          subtle: '#E5F0FC',
          border: '#B9D1EA',
        },
        charcoal: {
          900: '#172B45', // Primary text
          800: '#253852',
          700: '#3D506B',
          600: '#5B6B80', // Secondary text
          500: '#738499',
          400: '#91A1B5',
        },
        severity: {
          critical: '#DC2626',
          'critical-bg': '#FEF2F2',
          'critical-border': '#FECACA',
          high: '#EA580C',
          'high-bg': '#FFF7ED',
          'high-border': '#FED7AA',
          medium: '#D97706',
          'medium-bg': '#FFFBEB',
          'medium-border': '#FDE68A',
          low: '#16A34A',
          'low-bg': '#F0FDF4',
          'low-border': '#BBF7D0',
          info: '#5B6B80',
          'info-bg': '#F0F6FC',
          'info-border': '#D7E3F0',
        }
      },
      fontFamily: {
        sans: ['Inter', 'IBM Plex Sans', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['IBM Plex Mono', 'Menlo', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(16, 43, 78, 0.05), 0 1px 2px -1px rgba(16, 43, 78, 0.03)',
        'card-hover': '0 6px 18px -2px rgba(16, 43, 78, 0.08), 0 2px 6px -2px rgba(16, 43, 78, 0.04)',
        'sidebar': '2px 0 12px 0 rgba(10, 28, 51, 0.15)',
        'button-primary': '0 2px 4px 0 rgba(37, 99, 166, 0.25)',
      }
    },
  },
  plugins: [],
}
