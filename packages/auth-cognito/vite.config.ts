import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  root: path.resolve(process.cwd(), 'src/ui'),
  base: './',
  build: {
    outDir: path.resolve(process.cwd(), 'dist/ui'),
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      input: path.resolve(process.cwd(), 'src/ui/index.html'),
      output: {
        entryFileNames: 'widget.js',
        assetFileNames: ({ name }) => {
          if (name && name.endsWith('.css')) return 'style.css';
          return name || '[name][extname]';
        }
      }
    }
  },
  plugins: [react()],
}); 