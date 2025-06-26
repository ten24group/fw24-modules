import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  root: path.resolve(process.cwd(), 'src/ui'),
  base: './',
  build: {
    lib: {
      entry: path.resolve(process.cwd(), 'src/ui/index.tsx'),
      name: 'AuthWidget',
      fileName: () => 'widget',
      formats: [ 'iife' ],
    },
    outDir: path.resolve(process.cwd(), 'dist/ui'),
    emptyOutDir: true,
  },
  plugins: [ react() ],
}); 