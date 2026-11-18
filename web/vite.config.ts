import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The same policy that the admin listener sends (docs/API.md, section 3.4).
// "vite preview" sends it too, so a preview shows CSP faults in the console.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const apiTarget = env.RUSTHOLE_API || 'https://127.0.0.1:8443';
  return {
    plugins: [svelte()],
    // Component tests mount Svelte in happy-dom. They need the browser build of Svelte.
    resolve: mode === 'test' ? { conditions: ['browser'] } : undefined,
    build: {
      outDir: 'dist',
      target: 'es2022',
      sourcemap: false,
      assetsInlineLimit: 0,
      modulePreload: { polyfill: false },
    },
    server: {
      // Tests read the packaged config (packaging/rusthole.toml) as test data.
      fs: mode === 'test' ? { allow: ['.', '../packaging'] } : undefined,
      // Mode "api" sends /api to a real rusthole. The admin listener uses a
      // self-signed certificate in development, so do not check it here.
      proxy:
        mode === 'api'
          ? { '/api': { target: apiTarget, changeOrigin: true, secure: false } }
          : undefined,
    },
    preview: {
      headers: { 'Content-Security-Policy': CSP },
    },
    test: {
      include: ['src/**/*.test.ts'],
      environment: 'node',
    },
  };
});
