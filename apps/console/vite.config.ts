import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'FG_CONSOLE_');
  const target = new URL(env.FG_CONSOLE_CONTROL_URL || 'http://127.0.0.1:8081');
  if (target.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname) || target.username || target.password || target.pathname !== '/' || target.search || target.hash) {
    throw new Error('FG_CONSOLE_CONTROL_URL must be an HTTP origin on loopback, without credentials.');
  }
  const proxy = {
    '^/api/(?:v1/(?:branches(?:/|$)|capabilities$|policies/|github/bindings$)|health/(?:live|ready)$)': {
      target: target.origin, rewrite: (path: string) => path.replace(/^\/api/, '')
    }
  };
  return {
    plugins: [sveltekit()],
    server: { host: '127.0.0.1', port: 4193, strictPort: true, proxy, fs: { strict: true } },
    preview: { host: '127.0.0.1', port: 4194, strictPort: true, proxy },
    test: { include: ['src/**/*.test.ts'], environment: 'node' }
  };
});
