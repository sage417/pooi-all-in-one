import {defineConfig} from 'vite';
import tsconfigPaths from 'vite-tsconfig-paths'
import {builtinModules} from 'module'

// https://vitejs.dev/config
export default defineConfig(async () => {

  return {
    plugins: [tsconfigPaths(), ],
    build: {
      rollupOptions: {
        external: ['koffi', 'electron', ...builtinModules],
      },
    },
  };
});