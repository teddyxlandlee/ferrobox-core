import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/index.ts'),
      name: 'HelloViteLib',          // UMD 格式的全局变量名（本例未用 UMD，但指定无妨）
      fileName: (format) => {
        // ESM 输出为 index.mjs，CJS 输出为 index.cjs
        if (format === 'es') return 'index.mjs';
        if (format === 'cjs') return 'index.cjs';
        return `index.${format}.js`;
      },
      formats: ['es', 'cjs'],        // 只输出 ESM 和 CJS，浏览器和 Node 都用得到
    },
    rollupOptions: {
      // 如果库有外部依赖，可以在这里排除，本例没有依赖
      external: [],
    },
    outDir: 'dist',
    emptyOutDir: true,
  },
});