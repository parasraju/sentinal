import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  publicDir: false,
  build: {
    outDir: "dist/content",
    emptyOutDir: false,
    target: "chrome116",
    minify: "esbuild",
    sourcemap: false,
    lib: {
      entry: resolve(__dirname, "src/content/index.ts"),
      name: "SentinelContent",
      formats: ["iife"],
      fileName: () => "content-script.js",
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
});
