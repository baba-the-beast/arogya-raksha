import { resolve } from "path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "./"),
    },
  },
  define: {
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV || "production"),
  },
  build: {
    outDir: "app/static/dist",
    emptyOutDir: true,
    lib: {
      entry: resolve(__dirname, "src/main.tsx"),
      name: "OrbitHero",
      formats: ["es"],
      fileName: () => "orbit-hero.bundle.js",
    },
    rollupOptions: {
      output: {
        entryFileNames: "orbit-hero.bundle.js",
      },
    },
  },
});
