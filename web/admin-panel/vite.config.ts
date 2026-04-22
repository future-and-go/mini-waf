import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// PRX-WAF Admin Panel
//   - Dev: Vite serves at http://localhost:5174, proxies /api + /ws to :9527
//   - Prod: dist/ is embedded into the Rust binary via `rust_embed`
//           (crates/waf-api/src/static_files.rs) and served by prx-waf at
//           http://<host>:9527/ui/.
//   Base path `/ui/` so every asset URL in the generated index.html is
//   prefixed correctly and matches the Rust static handler, which strips
//   the `/ui/` prefix before looking up files in the embedded archive.
export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        // Function-style chunker: ensures React is isolated into ONE chunk
        // that loads before any consumer. The object-style manualChunks we
        // had before caused antd to crash with
        //   "Cannot read properties of undefined (reading
        //    '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED')"
        // because React ended up bundled in a sibling chunk rather than a
        // shared dependency. Matching by absolute `node_modules/x/` path is
        // unambiguous and keeps the cache-split benefits.
        manualChunks(id) {
          if (
            id.includes("/node_modules/react/") ||
            id.includes("/node_modules/react-dom/") ||
            id.includes("/node_modules/scheduler/")
          ) {
            return "react-vendor";
          }
          if (
            id.includes("/node_modules/antd/") ||
            id.includes("/node_modules/@ant-design/icons/") ||
            id.includes("/node_modules/rc-")
          ) {
            return "antd-vendor";
          }
          if (
            id.includes("/node_modules/@ant-design/plots/") ||
            id.includes("/node_modules/@ant-design/charts/") ||
            id.includes("/node_modules/@antv/")
          ) {
            return "charts-vendor";
          }
          if (id.includes("/node_modules/@refinedev/")) {
            return "refine-vendor";
          }
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5174,
    proxy: {
      "/api": {
        target: "http://localhost:9527",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://localhost:9527",
        ws: true,
      },
    },
  },
});
