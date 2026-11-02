import type { NextConfig } from "next";

// Settings (DB passwords, AUTH_SECRET) live in <repo>/.env, shared with
// docker compose and the Python ETL. Server code reads them through
// lib/env.ts, which loads that file on first use.

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  poweredByHeader: false,
  // Database drivers must stay on the server and are not bundled.
  serverExternalPackages: ["mysql2", "neo4j-driver", "bcryptjs"],
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
