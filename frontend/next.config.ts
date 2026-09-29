import type { NextConfig } from "next";

const api = process.env.PHISHING_CHECKER_API_ORIGIN;

const nextConfig: NextConfig = {
  async rewrites() {
    if (!api) return [];
    return [
      { source: "/api/analyze", destination: `${api}/api/analyze` },
      { source: "/api/health", destination: `${api}/api/health` },
    ];
  },
};

export default nextConfig;
