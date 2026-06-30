/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: { typedRoutes: false },
  // API proxying is handled at runtime by src/app/api/[...path]/route.ts
  // which reads API_INTERNAL_BASE at request time (works correctly in Docker).
};
export default nextConfig;

