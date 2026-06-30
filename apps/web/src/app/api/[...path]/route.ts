/**
 * Runtime proxy: forwards /api/* → backend API.
 *
 * Unlike next.config.mjs rewrites() which are evaluated at build time,
 * this route handler runs on every request and reads env vars at runtime.
 * This means API_INTERNAL_BASE (set in docker-compose) is always respected.
 */

import { NextRequest, NextResponse } from "next/server";

// Server-side (inside Docker): use the internal service name.
// Local dev: falls back to NEXT_PUBLIC_API_BASE or localhost:8000.
const API_BASE =
  process.env.API_INTERNAL_BASE ||
  process.env.NEXT_PUBLIC_API_BASE ||
  "http://localhost:8000";

async function proxy(req: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join("/");
  const search = req.nextUrl.search ?? "";
  const target = `${API_BASE}/${path}${search}`;

  // Forward body for non-GET requests
  const body =
    req.method !== "GET" && req.method !== "HEAD"
      ? await req.arrayBuffer()
      : undefined;

  // Forward relevant headers (but not host)
  const headers = new Headers();
  req.headers.forEach((val, key) => {
    if (["host", "connection", "transfer-encoding"].includes(key)) return;
    headers.set(key, val);
  });

  const upstream = await fetch(target, {
    method: req.method,
    headers,
    body: body ? Buffer.from(body) : undefined,
    // @ts-expect-error -- Node 18+ fetch option
    duplex: "half",
  });

  // Stream response back, preserving headers (especially Set-Cookie for auth)
  const respHeaders = new Headers();
  upstream.headers.forEach((val, key) => {
    respHeaders.set(key, val);
  });

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}

export const GET     = proxy;
export const POST    = proxy;
export const PUT     = proxy;
export const PATCH   = proxy;
export const DELETE  = proxy;
export const HEAD    = proxy;
export const OPTIONS = proxy;
