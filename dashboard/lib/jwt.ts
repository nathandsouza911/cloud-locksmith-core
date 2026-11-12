/**
 * lib/jwt.ts
 * Minimal JWT decoder — reads the payload without verifying the signature.
 * Verification is the backend's responsibility.
 */

interface JwtPayload {
  sub?: string; // user_id
  user_id?: string;
  tenant_id?: string;
  tenant_ids?: string[];
  email?: string;
  exp?: number;
  [key: string]: unknown;
}

export function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    // Base64url → base64 → JSON
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

export function isTokenExpired(token: string): boolean {
  const payload = decodeJwt(token);
  if (!payload?.exp) return false;
  return payload.exp * 1000 < Date.now();
}
