/**
 * Sprint 1 — after login a technician lands on their work, not on a dashboard.
 *
 * The destination is centralised so the eight entry points that redirect after
 * authentication cannot drift apart again.
 */

import { POST_LOGIN_LANDING } from "@/lib/auth";

test("authenticated users land on My Work", () => {
  expect(POST_LOGIN_LANDING).toBe("/work");
});

test("no auth entry point hardcodes its own post-login destination", () => {
  const fs = require("fs");
  const path = require("path");

  const entryPoints = [
    "app/login/page.tsx",
    "app/auth/callback/page.tsx",
    "app/msp/login/page.tsx",
    "app/msp/signup/page.tsx",
    "app/preview-login/page.tsx",
    "app/onboarding/page.tsx",
    "app/msp/confirm-tenant/page.tsx",
  ];

  const offenders = entryPoints.filter((file) => {
    const source = fs.readFileSync(path.join(process.cwd(), file), "utf8");
    return /(replace|href\s*=)\s*\(?\s*["']\/dashboard["']/.test(source);
  });

  expect(offenders).toEqual([]);
});
