import { expect, test } from "@playwright/test";

test.describe("smoke", () => {
  test("login page renders with form", async ({ page }) => {
    await page.goto("/login");
    await expect(page).toHaveTitle(/IR-?SAM|Next/i);
    await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  });

  test("unauthenticated dashboard redirects to login", async ({ page }) => {
    const response = await page.goto("/dashboard");
    // middleware should send us to /login
    await page.waitForURL(/\/login(\?|$)/);
    expect(response).toBeTruthy();
    await expect(page.getByRole("heading", { name: /welcome back/i })).toBeVisible();
  });

  test("root redirects to dashboard (and then to login)", async ({ page }) => {
    await page.goto("/");
    await page.waitForURL(/\/login(\?|$)/);
  });
});
