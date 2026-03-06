import { test, expect } from "@playwright/test";

test.describe("Shareable URLs", () => {
  test("/?secid= auto-resolves on page load", async ({ page }) => {
    await page.goto(
      "/?secid=secid%3Aadvisory%2Fmitre.org%2Fcve%23CVE-2021-44228"
    );
    await page.waitForLoadState("networkidle");

    // Input should be populated
    await expect(page.locator("#resolver-input")).toHaveValue(
      "secid:advisory/mitre.org/cve#CVE-2021-44228"
    );

    // Results should appear
    const badge = page.locator(".status-badge");
    await expect(badge).toBeVisible({ timeout: 15_000 });
    await expect(badge).toHaveAttribute("data-status", "found");
  });

  test("form submission updates URL with ?secid=", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await page
      .locator("#resolver-input")
      .fill("secid:advisory/mitre.org/cve#CVE-2021-44228");
    await page.locator('button[type="submit"]').click();

    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    // URL should now contain ?secid=
    const url = new URL(page.url());
    expect(url.searchParams.get("secid")).toBe(
      "secid:advisory/mitre.org/cve#CVE-2021-44228"
    );
  });

  test("example button click updates URL", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await page
      .locator(
        'button[data-example="secid:advisory/mitre.org/cve#CVE-2021-44228"]'
      )
      .click();

    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    const url = new URL(page.url());
    expect(url.searchParams.get("secid")).toBe(
      "secid:advisory/mitre.org/cve#CVE-2021-44228"
    );
  });

  test("/resolve?secid= redirects to /?secid= and resolves", async ({
    page,
  }) => {
    await page.goto(
      "/resolve?secid=secid%3Aadvisory%2Fmitre.org%2Fcve%23CVE-2021-44228"
    );
    await page.waitForLoadState("networkidle");

    // Should have redirected to /
    const url = new URL(page.url());
    expect(url.pathname).toBe("/");
    expect(url.searchParams.get("secid")).toBe(
      "secid:advisory/mitre.org/cve#CVE-2021-44228"
    );

    // Results should appear
    const badge = page.locator(".status-badge");
    await expect(badge).toBeVisible({ timeout: 15_000 });
    await expect(badge).toHaveAttribute("data-status", "found");
  });

  test("close button clears ?secid= from URL", async ({ page }) => {
    await page.goto(
      "/?secid=secid%3Aadvisory%2Fmitre.org%2Fcve%23CVE-2021-44228"
    );
    await page.waitForLoadState("networkidle");
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    await page.locator(".output-close-btn").click();
    await expect(page.locator("#resolver-output")).toBeHidden();

    // URL should no longer have ?secid=
    const url = new URL(page.url());
    expect(url.searchParams.has("secid")).toBe(false);
  });

  test("browser back button navigates between searches", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // First search
    await page.locator("#resolver-input").fill("secid:weakness/mitre.org/cwe#CWE-79");
    await page.locator('button[type="submit"]').click();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    // Second search
    await page.locator("#resolver-input").fill("secid:advisory/mitre.org/cve#CVE-2021-44228");
    await page.locator('button[type="submit"]').click();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    // Go back — should show first search
    await page.goBack();
    await expect(page.locator("#resolver-input")).toHaveValue(
      "secid:weakness/mitre.org/cwe#CWE-79"
    );

    // Go back again — should clear
    await page.goBack();
    await expect(page.locator("#resolver-input")).toHaveValue("");
    await expect(page.locator("#resolver-output")).toBeHidden();
  });

  test("page title updates on resolve and resets on close", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const defaultTitle = await page.title();

    await page
      .locator(
        'button[data-example="secid:advisory/mitre.org/cve#CVE-2021-44228"]'
      )
      .click();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    // Title should reflect the query
    await expect(page).toHaveTitle(/CVE-2021-44228/);

    // Close and check title resets
    await page.locator(".output-close-btn").click();
    await expect(page).toHaveTitle(defaultTitle);
  });
});
