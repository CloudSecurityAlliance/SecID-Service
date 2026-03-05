import { test, expect } from "@playwright/test";

test.describe("External Links", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("CVE result URL leads to cve.org", async ({ page }) => {
    await page
      .locator(
        'button[data-example="secid:advisory/mitre.org/cve#CVE-2021-44228"]'
      )
      .click();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    const link = page.locator(".result-item a[href*='cve.org']");
    await expect(link).toBeVisible();
    const href = await link.getAttribute("href");
    expect(href).toContain("cve.org");

    // HTTP check — verify the URL is reachable
    const response = await page.request.get(href!);
    expect(response.ok()).toBe(true);
  });

  test("CWE result URL leads to cwe.mitre.org", async ({ page }) => {
    await page
      .locator(
        'button[data-example="secid:weakness/mitre.org/cwe#CWE-79"]'
      )
      .click();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    const link = page.locator(".result-item a[href*='cwe.mitre.org']");
    await expect(link).toBeVisible();
    const href = await link.getAttribute("href");
    expect(href).toContain("cwe.mitre.org");

    const response = await page.request.get(href!);
    expect(response.ok()).toBe(true);
  });

  test("ATT&CK result URL leads to attack.mitre.org", async ({ page }) => {
    await page
      .locator(
        'button[data-example="secid:ttp/mitre.org/attack#T1059.003"]'
      )
      .click();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    const link = page.locator(".result-item a[href*='attack.mitre.org']");
    await expect(link).toBeVisible();
    const href = await link.getAttribute("href");
    expect(href).toContain("attack.mitre.org");

    const response = await page.request.get(href!);
    expect(response.ok()).toBe(true);
  });
});
