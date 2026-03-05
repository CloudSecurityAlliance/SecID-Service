import { test, expect } from "@playwright/test";

test.describe("Registry Explorer", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("explore button opens type grid with 7 types", async ({ page }) => {
    await page.locator("#explore-btn").click();
    await expect(page.locator("#resolver-output")).toBeVisible();

    const grid = page.locator(".explorer-type-grid");
    await expect(grid).toBeVisible();
    await expect(page.locator(".explorer-type-card")).toHaveCount(7);
  });

  test("clicking a type card shows namespaces", async ({ page }) => {
    await page.locator("#explore-btn").click();
    await expect(page.locator(".explorer-type-grid")).toBeVisible();

    // Click the "advisory" type card
    await page.locator(".explorer-type-card", { hasText: "advisory" }).click();

    // Wait for namespaces to load
    const breadcrumbs = page.locator(".explorer-breadcrumbs");
    await expect(breadcrumbs).toBeVisible({ timeout: 15_000 });
    await expect(breadcrumbs).toContainText("advisory");

    // Should show namespace items (e.g., mitre.org)
    const items = page.locator(".explorer-item");
    await expect(items.first()).toBeVisible({ timeout: 15_000 });
    const count = await items.count();
    expect(count).toBeGreaterThan(0);
  });

  test("clicking a namespace shows sources", async ({ page }) => {
    await page.locator("#explore-btn").click();
    await expect(page.locator(".explorer-type-grid")).toBeVisible();

    // Navigate to advisory
    await page.locator(".explorer-type-card", { hasText: "advisory" }).click();
    await expect(page.locator(".explorer-item").first()).toBeVisible({
      timeout: 15_000,
    });

    // Click a namespace (look for one with "mitre")
    const mitreItem = page.locator(".explorer-item", { hasText: "mitre" });
    if ((await mitreItem.count()) > 0) {
      await mitreItem.first().click();

      // Breadcrumbs should show deeper path
      const breadcrumbs = page.locator(".explorer-breadcrumbs");
      await expect(breadcrumbs).toContainText("mitre", { timeout: 15_000 });
    }
  });

  test("breadcrumb navigation goes back to type grid", async ({ page }) => {
    await page.locator("#explore-btn").click();
    await expect(page.locator(".explorer-type-grid")).toBeVisible();

    // Drill into advisory
    await page.locator(".explorer-type-card", { hasText: "advisory" }).click();
    await expect(page.locator(".explorer-item").first()).toBeVisible({
      timeout: 15_000,
    });

    // Click "Registry" breadcrumb to go back to root
    const registryLink = page.locator(".explorer-breadcrumbs a", {
      hasText: "Registry",
    });
    await registryLink.click();

    // Type grid should reappear
    await expect(page.locator(".explorer-type-grid")).toBeVisible();
    await expect(page.locator(".explorer-type-card")).toHaveCount(7);
  });
});
