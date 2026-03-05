import { test, expect } from "@playwright/test";

test.describe("Resolver", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
  });

  test("page loads with resolver form visible", async ({ page }) => {
    await expect(page.locator("#resolver-form")).toBeVisible();
    await expect(page.locator("#resolver-input")).toBeVisible();
    await expect(page.locator("#resolver-input")).toHaveValue("");
    await expect(page.locator("button[data-example]")).toHaveCount(5);
  });

  const examples = [
    {
      label: "CVE",
      secid: "secid:advisory/mitre.org/cve#CVE-2021-44228",
      status: "found",
    },
    {
      label: "CWE",
      secid: "secid:weakness/mitre.org/cwe#CWE-79",
      status: "found",
    },
    {
      label: "ATT&CK",
      secid: "secid:ttp/mitre.org/attack#T1059.003",
      status: "found",
    },
    {
      label: "Cross-source",
      secid: "secid:advisory/CVE-2024-1234",
      // Cross-source may return found or related depending on registry data
      status: /found|related/,
    },
    {
      label: "Browse weaknesses",
      secid: "secid:weakness",
      status: "found",
    },
  ];

  for (const ex of examples) {
    test(`example button "${ex.label}" fills input and shows results`, async ({
      page,
    }) => {
      const btn = page.locator(`button[data-example="${ex.secid}"]`);
      await btn.click();

      await expect(page.locator("#resolver-input")).toHaveValue(ex.secid);
      await expect(page.locator("#resolver-output")).toBeVisible();

      // Wait for the status badge to appear (means API responded)
      const badge = page.locator(".status-badge");
      await expect(badge).toBeVisible({ timeout: 15_000 });

      if (typeof ex.status === "string") {
        await expect(badge).toHaveAttribute("data-status", ex.status);
      } else {
        const status = await badge.getAttribute("data-status");
        expect(status).toMatch(ex.status);
      }
    });
  }

  test("manual form submission works", async ({ page }) => {
    await page
      .locator("#resolver-input")
      .fill("secid:advisory/mitre.org/cve#CVE-2023-44487");
    await page.locator('button[type="submit"]').click();

    const badge = page.locator(".status-badge");
    await expect(badge).toBeVisible({ timeout: 15_000 });
    await expect(badge).toHaveAttribute("data-status", "found");

    // Result should contain a link to cve.org
    const resultLink = page.locator(".result-item a[href*='cve.org']");
    await expect(resultLink).toBeVisible();
  });

  test("empty query does not show output", async ({ page }) => {
    // The form handler silently returns on empty input
    await page.locator("#resolver-input").fill("");
    await page.locator('button[type="submit"]').click();

    // Output should remain hidden
    await expect(page.locator("#resolver-output")).toBeHidden();
  });

  test("close button hides output", async ({ page }) => {
    // Trigger results via an example button
    await page
      .locator(
        'button[data-example="secid:advisory/mitre.org/cve#CVE-2021-44228"]'
      )
      .click();
    await expect(page.locator("#resolver-output")).toBeVisible();
    await expect(page.locator(".status-badge")).toBeVisible({
      timeout: 15_000,
    });

    // Click the close button
    await page.locator(".output-close-btn").click();
    await expect(page.locator("#resolver-output")).toBeHidden();
  });
});
