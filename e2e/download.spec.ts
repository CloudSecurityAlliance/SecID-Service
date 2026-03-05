import { test, expect } from "@playwright/test";

test.describe("Registry Download", () => {
  test("registry JSON download returns valid JSON with expected types", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Set up download listener before clicking
    const downloadPromise = page.waitForEvent("download");
    await page.locator(".registry-link").click();
    const download = await downloadPromise;

    // Verify download happened
    expect(download.suggestedFilename()).toBe("secid-registry.json");

    // Read and parse the downloaded file
    const path = await download.path();
    expect(path).toBeTruthy();

    const fs = await import("fs");
    const content = fs.readFileSync(path!, "utf-8");
    const data = JSON.parse(content);

    // Verify expected top-level structure
    expect(data).toHaveProperty("advisory");
    expect(data).toHaveProperty("weakness");
    expect(data).toHaveProperty("ttp");
    expect(data).toHaveProperty("control");
  });
});
