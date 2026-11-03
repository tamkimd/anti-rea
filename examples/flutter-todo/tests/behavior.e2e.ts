import { createRequire } from 'node:module';

const require = createRequire(`${process.env.ANTI_REA_E2E_RUNTIME}/package.json`);
const { test } = require('@e2e-dev/web');
const { expect } = require('e2e');

test('Flutter Todo adds a task and marks it complete', async ({ app, screen, browser }) => {
  await app.open('/');
  await browser.evaluate(async () => {
    for (let i = 0; i < 40; i++) {
      const placeholder = document.querySelector('flt-semantics-placeholder');
      if (placeholder) { placeholder.click(); return; }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error('Flutter web accessibility placeholder did not appear');
  });
  await screen.getByRole('button').last().click();
  await screen.getByRole('textbox').pressSequentially('Anti-REA example task');
  await screen.getByText('Save').click();

  const checkbox = screen.getByRole('checkbox', 'Anti-REA example task');
  await checkbox.click();
  await expect(checkbox).toBeChecked();
});
