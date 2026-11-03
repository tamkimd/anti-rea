import { test } from '@e2e-dev/web';
import { expect } from 'e2e';

test('adds, completes, and filters one todo', async ({ app, screen }) => {
  await app.open('/');
  const items = screen.getByRole('listitem');
  const input = screen.getByLabel('Add a new task');

  await input.fill('');
  await input.press('Enter');
  await expect(items).toHaveCount(0);

  await input.fill('Anti-REA example task');
  await screen.getByRole('button', 'Add task').click();
  await expect(items).toHaveCount(1);
  await expect(items.first()).toContainText('Anti-REA example task');

  await screen.getByRole('checkbox', 'Mark as completed').check();
  await screen.getByRole('tab', 'Active').click();
  await expect(items).toHaveCount(0);
  await screen.getByRole('tab', 'Completed').click();
  await expect(items).toHaveCount(1);
});
