import { test } from '@e2e-dev/web';
import { expect } from 'e2e';

test('TodoMVC rejects blank input, adds, toggles, and filters one todo', async ({ app, screen, browser }) => {
  await app.open('/');
  const input = screen.getByLabel('New Todo Input');
  const items = screen.getByTestId('todo-list').getByRole('listitem');

  await input.fill('   ');
  await input.press('Enter');
  await expect(items).toHaveCount(0);

  await input.fill('Anti-REA example task');
  await input.press('Enter');
  await expect(items).toHaveCount(1);
  await expect(items.first()).toContainText('Anti-REA example task');

  await screen.getByTestId('todo-item-toggle').check();
  await expect(browser).toHaveClass(screen.getByTestId('todo-item'), /completed/);

  await screen.getByRole('link', 'Active').click();
  await expect(items).toHaveCount(0);
  await screen.getByRole('link', 'Completed').click();
  await expect(items).toHaveCount(1);
});
