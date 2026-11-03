import { test } from '@e2e-dev/web';
import { expect } from 'e2e';

test('preserves the greeting journey', async ({ app, screen }) => {
  await app.open('/');
  await screen.getByRole('button', 'Greet').click();
  await expect(screen.getByRole('status')).toHaveText('Name is required.');
  await screen.getByLabel('Name').fill('Ada');
  await screen.getByRole('button', 'Greet').click();
  await expect(screen.getByRole('status')).toHaveText('Hello, Ada!');
});
