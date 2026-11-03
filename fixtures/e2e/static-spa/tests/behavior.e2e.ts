import { test } from '@e2e-dev/web';
import { expect } from 'e2e';

test('serves the built SPA greeting journey', async ({ app, screen, browser }) => {
  await app.open('/');
  const navigation = await browser.evaluate(() => {
    const entry = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    return { dom_content_loaded_ms: entry.domContentLoadedEventEnd - entry.startTime,
      load_event_ms: entry.loadEventEnd - entry.startTime };
  });
  await screen.getByRole('button', 'Greet').click();
  await expect(screen.getByRole('status')).toHaveText('Name is required.');
  await browser.evaluate(() => performance.mark('anti-rea-interaction-start'));
  await screen.getByLabel('Name').fill('Ada');
  await screen.getByRole('button', 'Greet').click();
  await expect(screen.getByRole('status')).toHaveText('Hello, Ada!');
  const interaction_ms = await browser.evaluate(() => {
    performance.mark('anti-rea-interaction-end');
    return performance.measure('anti-rea-greeting-interaction', 'anti-rea-interaction-start',
      'anti-rea-interaction-end').duration;
  });
  await browser.evaluate((metrics) => console.info('ANTI_REA_PERFORMANCE ' + JSON.stringify(metrics)),
    { ...navigation, interaction_ms });
});
