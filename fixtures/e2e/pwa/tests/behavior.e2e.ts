import { test } from '@e2e-dev/web';
import { expect } from 'e2e';

test('service worker caches a resource and activates a new worker revision', async ({ app, browser }) => {
  await app.open('/');
  await browser.evaluate(async () => {
    await navigator.serviceWorker.ready;
    const registration = await navigator.serviceWorker.getRegistration();
    if (!registration?.active) throw new Error('service worker did not activate');
    const response = await fetch('/offline.txt');
    if (await response.text() !== 'cached fixture response') throw new Error('unexpected resource body');
    const keys = await caches.keys();
    if (!keys.includes('pwa-fixture-v1')) throw new Error('initial versioned cache was not created');
    const cached = await caches.match('/offline.txt');
    if (!cached || await cached.text() !== 'cached fixture response') throw new Error('offline resource is not cached');
    await fetch('/enable-update');
    await registration.update();
    const installing = registration.installing;
    if (!installing) throw new Error('updated worker did not install');
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('updated worker did not reach installed state')), 5000);
      installing.addEventListener('statechange', () => {
        if (installing.state === 'installed') { clearTimeout(timeout); resolve(); }
        if (installing.state === 'redundant') { clearTimeout(timeout); reject(new Error('updated worker became redundant')); }
      });
    });
    if (!registration.waiting) throw new Error('updated worker was not waiting');
    registration.waiting.postMessage('activate-update');
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('new worker did not activate')), 5000);
      navigator.serviceWorker.addEventListener('controllerchange', () => { clearTimeout(timeout); resolve(); }, { once: true });
    });
    const deadline = Date.now() + 5000;
    let updatedKeys = await caches.keys();
    while ((!updatedKeys.includes('pwa-fixture-v2') || updatedKeys.includes('pwa-fixture-v1')) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 50));
      updatedKeys = await caches.keys();
    }
    if (!updatedKeys.includes('pwa-fixture-v2') || updatedKeys.includes('pwa-fixture-v1')) {
      throw new Error('activation cache state: ' + JSON.stringify(updatedKeys));
    }
    await fetch('/go-offline');
    const offlineResponse = await fetch('/offline.txt');
    if (await offlineResponse.text() !== 'cached fixture response') throw new Error('cached fallback failed while network was unavailable');
    await registration.unregister();
  });
  await expect(browser.locator('title')).toHaveText('PWA fixture');
});
