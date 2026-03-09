import assert from 'node:assert/strict';
import test from 'node:test';
import { SpacesRegistry } from '../src/api/tools/spaces-registry.ts';

const scope = {
  tenantId: 'ica',
  jurisdiction: 'ES',
  sector: 'animal-care',
};

test('SpacesRegistry hides api key fields in public list output', () => {
  const registry = new SpacesRegistry([
    {
      did: 'did:web:id.delta-dao.com',
      endpointUrl: 'https://adapter.example.org/dummy-sync',
      apiKey: 'secret-inline',
    },
  ]);

  const targets = registry.list(scope);
  assert.equal(targets.length, 1);
  assert.equal(targets[0]?.identifier, 'did:web:id.delta-dao.com');
  assert.equal(targets[0]?.url, 'https://adapter.example.org/dummy-sync');
  assert.equal((targets[0] as { endpointUrl?: string })?.endpointUrl, undefined);
  assert.equal((targets[0] as { did?: string })?.did, undefined);
  assert.equal((targets[0] as { id?: string })?.id, undefined);
});

test('SpacesRegistry preserves api key for sync targets only', () => {
  const registry = new SpacesRegistry();
  registry.replace(scope, [
    {
      did: 'did:web:id.delta-dao.com',
      endpointUrl: 'https://adapter.example.org/dummy-sync',
      apiKey: 'secret-inline',
    },
  ]);

  const publicTargets = registry.list(scope);
  assert.equal((publicTargets[0] as { apiKey?: string })?.apiKey, undefined);
  assert.equal(publicTargets[0]?.identifier, 'did:web:id.delta-dao.com');

  const syncTargets = registry.resolveForSync(scope);
  assert.equal(syncTargets[0]?.apiKey, 'secret-inline');
});
