/**
 * Flow contract:
 * - Firestore collection reads page deterministically by document id.
 * - A collection larger than one page returns every record exactly once.
 * - The next query starts after the final document of the previous page.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { VerificationCollectionsFirestoreAdapter } from '../src/api/tools/verification-collections/adapters.ts';

function buildFakeFirestore(records: Array<Record<string, unknown>>) {
  const documents = records.map((record, index) => ({
    id: `doc-${String(index).padStart(4, '0')}`,
    data: () => record,
  }));
  const requestedPages: Array<{ startAfterId?: string; limit: number }> = [];

  const collection = {
    orderBy(field: string) {
      assert.equal(field, '__name__');
      let startAfterId: string | undefined;
      let pageLimit = 0;
      const query = {
        limit(limit: number) {
          pageLimit = limit;
          return query;
        },
        startAfter(document: { id: string }) {
          startAfterId = document.id;
          return query;
        },
        async get() {
          requestedPages.push({ ...(startAfterId ? { startAfterId } : {}), limit: pageLimit });
          const startIndex = startAfterId
            ? documents.findIndex((document) => document.id === startAfterId) + 1
            : 0;
          return { docs: documents.slice(startIndex, startIndex + pageLimit) };
        },
      };
      return query;
    },
  };

  return {
    client: {
      collection() {
        return collection;
      },
    },
    requestedPages,
  };
}

test('Firestore adapter returns records beyond the first 200-document page', async () => {
  const source = Array.from({ length: 205 }, (_, index) => ({
    id: `credential-${index}`,
    createdAt: new Date(index * 1000).toISOString(),
  }));
  const fake = buildFakeFirestore(source);
  const adapter = new VerificationCollectionsFirestoreAdapter({
    provider: 'firestore',
    required: true,
    firestoreProjectId: 'example-project',
    firestoreCollectionPrefix: 'test',
  });
  (adapter as unknown as { firestoreClientPromise: Promise<unknown> }).firestoreClientPromise =
    Promise.resolve(fake.client);

  const records = await adapter.listIssuedCredentials();

  assert.equal(records.length, 205);
  assert.deepEqual(records, source);
  assert.deepEqual(fake.requestedPages, [
    { limit: 200 },
    { startAfterId: 'doc-0199', limit: 200 },
  ]);
});
