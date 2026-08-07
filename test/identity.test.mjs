/**
 * Hub-scoped identity distribution (identity-distribution-v1.md IDENT-xx).
 *
 * The forgery case below is the point of this file. Every member of a hub holds
 * that hub's secret, so the envelope proves only that *some* member wrote the
 * event: the record's own profile-key signature is the sole barrier to
 * publishing a name under someone else's key. That barrier is one call, and a
 * refactor that drops it leaves every honest assertion passing (TEST-41).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createInMemoryLog, openChannel, createSignedEvent } from 'nearbytes-log';
import { createCryptoOperations, createSecret, bytesToHex, EventType } from 'nearbytes-crypto';
import {
  createIdentityRecord,
  publishIdentitySnapshot,
  readIdentityDirectory,
  readOwnIdentityRecord,
  serializeIdentitySnapshot,
  parseIdentitySnapshotJson,
  IDENTITY_SNAPSHOT_PROTOCOL,
} from '../dist/index.js';

const HUB = 'hub:shared-secret';

async function fixture() {
  const crypto = createCryptoOperations();
  const log = createInMemoryLog();
  const deps = { log, crypto };
  const alice = await crypto.deriveKeys(createSecret('alice:secret'));
  return { crypto, log, deps, alice, alicePk: bytesToHex(alice.publicKey) };
}

test('publishes into the hub channel, not the profile channel', async () => {
  const { deps, alice, alicePk } = await fixture();
  const record = await createIdentityRecord(deps.crypto, alice, { displayName: 'Alice' }, 1000);
  const published = await publishIdentitySnapshot(deps, HUB, alice, record, 'a'.repeat(64), 1000);

  assert.equal(published.snapshot.ref.channel, alicePk, 'ref points at the canonical profile channel');
  assert.notEqual(published.channelPublicKey, alicePk, 'envelope is written under the hub key');
  assert.equal(published.payload.authorPublicKey, alicePk, 'authorship claims the profile key');
});

test('a hub member resolves the name', async () => {
  const { deps, alice, alicePk } = await fixture();
  const record = await createIdentityRecord(deps.crypto, alice, { displayName: 'Alice' }, 1000);
  await publishIdentitySnapshot(deps, HUB, alice, record, 'a'.repeat(64), 1000);

  const dir = await readIdentityDirectory(deps, HUB);
  assert.equal(dir.get(alicePk)?.displayName, 'Alice');
  assert.equal(dir.get(alicePk)?.source, 'snapshot');
});

test('a non-member cannot resolve the name (IDENT-01)', async () => {
  const { deps, alice, alicePk } = await fixture();
  const record = await createIdentityRecord(deps.crypto, alice, { displayName: 'Alice' }, 1000);
  await publishIdentitySnapshot(deps, HUB, alice, record, 'a'.repeat(64), 1000);

  const outsider = await readIdentityDirectory(deps, 'hub:some-other-secret');
  assert.equal(outsider.get(alicePk), undefined, 'readability follows the channel secret');
});

test('a hub member cannot forge a name under another key (IDENT-20..23)', async () => {
  const { crypto, log, deps, alice, alicePk } = await fixture();
  const record = await createIdentityRecord(crypto, alice, { displayName: 'Alice' }, 1000);
  const published = await publishIdentitySnapshot(deps, HUB, alice, record, 'a'.repeat(64), 1000);

  // Mallory holds the hub secret, so she can write a structurally perfect,
  // correctly-encrypted envelope claiming to be Alice — with a newer timestamp
  // so last-writer-wins would prefer it if it were accepted.
  const channel = await openChannel(createSecret(HUB), crypto);
  const hubKeys = await crypto.deriveKeys(channel.secret);
  const stolen = parseIdentitySnapshotJson(published.payload.record);
  const forged = { ...stolen, record: { ...stolen.record, profile: { displayName: 'Eve' } } };
  await log.events.storeEvent(
    hubKeys.publicKey,
    await createSignedEvent(crypto, hubKeys, {
      type: EventType.APP_RECORD,
      protocol: IDENTITY_SNAPSHOT_PROTOCOL,
      authorPublicKey: alicePk,
      record: serializeIdentitySnapshot(forged),
      publishedAt: 9999,
    }, []),
  );

  const dir = await readIdentityDirectory(deps, HUB);
  assert.notEqual(dir.get(alicePk)?.displayName, 'Eve', 'tampered record must be rejected');
  assert.equal(dir.get(alicePk)?.displayName, 'Alice', 'genuine record survives the forgery');
});

test('a newer genuine record wins (IDENT-24)', async () => {
  const { deps, alice, alicePk } = await fixture();
  const first = await createIdentityRecord(deps.crypto, alice, { displayName: 'Alice' }, 1000);
  await publishIdentitySnapshot(deps, HUB, alice, first, 'a'.repeat(64), 1000);
  const second = await createIdentityRecord(deps.crypto, alice, { displayName: 'Alice v2' }, 2000);
  await publishIdentitySnapshot(deps, HUB, alice, second, 'b'.repeat(64), 2000);

  const dir = await readIdentityDirectory(deps, HUB);
  assert.equal(dir.get(alicePk)?.displayName, 'Alice v2');
});

test('cannot publish a record belonging to another profile', async () => {
  const { crypto, deps, alice } = await fixture();
  const mallory = await crypto.deriveKeys(createSecret('mallory:secret'));
  const record = await createIdentityRecord(crypto, alice, { displayName: 'Alice' }, 1000);

  await assert.rejects(
    () => publishIdentitySnapshot(deps, HUB, mallory, record, 'c'.repeat(64), 3000),
    /must be signed by the profile that owns the record/,
  );
});

test('readOwnIdentityRecord returns the latest verified record and its event hash', async () => {
  const { crypto, log, deps, alice, alicePk } = await fixture();
  // Canonical publication lives in the profile's own channel.
  const record = await createIdentityRecord(crypto, alice, { displayName: 'Alice' }, 1000);
  const { serializeIdentityRecord, IDENTITY_RECORD_PROTOCOL } = await import('../dist/index.js');
  const eventHash = await log.events.storeEvent(
    alice.publicKey,
    await createSignedEvent(crypto, alice, {
      type: EventType.APP_RECORD,
      protocol: IDENTITY_RECORD_PROTOCOL,
      authorPublicKey: alicePk,
      record: serializeIdentityRecord(record),
      publishedAt: 1000,
    }, []),
  );

  const own = await readOwnIdentityRecord(deps, 'alice:secret');
  assert.equal(own?.record.profile.displayName, 'Alice');
  assert.equal(own?.eventHash, eventHash, 'hash must match so the snapshot ref is resolvable');
});

test('no identity published yields null rather than throwing', async () => {
  const { deps } = await fixture();
  assert.equal(await readOwnIdentityRecord(deps, 'nobody:secret'), null);
});
