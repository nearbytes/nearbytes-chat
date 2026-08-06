import type {
  AppRecordPayload,
  CryptoOperations,
  EventPayload,
  Hash,
  KeyPair,
  PublicKey,
  Secret,
} from 'nearbytes-crypto';
import {
  EventType,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  createHash,
  createPublicKey,
  createSecret,
  createSignature,
  hexToBytes,
} from 'nearbytes-crypto';
import type { EventLogEntry, Log } from 'nearbytes-log';
import { createSignedEvent, loadEventLog, openChannel } from 'nearbytes-log';

export const CHAT_MESSAGE_PROTOCOL = 'nb.chat.message.v1';
export const IDENTITY_RECORD_PROTOCOL = 'nb.identity.record.v1';
export const IDENTITY_SNAPSHOT_PROTOCOL = 'nb.identity.snapshot.v1';

export interface IdentityProfile {
  readonly displayName: string;
  readonly bio?: string;
}

export interface IdentityRecord {
  readonly p: typeof IDENTITY_RECORD_PROTOCOL;
  readonly k: string;
  readonly ts: number;
  readonly profile: IdentityProfile;
  readonly sig: string;
}

export interface IdentitySnapshot {
  readonly p: typeof IDENTITY_SNAPSHOT_PROTOCOL;
  readonly k: string;
  readonly ts: number;
  readonly ref: {
    readonly channel: string;
    readonly eventHash: string;
  };
  readonly record: IdentityRecord;
  readonly sig: string;
}

export interface ChatMessage {
  readonly p: typeof CHAT_MESSAGE_PROTOCOL;
  readonly k: string;
  readonly ts: number;
  readonly body: string;
  readonly sig: string;
}

export interface PublishedChatMessage {
  readonly channelPublicKey: string;
  readonly eventHash: Hash;
  readonly message: ChatMessage;
  readonly payload: AppRecordPayload;
}

export interface ChatTimelineItem {
  readonly eventHash: Hash;
  readonly channelPublicKey: string;
  readonly publishedAt: number;
  readonly message: ChatMessage;
  readonly verified: boolean;
}

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { readonly [key: string]: JsonValue };

export function canonicalJsonString(value: JsonValue): string {
  return JSON.stringify(sortJsonValue(value));
}

export function canonicalJsonBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(canonicalJsonString(value));
}

export async function createIdentityRecord(
  crypto: CryptoOperations,
  keyPair: KeyPair,
  profile: IdentityProfile,
  timestamp: number,
): Promise<IdentityRecord> {
  const unsigned = canonicalIdentityRecord(keyPair.publicKey, profile, timestamp);
  const signature = await crypto.signPR(canonicalJsonBytes(unsigned as unknown as JsonValue), keyPair.privateKey);
  return {
    ...unsigned,
    sig: bytesToBase64Url(signature),
  };
}

export async function verifyIdentityRecord(
  crypto: CryptoOperations,
  record: IdentityRecord,
): Promise<boolean> {
  const publicKey = publicKeyFromHex(record.k);
  const unsigned = canonicalIdentityRecord(publicKey, record.profile, record.ts);
  return crypto.verifyPU(
    canonicalJsonBytes(unsigned as unknown as JsonValue),
    createSignature(base64UrlToBytes(record.sig)),
    publicKey,
  );
}

export async function createChatMessage(
  crypto: CryptoOperations,
  keyPair: KeyPair,
  input: {
    readonly body: string;
    readonly timestamp: number;
  },
): Promise<ChatMessage> {
  const unsigned = canonicalChatMessage(keyPair.publicKey, input.body, input.timestamp);
  const signature = await crypto.signPR(canonicalJsonBytes(unsigned as unknown as JsonValue), keyPair.privateKey);
  return {
    ...unsigned,
    sig: bytesToBase64Url(signature),
  };
}

export async function verifyChatMessage(
  crypto: CryptoOperations,
  message: ChatMessage,
): Promise<boolean> {
  const publicKey = publicKeyFromHex(message.k);
  const unsigned = canonicalChatMessage(publicKey, message.body, message.ts);
  return crypto.verifyPU(
    canonicalJsonBytes(unsigned as unknown as JsonValue),
    createSignature(base64UrlToBytes(message.sig)),
    publicKey,
  );
}

export async function createIdentitySnapshot(
  crypto: CryptoOperations,
  keyPair: KeyPair,
  input: {
    readonly record: IdentityRecord;
    readonly ref: {
      readonly channel: string;
      readonly eventHash: string;
    };
    readonly timestamp: number;
  },
): Promise<IdentitySnapshot> {
  const unsigned = canonicalIdentitySnapshot(keyPair.publicKey, input.record, input.ref, input.timestamp);
  const signature = await crypto.signPR(canonicalJsonBytes(unsigned as unknown as JsonValue), keyPair.privateKey);
  return {
    ...unsigned,
    sig: bytesToBase64Url(signature),
  };
}

export async function verifyIdentitySnapshot(
  crypto: CryptoOperations,
  snapshot: IdentitySnapshot,
): Promise<boolean> {
  const publicKey = publicKeyFromHex(snapshot.k);
  if (!(await verifyIdentityRecord(crypto, snapshot.record))) {
    return false;
  }
  const unsigned = canonicalIdentitySnapshot(publicKey, snapshot.record, snapshot.ref, snapshot.ts);
  return crypto.verifyPU(
    canonicalJsonBytes(unsigned as unknown as JsonValue),
    createSignature(base64UrlToBytes(snapshot.sig)),
    publicKey,
  );
}

export function serializeIdentityRecord(record: IdentityRecord): string {
  return canonicalJsonString(record as unknown as JsonValue);
}

export function serializeIdentitySnapshot(snapshot: IdentitySnapshot): string {
  return canonicalJsonString(snapshot as unknown as JsonValue);
}

export function serializeChatMessage(message: ChatMessage): string {
  return canonicalJsonString(message as unknown as JsonValue);
}

export async function publishChatMessage(
  deps: {
    readonly log: Log;
    readonly crypto: CryptoOperations;
  },
  hubSecret: Secret | string,
  body: string,
  timestamp: number = Date.now(),
): Promise<PublishedChatMessage> {
  const secret = normalizeSecret(hubSecret);
  const channel = await openChannel(secret, deps.crypto);
  const keyPair = await deps.crypto.deriveKeys(channel.secret);
  const message = await createChatMessage(deps.crypto, keyPair, { body, timestamp });
  const payload: AppRecordPayload = {
    type: EventType.APP_RECORD,
    protocol: CHAT_MESSAGE_PROTOCOL,
    authorPublicKey: bytesToHex(keyPair.publicKey),
    record: serializeChatMessage(message),
    publishedAt: timestamp,
  };
  const signedEvent = await createSignedEvent(deps.crypto, keyPair, payload, []);
  const eventHash = await deps.log.events.storeEvent(keyPair.publicKey, signedEvent);
  return {
    channelPublicKey: bytesToHex(keyPair.publicKey),
    eventHash,
    message,
    payload,
  };
}

export async function readChatTimeline(
  deps: {
    readonly log: Log;
    readonly crypto: CryptoOperations;
  },
  hubSecret: Secret | string,
): Promise<ChatTimelineItem[]> {
  const secret = normalizeSecret(hubSecret);
  const channel = await openChannel(secret, deps.crypto);
  const entries = await loadEventLog(channel, deps.log, deps.crypto);
  return projectChatTimeline(entries, deps.crypto);
}

export async function projectChatTimeline(
  entries: readonly EventLogEntry[],
  crypto: CryptoOperations,
): Promise<ChatTimelineItem[]> {
  const out: ChatTimelineItem[] = [];
  for (const entry of entries) {
    const extracted = parseChatPayload(entry.signedEvent.payload);
    if (extracted === null) {
      continue;
    }
    const verified = await verifyChatMessage(crypto, extracted.message).catch(() => false);
    out.push({
      eventHash: entry.eventHash,
      channelPublicKey: entry.signedEvent.envelope.publicKey,
      publishedAt: extracted.publishedAt,
      message: extracted.message,
      verified,
    });
  }
  out.sort((left, right) => {
    if (left.publishedAt !== right.publishedAt) return left.publishedAt - right.publishedAt;
    if (left.eventHash < right.eventHash) return -1;
    if (left.eventHash > right.eventHash) return 1;
    return 0;
  });
  return out;
}

export interface PublishedIdentitySnapshot {
  readonly channelPublicKey: string;
  readonly eventHash: Hash;
  readonly snapshot: IdentitySnapshot;
  readonly payload: AppRecordPayload;
}

/**
 * Publishes a profile's identity record into a hub channel as an
 * `nb.identity.snapshot.v1` app record, so members of that hub can resolve
 * the profile's display name. The canonical record still lives in the
 * profile's own channel; the snapshot carries a `ref` back to it.
 *
 * Two keys are involved and they are NOT interchangeable:
 *
 * - `profileKeyPair` signs the snapshot (and the record inside it). This is
 *   the only thing that authenticates "this display name belongs to this
 *   profile".
 * - the hub secret derives the channel keypair that signs and encrypts the
 *   *envelope*. This only scopes readability to hub members.
 *
 * Every hub member holds the hub secret, so the envelope proves nothing
 * about authorship — any member could write an event claiming any
 * `authorPublicKey`. Readers MUST therefore call `verifyIdentitySnapshot`
 * (or use {@link projectIdentityDirectory}) before trusting a name.
 */
export async function publishIdentitySnapshot(
  deps: {
    readonly log: Log;
    readonly crypto: CryptoOperations;
  },
  hubSecret: Secret | string,
  profileKeyPair: KeyPair,
  record: IdentityRecord,
  canonicalEventHash: string,
  timestamp: number = Date.now(),
): Promise<PublishedIdentitySnapshot> {
  const secret = normalizeSecret(hubSecret);
  const channel = await openChannel(secret, deps.crypto);
  const hubKeyPair = await deps.crypto.deriveKeys(channel.secret);
  const profilePublicKey = bytesToHex(profileKeyPair.publicKey);
  if (record.k !== profilePublicKey) {
    throw new Error('Identity snapshot must be signed by the profile that owns the record');
  }
  const snapshot = await createIdentitySnapshot(deps.crypto, profileKeyPair, {
    record,
    // SNAPSHOT ref points at the canonical event in the profile's OWN
    // channel; `parseIdentitySnapshot` enforces ref.channel === record.k.
    ref: { channel: profilePublicKey, eventHash: canonicalEventHash },
    timestamp,
  });
  const payload: AppRecordPayload = {
    type: EventType.APP_RECORD,
    protocol: IDENTITY_SNAPSHOT_PROTOCOL,
    authorPublicKey: profilePublicKey,
    record: serializeIdentitySnapshot(snapshot),
    publishedAt: timestamp,
  };
  const signedEvent = await createSignedEvent(deps.crypto, hubKeyPair, payload, []);
  const eventHash = await deps.log.events.storeEvent(hubKeyPair.publicKey, signedEvent);
  return {
    channelPublicKey: bytesToHex(hubKeyPair.publicKey),
    eventHash,
    snapshot,
    payload,
  };
}

export interface IdentityDirectoryEntry {
  readonly profilePublicKey: string;
  readonly displayName: string;
  readonly bio?: string;
  readonly publishedAt: number;
  /** `record` = canonical, in the profile's own channel; `snapshot` = carried into this channel. */
  readonly source: 'record' | 'snapshot';
}

/**
 * Projects a channel's events into a profile-public-key → display-name
 * directory, keyed by the profile key that actually *signed* the identity
 * record.
 *
 * Signature verification is mandatory here, not decorative: within a hub
 * every member holds the channel secret, so an unverified `authorPublicKey`
 * is an unauthenticated claim and any member could otherwise publish a name
 * under someone else's profile key. Records that fail verification are
 * dropped rather than surfaced.
 *
 * Last writer wins per profile, ordered by the record's own `ts`.
 */
export async function projectIdentityDirectory(
  entries: readonly EventLogEntry[],
  crypto: CryptoOperations,
): Promise<Map<string, IdentityDirectoryEntry>> {
  const out = new Map<string, IdentityDirectoryEntry>();
  for (const entry of entries) {
    const payload = entry.signedEvent.payload;
    if (payload.type !== EventType.APP_RECORD || typeof payload.record !== 'string') {
      continue;
    }
    let record: IdentityRecord | null = null;
    let source: IdentityDirectoryEntry['source'] | null = null;
    try {
      if (payload.protocol === IDENTITY_RECORD_PROTOCOL) {
        const parsed = parseIdentityRecordJson(payload.record);
        if (parsed !== null && (await verifyIdentityRecord(crypto, parsed))) {
          record = parsed;
          source = 'record';
        }
      } else if (payload.protocol === IDENTITY_SNAPSHOT_PROTOCOL) {
        const parsed = parseIdentitySnapshotJson(payload.record);
        // verifyIdentitySnapshot checks the inner record too.
        if (parsed !== null && (await verifyIdentitySnapshot(crypto, parsed))) {
          record = parsed.record;
          source = 'snapshot';
        }
      }
    } catch {
      // Malformed or unverifiable identity payloads are skipped so one bad
      // record cannot break the directory for the whole channel.
      continue;
    }
    if (record === null || source === null) {
      continue;
    }
    const existing = out.get(record.k);
    if (existing !== undefined && existing.publishedAt >= record.ts) {
      continue;
    }
    const bio = record.profile.bio;
    out.set(record.k, {
      profilePublicKey: record.k,
      displayName: record.profile.displayName,
      ...(bio !== undefined ? { bio } : {}),
      publishedAt: record.ts,
      source,
    });
  }
  return out;
}

/**
 * Latest verified identity record a channel holds for its *own* key, together
 * with the event hash that carries it.
 *
 * This is what a profile needs in order to re-broadcast itself: the canonical
 * record lives in the profile's own channel, and {@link publishIdentitySnapshot}
 * needs both the record and its canonical `eventHash` to build the snapshot
 * `ref`. Returns `null` when the profile has never published an identity.
 */
export async function readOwnIdentityRecord(
  deps: {
    readonly log: Log;
    readonly crypto: CryptoOperations;
  },
  profileSecret: Secret | string,
): Promise<{ readonly record: IdentityRecord; readonly eventHash: Hash } | null> {
  const secret = normalizeSecret(profileSecret);
  const channel = await openChannel(secret, deps.crypto);
  const keyPair = await deps.crypto.deriveKeys(channel.secret);
  const own = bytesToHex(keyPair.publicKey);
  const entries = await loadEventLog(channel, deps.log, deps.crypto);
  let best: { record: IdentityRecord; eventHash: Hash } | null = null;
  for (const entry of entries) {
    const payload = entry.signedEvent.payload;
    if (payload.type !== EventType.APP_RECORD || typeof payload.record !== 'string') continue;
    if (payload.protocol !== IDENTITY_RECORD_PROTOCOL) continue;
    try {
      const record = parseIdentityRecordJson(payload.record);
      // Only our own key, and only if it actually verifies.
      if (record === null || record.k !== own) continue;
      if (!(await verifyIdentityRecord(deps.crypto, record))) continue;
      if (best === null || record.ts > best.record.ts) {
        best = { record, eventHash: entry.eventHash };
      }
    } catch {
      continue;
    }
  }
  return best;
}

/** Reads a hub channel and projects its verified identity directory. */
export async function readIdentityDirectory(
  deps: {
    readonly log: Log;
    readonly crypto: CryptoOperations;
  },
  hubSecret: Secret | string,
): Promise<Map<string, IdentityDirectoryEntry>> {
  const secret = normalizeSecret(hubSecret);
  const channel = await openChannel(secret, deps.crypto);
  const entries = await loadEventLog(channel, deps.log, deps.crypto);
  return projectIdentityDirectory(entries, deps.crypto);
}

export function parseChatPayload(
  payload: EventPayload,
): { readonly message: ChatMessage; readonly publishedAt: number } | null {
  if (payload.type === EventType.APP_RECORD && payload.protocol === CHAT_MESSAGE_PROTOCOL) {
    const message = parseChatMessageJson(payload.record);
    if (message === null) {
      return null;
    }
    return { message, publishedAt: payload.publishedAt };
  }
  if (payload.type === EventType.CHAT_MESSAGE && typeof payload.message === 'string') {
    const message = parseChatMessageJson(payload.message);
    if (message === null) {
      return null;
    }
    return { message, publishedAt: payload.publishedAt ?? message.ts };
  }
  return null;
}

export function parseIdentityRecord(value: unknown): IdentityRecord {
  const object = asObject(value, 'Identity record must be an object');
  if (object.p !== IDENTITY_RECORD_PROTOCOL) {
    throw new Error('Unsupported identity record protocol');
  }
  const publicKey = parsePublicKeyHex(object.k, 'Identity record public key is invalid');
  const ts = parseTimestamp(object.ts, 'Identity record timestamp is invalid');
  const profile = parseIdentityProfile(object.profile);
  const sig = parseBase64UrlString(object.sig, 'Identity record signature is invalid');
  return {
    p: IDENTITY_RECORD_PROTOCOL,
    k: publicKey,
    ts,
    profile,
    sig,
  };
}

export function parseIdentityRecordJson(text: string): IdentityRecord | null {
  const parsed = parseJsonProtocol(text);
  if (!parsed || parsed.p !== IDENTITY_RECORD_PROTOCOL) {
    return null;
  }
  return parseIdentityRecord(parsed);
}

export function parseIdentitySnapshot(value: unknown): IdentitySnapshot {
  const object = asObject(value, 'Identity snapshot must be an object');
  if (object.p !== IDENTITY_SNAPSHOT_PROTOCOL) {
    throw new Error('Unsupported identity snapshot protocol');
  }
  const publicKey = parsePublicKeyHex(object.k, 'Identity snapshot public key is invalid');
  const ts = parseTimestamp(object.ts, 'Identity snapshot timestamp is invalid');
  const ref = parseIdentitySnapshotRef(object.ref);
  const record = parseIdentityRecord(object.record);
  if (record.k !== publicKey) {
    throw new Error('Identity snapshot record key does not match snapshot public key');
  }
  if (ref.channel !== publicKey) {
    throw new Error('Identity snapshot channel does not match snapshot public key');
  }
  const sig = parseBase64UrlString(object.sig, 'Identity snapshot signature is invalid');
  return {
    p: IDENTITY_SNAPSHOT_PROTOCOL,
    k: publicKey,
    ts,
    ref,
    record,
    sig,
  };
}

export function parseIdentitySnapshotJson(text: string): IdentitySnapshot | null {
  const parsed = parseJsonProtocol(text);
  if (!parsed || parsed.p !== IDENTITY_SNAPSHOT_PROTOCOL) {
    return null;
  }
  return parseIdentitySnapshot(parsed);
}

export function parseChatMessage(value: unknown): ChatMessage {
  const object = asObject(value, 'Chat message must be an object');
  if (object.p !== CHAT_MESSAGE_PROTOCOL) {
    throw new Error('Unsupported chat message protocol');
  }
  const publicKey = parsePublicKeyHex(object.k, 'Chat message public key is invalid');
  const ts = parseTimestamp(object.ts, 'Chat message timestamp is invalid');
  const body = parseRequiredTrimmedString(object.body, 'Chat message body is required');
  const sig = parseBase64UrlString(object.sig, 'Chat message signature is invalid');
  return {
    p: CHAT_MESSAGE_PROTOCOL,
    k: publicKey,
    ts,
    body,
    sig,
  };
}

export function parseChatMessageJson(text: string): ChatMessage | null {
  const parsed = parseJsonProtocol(text);
  if (!parsed || parsed.p !== CHAT_MESSAGE_PROTOCOL) {
    return null;
  }
  return parseChatMessage(parsed);
}

function canonicalIdentityRecord(
  publicKey: PublicKey,
  profile: IdentityProfile,
  timestamp: number,
): Omit<IdentityRecord, 'sig'> {
  return {
    p: IDENTITY_RECORD_PROTOCOL,
    k: bytesToHex(publicKey),
    ts: timestamp,
    profile: normalizeIdentityProfile(profile),
  };
}

function canonicalIdentitySnapshot(
  publicKey: PublicKey,
  record: IdentityRecord,
  ref: {
    readonly channel: string;
    readonly eventHash: string;
  },
  timestamp: number,
): Omit<IdentitySnapshot, 'sig'> {
  const normalizedRecord = parseIdentityRecord(record);
  const snapshotPublicKey = bytesToHex(publicKey);
  if (normalizedRecord.k !== snapshotPublicKey) {
    throw new Error('Identity snapshot record key does not match signer key');
  }
  const channel = parsePublicKeyHex(ref.channel, 'Identity snapshot channel is invalid');
  if (channel !== snapshotPublicKey) {
    throw new Error('Identity snapshot channel does not match signer key');
  }
  return {
    p: IDENTITY_SNAPSHOT_PROTOCOL,
    k: snapshotPublicKey,
    ts: timestamp,
    ref: {
      channel,
      eventHash: parseEventHashHex(ref.eventHash, 'Identity snapshot event hash is invalid'),
    },
    record: normalizedRecord,
  };
}

function canonicalChatMessage(
  publicKey: PublicKey,
  body: string,
  timestamp: number,
): Omit<ChatMessage, 'sig'> {
  const normalizedBody = body.trim();
  if (!normalizedBody) {
    throw new Error('Chat message body must not be empty');
  }
  return {
    p: CHAT_MESSAGE_PROTOCOL,
    k: bytesToHex(publicKey),
    ts: timestamp,
    body: normalizedBody,
  };
}

function normalizeIdentityProfile(profile: IdentityProfile): IdentityProfile {
  const displayName = profile.displayName.trim();
  if (displayName.length === 0) {
    throw new Error('Identity displayName is required');
  }
  const bio = normalizeOptionalString(profile.bio);
  return bio ? { displayName, bio } : { displayName };
}

function parseIdentityProfile(value: unknown): IdentityProfile {
  const object = asObject(value, 'Identity profile must be an object');
  return normalizeIdentityProfile({
    displayName: parseRequiredString(object.displayName, 'Identity display name is invalid'),
    bio: parseOptionalTrimmedString(object.bio, 'Identity bio is invalid'),
  });
}

function parseIdentitySnapshotRef(
  value: unknown,
): {
  readonly channel: string;
  readonly eventHash: string;
} {
  const object = asObject(value, 'Identity snapshot ref must be an object');
  return {
    channel: parsePublicKeyHex(object.channel, 'Identity snapshot channel is invalid'),
    eventHash: parseEventHashHex(object.eventHash, 'Identity snapshot event hash is invalid'),
  };
}

function normalizeSecret(value: Secret | string): Secret {
  return typeof value === 'string' ? createSecret(value) : value;
}

function normalizeOptionalString(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parsePublicKeyHex(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw new Error(message);
  }
  return bytesToHex(publicKeyFromHex(value));
}

function parseEventHashHex(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw new Error(message);
  }
  return createHash(value);
}

export function publicKeyFromHex(value: string): PublicKey {
  const bytes = hexToBytes(value.toLowerCase());
  if (bytes.length !== 65) {
    throw new Error('Public key must be 65 bytes');
  }
  return createPublicKey(bytes);
}

function parseRequiredString(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw new Error(message);
  }
  return value;
}

function parseRequiredTrimmedString(value: unknown, message: string): string {
  const s = parseRequiredString(value, message);
  const trimmed = s.trim();
  if (!trimmed) {
    throw new Error(message);
  }
  return trimmed;
}

function parseOptionalTrimmedString(value: unknown, message: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new Error(message);
  }
  return normalizeOptionalString(value);
}

function parseTimestamp(value: unknown, message: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(message);
  }
  return value;
}

function parseBase64UrlString(value: unknown, message: string): string {
  if (typeof value !== 'string') {
    throw new Error(message);
  }
  const bytes = base64UrlToBytes(value);
  if (bytes.length === 0) {
    throw new Error(message);
  }
  return bytesToBase64Url(bytes);
}

function parseJsonProtocol(text: string): { readonly p?: string } | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith('{')) {
    return null;
  }
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    return parsed as { readonly p?: string };
  } catch {
    return null;
  }
}

function asObject(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as Record<string, unknown>;
}

function sortJsonValue(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => sortJsonValue(item));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const sorted: Record<string, JsonValue> = {};
  const objectValue = value as { readonly [key: string]: JsonValue };
  for (const key of Object.keys(objectValue).sort((left, right) => left.localeCompare(right))) {
    sorted[key] = sortJsonValue(objectValue[key]);
  }
  return sorted;
}

// Projection-engine integration (storage/projection-engine-v1.md, chat-v1 §5).
export { createChatProjector, CHAT_PROJECTOR_ID } from './chatProjector.js';
export type { ChatKey, ChatTimelineState } from './chatProjector.js';
export { createChatService } from './chatService.js';
export type { ChatService, ChatServiceDependencies } from './chatService.js';
