/**
 * Engine-backed chat service — the replacement for repeated full `readChatTimeline`
 * reloads. One projection per hub channel, persisted via a MaterializedStore, fed
 * incrementally by the log router. `nearbytes-engine` wires this; shells consume it.
 */
import type { CryptoOperations, Hash, Secret } from 'nearbytes-crypto';
import { createSecret, bytesToHex } from 'nearbytes-crypto';
import type { EventLogEntry, Log, MaterializedStore, Projection } from 'nearbytes-log';
import {
  createProjection,
  eventEnvelopePublicKeyMatches,
  hydrateSignedEvent,
  openChannel,
} from 'nearbytes-log';
import { publishChatMessage } from './index.js';
import type { ChatTimelineItem, PublishedChatMessage } from './index.js';
import { createChatProjector, CHAT_PROJECTOR_ID, type ChatTimelineState } from './chatProjector.js';

export interface ChatServiceDependencies {
  readonly log: Log;
  readonly crypto: CryptoOperations;
  readonly store: MaterializedStore;
}

export interface ChatService {
  /** Live, persisted chat timeline (no full channel reload when warm). */
  timeline(secret: string): Promise<ChatTimelineItem[]>;
  /** Append a chat message; the projection updates incrementally. */
  publish(secret: string, body: string, timestamp?: number): Promise<PublishedChatMessage>;
  /** Boot path: ingest a batch of already-known events for one channel. */
  ingest(secret: string, entries: readonly EventLogEntry[]): Promise<void>;
  /** Subscribe to timeline changes for one channel. */
  onChange(secret: string, listener: (items: ChatTimelineItem[]) => void): Promise<() => void>;
  /**
   * Drop in-memory and persisted projection state for one hub channel so the next
   * {@link timeline} rebuilds from the event log (cold replay).
   */
  invalidateTimeline(secret: string): Promise<void>;
  stop(): void;
}

const HYDRATE_CONCURRENCY = 128;

/** Map with bounded concurrency, preserving input order in the result. */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      out[index] = await fn(items[index]!);
    }
  };
  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return out;
}

export function createChatService(deps: ChatServiceDependencies): ChatService {
  const projections = new Map<string, Promise<Projection<ChatTimelineState>>>();
  const projector = createChatProjector();

  const norm = (secret: string): string => createSecret(secret) as unknown as string;

  const hydrateOne = async (
    secret: Secret,
    eventHash: string,
  ): Promise<EventLogEntry | undefined> => {
    const keyPair = await deps.crypto.deriveKeys(secret);
    try {
      const signed = await deps.log.events.retrieveEvent(keyPair.publicKey, eventHash as Hash);
      if (!eventEnvelopePublicKeyMatches(signed, keyPair.publicKey)) return undefined;
      return {
        eventHash: eventHash as Hash,
        signedEvent: await hydrateSignedEvent(deps.crypto, keyPair.privateKey, signed),
      };
    } catch {
      return undefined;
    }
  };

  const catchUp = async (projection: Projection<ChatTimelineState>, secret: string): Promise<void> => {
    // Derive the channel keypair ONCE (PBKDF2 is ~20ms); never per event.
    const keyPair = await deps.crypto.deriveKeys(createSecret(secret));
    const listed = await deps.log.events.listEvents(keyPair.publicKey);
    const unknown = listed.filter((hash) => !projection.has(hash));
    if (unknown.length === 0) return;
    // Hydrate (retrieve + verify + decrypt) with bounded concurrency so cold
    // builds of large channels saturate I/O without exhausting file handles.
    const hydrated = await mapWithConcurrency(unknown, HYDRATE_CONCURRENCY, async (hash) => {
      try {
        // Trusted replay: events in the local log were signature-verified at
        // reception/emit; the content-address hash is still checked on read.
        const signed = await deps.log.events.retrieveEvent(keyPair.publicKey, hash as Hash, {
          verifySignature: false,
        });
        if (!eventEnvelopePublicKeyMatches(signed, keyPair.publicKey)) return undefined;
        return {
          eventHash: hash as Hash,
          signedEvent: await hydrateSignedEvent(deps.crypto, keyPair.privateKey, signed),
        } satisfies EventLogEntry;
      } catch {
        return undefined;
      }
    });
    const entries = hydrated.filter((entry): entry is EventLogEntry => entry !== undefined);
    if (entries.length > 0) await projection.ingest(entries);
  };

  const ensure = (secret: string): Promise<Projection<ChatTimelineState>> => {
    const key = norm(secret);
    let pending = projections.get(key);
    if (pending === undefined) {
      pending = (async () => {
        const channel = await openChannel(createSecret(secret), deps.crypto);
        const projection = await createProjection(deps.log, channel, deps.crypto, projector, deps.store);
        await catchUp(projection, secret);
        return projection;
      })();
      projections.set(key, pending);
    }
    return pending;
  };

  const namespaceFor = async (secret: string): Promise<{ projectorId: string; channelHex: string }> => {
    const channel = await openChannel(createSecret(secret), deps.crypto);
    return { projectorId: CHAT_PROJECTOR_ID, channelHex: bytesToHex(channel.publicKey).toLowerCase() };
  };

  return {
    async timeline(secret) {
      const projection = await ensure(secret);
      await catchUp(projection, secret);
      return [...projection.state().items];
    },
    async publish(secret, body, timestamp) {
      const published = await publishChatMessage(
        { log: deps.log, crypto: deps.crypto },
        secret,
        body,
        timestamp,
      );
      const projection = await ensure(secret);
      const entry = await hydrateOne(createSecret(secret), published.eventHash);
      if (entry !== undefined) await projection.ingest([entry]);
      return published;
    },
    async ingest(secret, entries) {
      const projection = await ensure(secret);
      await projection.ingest(entries);
    },
    async onChange(secret, listener) {
      const projection = await ensure(secret);
      return projection.onChange((state) => listener([...state.items]));
    },
    async invalidateTimeline(secret) {
      const key = norm(secret);
      const pending = projections.get(key);
      if (pending !== undefined) {
        const projection = await pending;
        await projection.stop();
        projections.delete(key);
      }
      await deps.store.dropNamespace(await namespaceFor(secret));
    },
    stop() {
      for (const pending of projections.values()) {
        void pending.then((projection) => projection.stop()).catch(() => undefined);
      }
      projections.clear();
    },
  };
}
