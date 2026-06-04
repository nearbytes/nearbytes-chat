/**
 * Engine-backed chat service — the replacement for repeated full `readChatTimeline`
 * reloads. One projection per hub channel, persisted via a MaterializedStore, fed
 * incrementally by the log router. `nearbytes-engine` wires this; shells consume it.
 */
import type { CryptoOperations } from 'nearbytes-crypto';
import { createSecret, bytesToHex } from 'nearbytes-crypto';
import type { EventLogEntry, Log, MaterializedStore, Projection } from 'nearbytes-log';
import { createProjection, openChannel } from 'nearbytes-log';
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

export function createChatService(deps: ChatServiceDependencies): ChatService {
  const projections = new Map<string, Promise<Projection<ChatTimelineState>>>();
  const projector = createChatProjector();

  const norm = (secret: string): string => createSecret(secret) as unknown as string;

  // Catch-up (list + trusted, bounded-parallel hydrate + ingest) is shared in the
  // projection engine; the service never reimplements it.
  const ensure = (secret: string): Promise<Projection<ChatTimelineState>> => {
    const key = norm(secret);
    let pending = projections.get(key);
    if (pending === undefined) {
      pending = (async () => {
        const channel = await openChannel(createSecret(secret), deps.crypto);
        const projection = await createProjection(deps.log, channel, deps.crypto, projector, deps.store);
        await projection.catchUp();
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
      await projection.catchUp();
      return [...projection.state().items];
    },
    async publish(secret, body, timestamp) {
      const published = await publishChatMessage(
        { log: deps.log, crypto: deps.crypto },
        secret,
        body,
        timestamp,
      );
      // Pick up the just-stored event (catchUp lists once, hydrates only the new
      // hash); dedupes with the router's live push.
      await (await ensure(secret)).catchUp();
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
