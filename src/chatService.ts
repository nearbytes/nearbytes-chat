/**
 * Engine-backed chat service — the replacement for repeated full `readChatTimeline`
 * reloads. One projection per hub channel, persisted via a MaterializedStore, fed
 * incrementally by the log router. `nearbytes-engine` wires this; shells consume it.
 */
import type { CryptoOperations, Hash, Secret } from 'nearbytes-crypto';
import { createSecret } from 'nearbytes-crypto';
import type { EventLogEntry, Log, MaterializedStore, Projection } from 'nearbytes-log';
import {
  createProjection,
  eventEnvelopePublicKeyMatches,
  hydrateSignedEvent,
  openChannel,
} from 'nearbytes-log';
import { publishChatMessage } from './index.js';
import type { ChatTimelineItem, PublishedChatMessage } from './index.js';
import { createChatProjector, type ChatTimelineState } from './chatProjector.js';

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
  stop(): void;
}

export function createChatService(deps: ChatServiceDependencies): ChatService {
  const projections = new Map<string, Promise<Projection<ChatTimelineState>>>();
  const projector = createChatProjector(deps.crypto);

  const ensure = (secret: string): Promise<Projection<ChatTimelineState>> => {
    const normalized = createSecret(secret) as unknown as string;
    let pending = projections.get(normalized);
    if (pending === undefined) {
      pending = (async () => {
        const channel = await openChannel(createSecret(secret), deps.crypto);
        return createProjection(deps.log, channel, deps.crypto, projector, deps.store);
      })();
      projections.set(normalized, pending);
    }
    return pending;
  };

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

  return {
    async timeline(secret) {
      const projection = await ensure(secret);
      return [...projection.state().items];
    },
    async publish(secret, body, timestamp) {
      const published = await publishChatMessage(
        { log: deps.log, crypto: deps.crypto },
        secret,
        body,
        timestamp,
      );
      // The router push will also ingest; ingest dedupes, so this just makes the
      // local timeline deterministic immediately after publish resolves.
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
    stop() {
      for (const pending of projections.values()) {
        void pending.then((projection) => projection.stop()).catch(() => undefined);
      }
      projections.clear();
    },
  };
}
