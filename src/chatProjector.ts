/**
 * CHAT projector for the projection engine (`storage/projection-engine-v1.md`,
 * `application/chat-v1.md` §5). Chat is append-only at the engine level: the
 * engine maintains no order, and `reduce` sorts the timeline by
 * `(publishedAt, eventHash)`. This is the protocol's ordering choice, not the
 * engine's.
 */
import type { OrderKey, Projector } from 'nearbytes-log';
import { appendReorder } from 'nearbytes-log';
import { parseChatPayload } from './index.js';
import type { ChatTimelineItem } from './index.js';

export const CHAT_PROJECTOR_ID = 'nb.chat.v1';

export type ChatKey = OrderKey;

export interface ChatTimelineState {
  readonly items: readonly ChatTimelineItem[];
}

function byPublishedAtThenHash(a: ChatTimelineItem, b: ChatTimelineItem): number {
  if (a.publishedAt !== b.publishedAt) return a.publishedAt - b.publishedAt;
  if (a.eventHash < b.eventHash) return -1;
  if (a.eventHash > b.eventHash) return 1;
  return 0;
}

export function createChatProjector(): Projector<ChatTimelineState, ChatKey> {
  return {
    id: CHAT_PROJECTOR_ID,
    initial: () => ({ items: [] }),
    serializeState: (state) => new TextEncoder().encode(JSON.stringify(state.items)),
    deserializeState: (bytes) => ({
      items: JSON.parse(new TextDecoder().decode(bytes)) as ChatTimelineItem[],
    }),
    key: (entry) => ({ hash: entry.eventHash }),
    reorder: (prev, next) => appendReorder(prev, next),
    reduce: (base, tail) => {
      // Events reach the projector only after acceptance-time verification (sync
      // receive / local emit verify the channel signature; the log re-checks the
      // content-address hash on read). Replay therefore trusts the local log and
      // does NOT re-run a per-event ECDSA verify — the dominant cost on cold
      // rebuilds. The hub key that signed the envelope is the chat record signer
      // in v1 (chat-v1 §4), so envelope authenticity implies record authenticity.
      const items = [...base.items];
      for (const entry of tail) {
        const extracted = parseChatPayload(entry.signedEvent.payload);
        if (extracted === null) continue; // non-chat events have no timeline effect
        items.push({
          eventHash: entry.eventHash,
          channelPublicKey: entry.signedEvent.envelope.publicKey,
          publishedAt: extracted.publishedAt,
          message: extracted.message,
          verified: true,
        });
      }
      items.sort(byPublishedAtThenHash);
      return { items };
    },
  };
}
