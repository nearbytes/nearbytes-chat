/**
 * CHAT projector for the projection engine (`storage/projection-engine-v1.md`,
 * `application/chat-v1.md` §5). Chat is append-only at the engine level: the
 * engine maintains no order, and `reduce` sorts the timeline by
 * `(publishedAt, eventHash)`. This is the protocol's ordering choice, not the
 * engine's.
 */
import type { CryptoOperations } from 'nearbytes-crypto';
import type { OrderKey, Projector } from 'nearbytes-log';
import { appendReorder } from 'nearbytes-log';
import { parseChatPayload, verifyChatMessage } from './index.js';
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

export function createChatProjector(crypto: CryptoOperations): Projector<ChatTimelineState, ChatKey> {
  return {
    id: CHAT_PROJECTOR_ID,
    initial: () => ({ items: [] }),
    serializeState: (state) => new TextEncoder().encode(JSON.stringify(state.items)),
    deserializeState: (bytes) => ({
      items: JSON.parse(new TextDecoder().decode(bytes)) as ChatTimelineItem[],
    }),
    key: (entry) => ({ hash: entry.eventHash }),
    reorder: (prev, next) => appendReorder(prev, next),
    reduce: async (base, tail) => {
      const items = [...base.items];
      for (const entry of tail) {
        const extracted = parseChatPayload(entry.signedEvent.payload);
        if (extracted === null) continue; // non-chat events have no timeline effect
        const verified = await verifyChatMessage(crypto, extracted.message).catch(() => false);
        items.push({
          eventHash: entry.eventHash,
          channelPublicKey: entry.signedEvent.envelope.publicKey,
          publishedAt: extracted.publishedAt,
          message: extracted.message,
          verified,
        });
      }
      items.sort(byPublishedAtThenHash);
      return { items };
    },
  };
}
