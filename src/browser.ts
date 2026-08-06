export {
  CHAT_MESSAGE_PROTOCOL,
  IDENTITY_RECORD_PROTOCOL,
  IDENTITY_SNAPSHOT_PROTOCOL,
  canonicalJsonBytes,
  canonicalJsonString,
  createChatMessage,
  createIdentityRecord,
  createIdentitySnapshot,
  parseChatMessage,
  parseChatMessageJson,
  parseChatPayload,
  parseIdentityRecord,
  parseIdentityRecordJson,
  parseIdentitySnapshot,
  parseIdentitySnapshotJson,
  projectChatTimeline,
  projectIdentityDirectory,
  publicKeyFromHex,
  publishChatMessage,
  publishIdentitySnapshot,
  readChatTimeline,
  readIdentityDirectory,
  readOwnIdentityRecord,
  serializeChatMessage,
  serializeIdentityRecord,
  serializeIdentitySnapshot,
  verifyChatMessage,
  verifyIdentityRecord,
  verifyIdentitySnapshot,
} from './index.js';

export type {
  ChatMessage,
  ChatTimelineItem,
  IdentityDirectoryEntry,
  IdentityProfile,
  IdentityRecord,
  IdentitySnapshot,
  PublishedChatMessage,
  PublishedIdentitySnapshot,
} from './index.js';

// Projection-engine integration (browser-safe; caller supplies an in-memory store).
export { createChatProjector, CHAT_PROJECTOR_ID, createChatService } from './index.js';
export type {
  ChatKey,
  ChatTimelineState,
  ChatService,
  ChatServiceDependencies,
} from './index.js';
