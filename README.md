# nearbytes-chat

Hub-scoped chat protocol for Nearbytes.

`nearbytes-chat` owns the chat and identity record codecs used by Nearbytes
apps. It writes chat messages into an existing Nearbytes log channel. That
channel is the chat scope and is currently called a hub or volume by user-facing
tools.

Profiles are not chat containers. A profile remains a sync/social identity used
for discovery, authorization, friend following, and identity records.

## Install

```sh
yarn install
yarn build
yarn type-check
```

This package is not published to npm. Other Nearbytes repos consume it with a
pinned GitHub dependency:

```json
{
  "dependencies": {
    "nearbytes-chat": "github:nearbytes/nearbytes-chat#<commit-sha>"
  }
}
```

## Protocols

- `nb.chat.message.v1` — canonical JSON chat message record.
- `nb.identity.record.v1` — display-name record signed by a profile key.
- `nb.identity.snapshot.v1` — identity record snapshot.

## Chat Scope

Chat is scoped to the hub/volume channel where the app record is stored.

```text
hub secret -> channel keypair -> channel event log
```

Every message in that channel belongs to that hub. A reader obtains the chat
timeline by replaying the channel log and filtering chat app records.

## Log Shape

`publishChatMessage` writes an `APP_RECORD` event:

```json
{
  "type": "APP_RECORD",
  "protocol": "nb.chat.message.v1",
  "authorPublicKey": "<hub-public-key>",
  "record": "{...canonical chat record...}",
  "publishedAt": 1710000000000
}
```

The inner chat record is canonical JSON:

```json
{
  "p": "nb.chat.message.v1",
  "k": "<hub-public-key>",
  "ts": 1710000000000,
  "body": "hello",
  "sig": "<base64url-signature>"
}
```

The v1 writer signs with the channel/hub keypair. The record is stored in the
hub log, so the channel itself remains the message scope.

## Library Usage

```ts
import { publishChatMessage, readChatTimeline } from 'nearbytes-chat';
import { createFilesystemLog } from 'nearbytes-log';
import { createCryptoOperations } from 'nearbytes-crypto';

const log = createFilesystemLog('/path/to/data');
const crypto = createCryptoOperations();

await publishChatMessage(
  { log, crypto },
  'team:secret',
  'hello team',
);

const messages = await readChatTimeline(
  { log, crypto },
  'team:secret',
);
```

## Main Exports

- `createChatMessage`, `verifyChatMessage`
- `publishChatMessage`, `readChatTimeline`, `projectChatTimeline`
- `parseChatMessage`, `parseChatMessageJson`, `serializeChatMessage`
- `createIdentityRecord`, `verifyIdentityRecord`
- `createIdentitySnapshot`, `verifyIdentitySnapshot`
- protocol constants:
  - `CHAT_MESSAGE_PROTOCOL`
  - `IDENTITY_RECORD_PROTOCOL`
  - `IDENTITY_SNAPSHOT_PROTOCOL`

## Consumers

- [`nearbytes-cli`](https://github.com/nearbytes/nearbytes-cli) provides the
  `say` and `chat` commands.
- [`nearbytes-files`](https://github.com/nearbytes/nearbytes-files) recognizes
  chat app records in volume timelines but does not own the chat protocol.
