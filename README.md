# nearbytes-chat

Hub-scoped chat protocol for Nearbytes.

Chat messages are application records written into an existing Nearbytes log
channel. The channel, often called a hub or volume by user-facing tools, is the
chat scope. Profiles remain sync/social identities and are not the chat
container.

## Protocols

- `nb.chat.message.v1` — canonical JSON chat message record.
- `nb.identity.record.v1` — display-name record signed by a profile key.
- `nb.identity.snapshot.v1` — identity record snapshot.

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

The event is stored under the hub channel public key. Replaying the hub log and
filtering `nb.chat.message.v1` records produces the chat timeline.
