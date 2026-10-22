# SlyOS bridge

The bridge holds a person's own messaging accounts — WhatsApp linked as a
device, Telegram, and Signal linked as a secondary device — so they reach SlyOS
without a Mac in between. It is one small Go service: it links an account (a QR
code, or for WhatsApp and Telegram a code), receives that account's messages and
forwards them to the SlyOS brain, and sends a reply only when a person pressed
Send for it.

It is published under the GNU Affero General Public License v3.0 (see
`LICENSE`) because it links libsignal, which is AGPL-3.0.

## What it keeps, and how

- Every connection gets its own data key, wrapped by one root key
  (`BRIDGE_ROOT_KEY_BASE64`). Everything a connection needs to resume — keys,
  sessions, contacts — is sealed with AES-256-GCM under that data key before it
  is written to Postgres (`internal/sealed`). Signal's own database lives in
  memory and is sealed the same way, as one record.
- Disconnecting deletes the wrapped data key first, then the sealed records: from
  that moment nothing stored can be read by anyone, including the bridge.
- Message content is never logged; library logs are counted, not printed
  (`internal/logsafe`).
- A send that no person pressed is refused here, a second time after the brain
  refused it, and sends are paced and limited to chats that wrote first
  (`internal/session`, `internal/ratelimit`).

## Libraries

| Provider | Library | License |
| --- | --- | --- |
| WhatsApp | [whatsmeow](https://github.com/tulir/whatsmeow) | MPL-2.0 |
| Telegram | [gotd/td](https://github.com/gotd/td) | MIT |
| Signal | [signalmeow](https://github.com/mautrix/signal) (mautrix-signal) | AGPL-3.0 |
| Signal | [libsignal](https://github.com/signalapp/libsignal), Rust FFI | AGPL-3.0 |

## Build

The image is one static linux/amd64 binary on distroless. Stage 1 compiles
`libsignal_ffi.a` from libsignal at the version signalmeow pins (`Dockerfile`,
`LIBSIGNAL_VERSION`; a test checks the two agree).

```sh
docker buildx build --platform linux/amd64 -f Dockerfile -t slyos-bridge --load .
```

Without `-tags libsignal` (for example `go test ./...`) the binary builds
without cgo's Rust half and simply does not serve Signal.

```sh
go test ./...
```

## Run

| Variable | Meaning |
| --- | --- |
| `BRIDGE_ROOT_KEY_BASE64` | 32 random bytes, base64. Wraps every connection's data key. |
| `BRIDGE_SHARED_SECRET` | 32+ characters. The brain sends it to call the bridge. |
| `BRIDGE_EVENTS_SECRET` | 32+ characters, different. The bridge signs its events to the brain with it. |
| `BRAIN_URL` | Where events go (`$BRAIN_URL/v1/webhooks/bridge`). |
| `BRIDGE_DATABASE_URL` | Postgres for sealed state. Without it the bridge refuses to start unless `BRIDGE_ALLOW_MEMORY=1`. |
| `BRIDGE_DB_MAX_CONNS` | Pool ceiling, 2–100 (default 10). |
| `TELEGRAM_API_ID`, `TELEGRAM_API_HASH` | Telegram app registration; without them Telegram is not served. |

The HTTP API the brain calls is described at the top of `internal/api/api.go`.
