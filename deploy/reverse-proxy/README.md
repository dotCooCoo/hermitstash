# Reverse proxy examples

Three drop-in configs that put a TLS-terminating proxy in front of HermitStash.
All three assume the same backend: HermitStash on `127.0.0.1:3000` with
`TRUST_PROXY=true` and `RP_ORIGIN=https://files.example.com`.

| File | Use when |
|------|----------|
| [`Caddyfile`](Caddyfile) | You want automatic TLS with the least configuration |
| [`nginx.conf`](nginx.conf) | You already run nginx or need fine-grained control |
| [`apache.conf`](apache.conf) | Your distro / hosting panel is Apache-first |

Each config:

- Terminates TLS with a Let's Encrypt cert
- Forwards `/sync/ws` WebSocket upgrades (used by the companion sync client)
- Matches the 100MB `MAX_FILE_SIZE` default — bump the value in both places if you raise it
- Disables response buffering so streamed ciphertext doesn't spool to disk
- Passes `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` through so `TRUST_PROXY=true` can honor them
- Leaves security headers to HermitStash — adding HSTS/CSP at the proxy will collide with the app's own headers

## mTLS sync clients

HermitStash's sync protocol optionally uses mTLS: clients present a client certificate
on the WebSocket connection. A reverse proxy terminating TLS **strips the client cert
before the upstream sees it**, which breaks the mTLS check.

If you use sync mTLS, the two options are:

1. **TCP passthrough** — have the proxy forward raw TCP for port 443 (or a dedicated
   port) straight to HermitStash's TLS listener, so node's `socket.getPeerCertificate()`
   gets the real cert. Simplest in Caddy via the `layer4` app; in nginx via the `stream`
   module; in Apache there's no clean equivalent.
2. **Bypass port** — run HermitStash with TLS on a separate port (e.g. 8443) that's
   exposed directly to sync clients, and keep the proxy only for human browser
   traffic on 443.

For servers not using sync mTLS (`MTLS_REQUIRED=false` or no client certs ever
enrolled), the configs in this directory work as-is.
