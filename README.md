# Clarity relay

The relay behind [Clarity AUI](https://clarityaui.com)'s "approve from your phone, from anywhere". It is a mailbox:
Clarity on your computer and the page on your phone each hold a WebSocket to it, and it passes sealed envelopes
between them. It holds no account, no key and no plaintext.

Clarity runs one at `relay.clarityaui.com`. This is its source, so you can read what it does, and run your own.

## What it sees, and what it cannot

| It sees | It never sees |
|---|---|
| a random pairing id | a command, a file, a folder or a tool name |
| when each side connects | a run's title or its output |
| the size and time of each envelope | an approval, or its answer |
| a phone's push address, if the phone allows notifications | any key |

Everything inside an envelope is encrypted on the computer and on the phone (ECDH on P-256, HKDF-SHA256, AES-256-GCM),
with keys only they hold, and a phone's answer to an approval is signed by a key the relay never has. A relay can delay
or drop envelopes. It cannot read, change or forge one. Pairing shows six digits on both screens, made from both public
keys, so a relay that swapped a key would show two different numbers.

The phone's page is not served by the relay. It comes from a static origin of its own, so a relay that turned hostile
cannot hand the phone other code.

## What it keeps, and for how long

- An envelope for a side that is away: at most 50 of them and 512 KiB, for ten minutes.
- A count of connections per address, by a hash of the address (an IPv6 address by its /64), for two hours.
- The pairing's mailbox and a phone's push address: until Clarity unpairs the phone, or 90 days after either side last
  connected.
- No request logs.

## Limits

A frame is at most 64 KiB. A side sends at most 120 frames a minute. An address opens at most 120 connections an hour.

## Run your own

You need a Cloudflare account; the free plan is enough.

```sh
npm install
npx wrangler login
npx wrangler deploy
npm run vapid        # sets the key the relay signs Web Push with; prints neither half
```

Then, in Clarity: Settings › Remote runtime › Phone, from anywhere › Relay, and enter your relay's address. Phones
paired from then on use it; phones already paired keep the relay they were paired through.

To serve it on a domain of your own, see the commented `routes` lines in `wrangler.jsonc`. Set `VAPID_SUBJECT` there to
a page or a `mailto:` of yours: a push service uses it to reach whoever runs the relay.

## The protocol, briefly

- `GET /v1/health` → `{"ok":true,"push":<bool>}`. `GET /v1/vapid` → the relay's public push key. Both are readable from
  any origin.
- `GET /v1/m/<pairing id>?side=app|phone`, upgraded to a WebSocket: the mailbox. A 22-character id names it.
- Either side sends `{"env":{"v":1,"d":0|1,"c":<counter>,"x":"<sealed>"}}`; `d` must point the way that side sends.
  Clarity may add `"push":true` to wake a phone that is away.
- The phone sends `{"sub":<push subscription>}` to be told of a waiting approval. Only the browsers' own push services
  are accepted as an endpoint.
- Clarity's first connection sends `{"claim":"<SHA-256 of a secret>"}`; `{"drop":"<the secret>"}` later deletes the
  mailbox and closes both sides (code 4001).

## Where this comes from

This repository is a published copy of the relay's source from Clarity's own repository (at `48c2433ac`). Changes land there
first. Found a security problem? Please write to support@clarityaui.com rather than opening an issue.

## Licence

MIT. See [LICENSE](LICENSE).
