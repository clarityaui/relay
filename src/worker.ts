/**
 * THE RELAY: a mailbox that forwards sealed envelopes between one Clarity install
 * and the phone paired with it, for someone with no tailnet. It holds no account, no key and no plaintext.
 *
 * - One Durable Object per pairing (`Mailbox`); each side holds a WebSocket to it. A side that is away gets a short queue:
 *   at most 50 envelopes, each for 10 minutes. Answers are not queued for long, so an approval sent to a closed app cannot
 *   land, later, on a run that has moved on.
 * - It sees a pairing id, when each side connects, the size and time of each envelope, and a phone's push endpoint. It never
 *   sees a command, a file, a folder or tool name, a run title or an answer.
 * - Abuse limits: a frame is at most 64 KiB, a side sends at most 120 frames a minute, and an address (an IPv6 one by its
 *   /64) opens at most 120 connections an hour (`Gate`). A side's queue holds at most 512 KiB and is purged as it expires;
 *   a mailbox nobody has opened for 90 days is deleted.
 * - ⚠ Its two public answers (`/v1/health`, `/v1/vapid`) are readable from any origin: the page is served by the site and
 *   asks the relay for its push key, and without the header every real browser refused it ("Allow notifications" failed).
 * - Unpair: Clarity's first connection registers the SHA-256 of a drop secret only it holds; the secret itself deletes the
 *   mailbox. A lost phone does not need the relay at all: Clarity forgets its key, and nothing it sends opens.
 *
 * One `wrangler deploy` runs it, so anyone may run their own and point Clarity's Settings at it (README.md).
 */
import { encryptPush, pushEndpointOk, vapidAuthorization, type PushSubscriptionKeys } from './webpush'

export interface Env {
  MAILBOX: DurableObjectNamespace
  GATE: DurableObjectNamespace
  /** The VAPID key the relay signs pushes with (a secret), its public half, and who to write to about it. */
  VAPID_PUBLIC_KEY?: string
  VAPID_PRIVATE_KEY?: string
  VAPID_SUBJECT?: string
}

type Side = 'app' | 'phone'
const SIDES: readonly Side[] = ['app', 'phone']
const other = (s: Side): Side => (s === 'app' ? 'phone' : 'app')
/** Which way an envelope from each side must point (the envelope's `d` field): Clarity sends 0, the phone 1. */
const DIRECTION: Record<Side, 0 | 1> = { app: 0, phone: 1 }

export const LIMITS = Object.freeze({ frameBytes: 64 * 1024, queue: 50, queueBytes: 512 * 1024, queueMs: 10 * 60_000, framesPerMinute: 120, connectsPerHour: 120, socketsPerSide: 2, idleMs: 90 * 24 * 3600_000 })

const PAIRING = /^\/v1\/m\/([A-Za-z0-9_-]{22})$/
const te = new TextEncoder()

const json = (body: unknown, status = 200, extra: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra } })
/** Public, and read by a page on another origin: no credentials are ever involved. */
const PUBLIC = { 'access-control-allow-origin': '*' }

/**
 * The key an address is counted under: an IPv4 address as it is, an IPv6 one by its first 64 bits (one home line or phone
 * holds a whole /64, so counting each address would count nothing). An IPv4-mapped IPv6 address counts as its IPv4.
 */
export function gateKey(ip: string): string {
  const a = ip.trim().toLowerCase().replace(/%.*$/, '')
  if (!a.includes(':')) return a
  const mapped = /^(?:0*:)*:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a) ?? /^::(\d+\.\d+\.\d+\.\d+)$/.exec(a)
  if (mapped) return mapped[1]
  const [head, tail] = a.split('::')
  const left = head ? head.split(':') : []
  const right = tail === undefined ? [] : tail ? tail.split(':') : []
  const groups = tail === undefined ? left : [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right]
  return `${groups.slice(0, 4).map((g) => (parseInt(g, 16) || 0).toString(16)).join(':')}::/64`
}

/** What a side's queue keeps: the envelopes younger than `queueMs`, newest last, within `queue` of them and `queueBytes`. */
export function keptQueue(q: { at: number; frame: string }[], now: number): { at: number; frame: string }[] {
  const young = q.filter((x) => now - x.at < LIMITS.queueMs).slice(-LIMITS.queue)
  let bytes = 0
  let from = young.length
  while (from > 0 && bytes + young[from - 1].frame.length <= LIMITS.queueBytes) bytes += young[--from].frame.length
  return young.slice(from)
}

/** When a mailbox next looks at itself: when its oldest queued envelope expires, or when it has sat unopened 90 days. */
export function nextLook(touched: number, queuedAt: number[]): number {
  return Math.min(touched + LIMITS.idleMs, ...queuedAt.map((at) => at + LIMITS.queueMs))
}

async function sha256(s: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(s)))
  let out = ''
  for (const b of h) out += String.fromCharCode(b)
  return btoa(out).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The envelope's shape, and nothing of what is in it. */
function envelopeShape(e: unknown): e is { v: 1; d: 0 | 1; c: number; x: string } {
  const o = e as { v?: unknown; d?: unknown; c?: unknown; x?: unknown }
  return !!o && typeof o === 'object' && o.v === 1 && (o.d === 0 || o.d === 1) && Number.isSafeInteger(o.c) && (o.c as number) >= 0 && typeof o.x === 'string' && /^[A-Za-z0-9_-]+$/.test(o.x)
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const u = new URL(req.url)
    if (u.pathname === '/v1/health') return json({ ok: true, push: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY) }, 200, PUBLIC)
    // The phone subscribes to push under the relay's public VAPID key; nothing else about the relay is served.
    if (u.pathname === '/v1/vapid') return json({ key: env.VAPID_PUBLIC_KEY ?? null }, 200, PUBLIC)
    const m = PAIRING.exec(u.pathname)
    if (!m) return json({ error: 'not found' }, 404)
    if ((req.headers.get('upgrade') || '').toLowerCase() !== 'websocket') return json({ error: 'a mailbox is a WebSocket' }, 426)
    const side = u.searchParams.get('side')
    if (side !== 'app' && side !== 'phone') return json({ error: 'side is app or phone' }, 400)
    // The address is hashed before it names anything: the gate counts it and never keeps it.
    const addr = await sha256(`clarity-relay gate|${gateKey(req.headers.get('cf-connecting-ip') || 'local')}`)
    const gate = await env.GATE.get(env.GATE.idFromName(addr)).fetch('https://gate/connect', { method: 'POST' })
    if (gate.status === 429) return json({ error: 'too many connections from this address' }, 429)
    return env.MAILBOX.get(env.MAILBOX.idFromName(m[1])).fetch(req)
  }
}

/** Counts connections from one (hashed) address, an hour at a time. */
export class Gate implements DurableObject {
  constructor(private ctx: DurableObjectState) {}
  async fetch(): Promise<Response> {
    const hour = Math.floor(Date.now() / 3600_000)
    const seen = (await this.ctx.storage.get<{ hour: number; n: number }>('w')) ?? { hour, n: 0 }
    const w = seen.hour === hour ? seen : { hour, n: 0 }
    if (w.n >= LIMITS.connectsPerHour) return new Response(null, { status: 429 })
    await this.ctx.storage.put('w', { hour, n: w.n + 1 })
    await this.ctx.storage.setAlarm(Date.now() + 2 * 3600_000)
    return new Response(null, { status: 204 })
  }
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll()
  }
}

type Queued = { at: number; frame: string }
type Sub = { endpoint: string; keys: PushSubscriptionKeys }

/** One pairing's mailbox. */
export class Mailbox implements DurableObject {
  private sent: Record<Side, number[]> = { app: [], phone: [] }
  constructor(
    private ctx: DurableObjectState,
    private env: Env
  ) {}

  async fetch(req: Request): Promise<Response> {
    const side = new URL(req.url).searchParams.get('side') as Side
    // A side reconnecting replaces its oldest socket rather than piling up.
    const open = this.ctx.getWebSockets(side)
    for (const old of open.slice(0, Math.max(0, open.length - (LIMITS.socketsPerSide - 1)))) old.close(4000, 'replaced')
    const pair = new WebSocketPair()
    const [client, server] = [pair[0], pair[1]]
    this.ctx.acceptWebSocket(server, [side])
    const waiting = await this.take(side)
    for (const q of waiting) server.send(q.frame)
    server.send(JSON.stringify({ relay: 1, delivered: waiting.length }))
    await this.ctx.storage.put('touched', Date.now())
    await this.look()
    return new Response(null, { status: 101, webSocket: client })
  }

  async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
    const side = this.ctx.getTags(ws)[0] as Side
    if (!SIDES.includes(side)) return
    const size = typeof data === 'string' ? te.encode(data).length : data.byteLength
    if (typeof data !== 'string' || size > LIMITS.frameBytes) return ws.send(JSON.stringify({ error: 'a frame is text, at most 64 KiB' }))
    if (!this.allow(side)) return ws.send(JSON.stringify({ error: 'slow down' }))
    let msg: { env?: unknown; push?: unknown; sub?: unknown; claim?: unknown; drop?: unknown }
    try {
      msg = JSON.parse(data)
    } catch {
      return ws.send(JSON.stringify({ error: 'not JSON' }))
    }
    if (msg && msg.env !== undefined) {
      if (!envelopeShape(msg.env) || msg.env.d !== DIRECTION[side]) return ws.send(JSON.stringify({ error: 'not an envelope from this side' }))
      const frame = JSON.stringify({ env: msg.env })
      const peers = this.ctx.getWebSockets(other(side))
      if (peers.length) {
        for (const p of peers) p.send(frame)
        return
      }
      await this.enqueue(other(side), frame)
      if (side === 'app' && msg.push === true) await this.push(frame)
      return
    }
    if (side === 'phone' && msg && msg.sub !== undefined) {
      const s = msg.sub as Sub
      const ok = !!s && typeof s.endpoint === 'string' && pushEndpointOk(s.endpoint) && typeof s.keys?.p256dh === 'string' && typeof s.keys?.auth === 'string'
      if (!ok) return ws.send(JSON.stringify({ error: 'not a push subscription this relay sends to' }))
      await this.ctx.storage.put('sub', { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } })
      return ws.send(JSON.stringify({ relay: 1, push: true }))
    }
    if (side === 'app' && msg && typeof msg.claim === 'string' && /^[A-Za-z0-9_-]{43}$/.test(msg.claim)) {
      if (!(await this.ctx.storage.get('drop'))) await this.ctx.storage.put('drop', msg.claim)
      return
    }
    if (side === 'app' && msg && typeof msg.drop === 'string') {
      const held = await this.ctx.storage.get<string>('drop')
      if (!held || held !== (await sha256(msg.drop))) return ws.send(JSON.stringify({ error: 'not this mailbox\'s drop secret' }))
      for (const s of this.ctx.getWebSockets()) s.close(4001, 'unpaired')
      await this.ctx.storage.deleteAlarm()
      await this.ctx.storage.deleteAll()
      return
    }
    ws.send(JSON.stringify({ error: 'unknown frame' }))
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    try {
      ws.close(code === 1005 ? 1000 : code, 'closed')
    } catch {
      /* already closed */
    }
  }

  /** Purges what has expired from each queue, deletes a mailbox nobody has opened for 90 days, and sets the next look. */
  async alarm(): Promise<void> {
    const now = Date.now()
    for (const side of SIDES) {
      const q = (await this.ctx.storage.get<Queued[]>(`q:${side}`)) ?? []
      const kept = keptQueue(q, now)
      if (kept.length === q.length) continue
      if (kept.length) await this.ctx.storage.put(`q:${side}`, kept)
      else await this.ctx.storage.delete(`q:${side}`)
    }
    const touched = (await this.ctx.storage.get<number>('touched')) ?? 0
    if (now - touched >= LIMITS.idleMs && this.ctx.getWebSockets().length === 0) await this.ctx.storage.deleteAll()
    else await this.look()
  }

  /** Sets the alarm for the next look: the earliest of a queued envelope's expiry and the idle deadline. */
  private async look(): Promise<void> {
    const touched = (await this.ctx.storage.get<number>('touched')) ?? Date.now()
    const queuedAt: number[] = []
    for (const side of SIDES) for (const x of (await this.ctx.storage.get<Queued[]>(`q:${side}`)) ?? []) queuedAt.push(x.at)
    await this.ctx.storage.setAlarm(nextLook(touched, queuedAt))
  }

  /** At most `framesPerMinute` from a side, counted in this object's life (a sleeping mailbox starts the count again). */
  private allow(side: Side): boolean {
    const now = Date.now()
    const recent = this.sent[side].filter((t) => now - t < 60_000)
    if (recent.length >= LIMITS.framesPerMinute) return false
    recent.push(now)
    this.sent[side] = recent
    return true
  }

  private async enqueue(side: Side, frame: string): Promise<void> {
    const now = Date.now()
    const q = keptQueue([...((await this.ctx.storage.get<Queued[]>(`q:${side}`)) ?? []), { at: now, frame }], now)
    await this.ctx.storage.put(`q:${side}`, q)
    await this.look()
  }

  private async take(side: Side): Promise<Queued[]> {
    const q = keptQueue((await this.ctx.storage.get<Queued[]>(`q:${side}`)) ?? [], Date.now())
    await this.ctx.storage.delete(`q:${side}`)
    return q
  }

  /** Wakes a phone that is away: the frame, already sealed, encrypted again for its push subscription (RFC 8291). */
  private async push(frame: string): Promise<void> {
    const sub = await this.ctx.storage.get<Sub>('sub')
    const { VAPID_PUBLIC_KEY: pub, VAPID_PRIVATE_KEY: priv, VAPID_SUBJECT: subject } = this.env
    if (!sub || !pub || !priv) return
    try {
      const body = await encryptPush(te.encode(frame), sub.keys)
      const res = await fetch(sub.endpoint, {
        method: 'POST',
        headers: { authorization: await vapidAuthorization(sub.endpoint, { publicKey: pub, privateKey: priv, subject: subject || 'mailto:relay@clarityaui.com' }), 'content-encoding': 'aes128gcm', 'content-type': 'application/octet-stream', ttl: '600', urgency: 'high' },
        body
      })
      // The push service's word that the subscription is gone: forget it, rather than post to it on every notice.
      if (res.status === 404 || res.status === 410) await this.ctx.storage.delete('sub')
    } catch {
      /* a push is a courtesy: the envelope still waits in the queue */
    }
  }
}
