/**
 * WEB PUSH FROM THE RELAY: RFC 8291's aes128gcm encryption of a payload to one browser's subscription, and
 * RFC 8292's VAPID header naming this relay to the push service. WebCrypto only, so it runs in the Worker and in node.
 *
 * What it encrypts is already a sealed envelope (src/shared/relayCrypto.ts): the push service sees ciphertext under this
 * layer, and this relay never saw anything but ciphertext under that one.
 *
 * test:relayworker holds the encryption to RFC 8291's own worked example, byte for byte.
 */

const te = new TextEncoder()
const subtle = (): SubtleCrypto => globalThis.crypto.subtle

export function b64u(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ''
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function unb64u(s: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('not base64url')
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4))
  const u = new Uint8Array(b.length)
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i)
  return u
}

const concat = (...parts: Uint8Array[]): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

async function hkdf(salt: Uint8Array<ArrayBuffer>, ikm: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>, bytes: number): Promise<Uint8Array<ArrayBuffer>> {
  const key = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8))
}

/** A P-256 key pair from its raw public point and its private scalar, as the RFC's example gives them. */
export async function importEcdhPair(publicRaw: string, privateD: string): Promise<CryptoKeyPair> {
  const pub = unb64u(publicRaw)
  const jwk = { kty: 'EC', crv: 'P-256', x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), d: privateD, ext: true }
  const privateKey = await subtle().importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const publicKey = await subtle().importKey('raw', pub, { name: 'ECDH', namedCurve: 'P-256' }, true, [])
  return { privateKey, publicKey }
}

export type PushSubscriptionKeys = { p256dh: string; auth: string }

/**
 * The body of one push message: salt, record size, the sender's public key, then one record of the payload padded with the
 * last-record delimiter (RFC 8291 §4, RFC 8188). `fixed` is for the RFC's example: its sender keys and salt.
 */
export async function encryptPush(payload: Uint8Array<ArrayBuffer>, sub: PushSubscriptionKeys, fixed?: { as: CryptoKeyPair; salt: Uint8Array<ArrayBuffer> }): Promise<Uint8Array<ArrayBuffer>> {
  const uaPublicRaw = unb64u(sub.p256dh)
  const authSecret = unb64u(sub.auth)
  if (uaPublicRaw.length !== 65 || uaPublicRaw[0] !== 4) throw new Error('the subscription key is not a P-256 point')
  if (authSecret.length !== 16) throw new Error('the subscription auth secret is not 16 bytes')
  const as = fixed?.as ?? ((await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair)
  const salt = fixed?.salt ?? globalThis.crypto.getRandomValues(new Uint8Array(16))
  const uaPublic = await subtle().importKey('raw', uaPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const asPublicRaw = new Uint8Array(await subtle().exportKey('raw', as.publicKey))
  const ecdhSecret = new Uint8Array(await subtle().deriveBits({ name: 'ECDH', public: uaPublic }, as.privateKey, 256))
  const keyInfo = concat(te.encode('WebPush: info\0'), uaPublicRaw, asPublicRaw)
  const ikm = await hkdf(authSecret, ecdhSecret, keyInfo, 32)
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12)
  const key = await subtle().importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt'])
  const record = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(payload, new Uint8Array([2]))))
  const rs = new Uint8Array([0, 0, 16, 0]) // 4096, big-endian
  return concat(salt, rs, new Uint8Array([asPublicRaw.length]), asPublicRaw, record)
}

/** The VAPID signing key: a P-256 key pair whose raw public point push services see as `k=`. */
export type Vapid = { publicKey: string; privateKey: string; subject: string }

/** `Authorization: vapid t=<JWT>, k=<public key>` for a push to `endpoint` (RFC 8292), good for twelve hours from `now`. */
export async function vapidAuthorization(endpoint: string, vapid: Vapid, now = Date.now()): Promise<string> {
  const aud = new URL(endpoint).origin
  const header = b64u(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })))
  const claims = b64u(te.encode(JSON.stringify({ aud, exp: Math.floor(now / 1000) + 12 * 3600, sub: vapid.subject })))
  const pub = unb64u(vapid.publicKey)
  const jwk = { kty: 'EC', crv: 'P-256', x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), d: vapid.privateKey, ext: true }
  const key = await subtle().importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
  const sig = await subtle().sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(`${header}.${claims}`))
  return `vapid t=${header}.${claims}.${b64u(sig)}, k=${vapid.publicKey}`
}

/**
 * The push services the phone browsers use. ⚠ Anyone who can write to a mailbox can register a subscription, so one naming
 * any https host would have the relay post to it on every notice: only these hosts are taken.
 */
export const PUSH_HOSTS = ['fcm.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com', 'notify.windows.com'] as const

export function pushEndpointOk(endpoint: string): boolean {
  let u: URL
  try {
    u = new URL(endpoint)
  } catch {
    return false
  }
  const host = u.hostname.toLowerCase()
  return u.protocol === 'https:' && !u.username && !u.password && !u.port && endpoint.length <= 1024 && PUSH_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))
}
