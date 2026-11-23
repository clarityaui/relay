#!/usr/bin/env node
/**
 * The relay's push key: a fresh P-256 key pair the relay signs Web Push requests with (RFC 8292), handed to
 * the deployed Worker as two secrets through wrangler's stdin. Neither half is printed, logged or written to a file.
 *
 *   node scripts/vapid.mjs              set the key, refusing when one is already set
 *   node scripts/vapid.mjs --rotate     replace it: every phone's notifications stop until it allows them again
 *   node scripts/vapid.mjs --dry-run    make a key and say what would be set, setting nothing
 *
 * ⚠ The relay must be deployed first (`npx wrangler deploy`): a secret put to a
 *   Worker that does not exist asks to create one. Exit 2 when it set nothing because it could not ask wrangler.
 */
import { spawnSync } from 'node:child_process'
import { webcrypto } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const CONFIG = 'wrangler.jsonc'
const NAMES = ['VAPID_PUBLIC_KEY', 'VAPID_PRIVATE_KEY']
const args = new Set(process.argv.slice(2))
const b64u = (bytes) => Buffer.from(bytes).toString('base64url')
const wrangler = (argv, input) => {
  const r = spawnSync(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['wrangler', ...argv, '--config', CONFIG], { cwd: root, input, encoding: 'utf8', shell: process.platform === 'win32' })
  return { code: r.status ?? 1, out: `${r.stdout || ''}${r.stderr || ''}` }
}

const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
const publicKey = b64u(new Uint8Array(await webcrypto.subtle.exportKey('raw', pair.publicKey)))
const privateKey = (await webcrypto.subtle.exportKey('jwk', pair.privateKey)).d
if (publicKey.length !== 87 || !privateKey || privateKey.length !== 43) {
  console.log('REFUSED: the key did not come out as a P-256 pair; nothing was set')
  process.exit(2)
}
if (args.has('--dry-run')) {
  console.log(`would set ${NAMES.join(' and ')} on the relay (${CONFIG}): a ${publicKey.length}-character public key and a ${privateKey.length}-character private one`)
  process.exit(0)
}

const listed = wrangler(['secret', 'list', '--format', 'json'])
let have = []
try {
  have = JSON.parse(listed.out.slice(listed.out.indexOf('['))).map((s) => s.name)
} catch {
  console.log(`REFUSED: could not list the relay's secrets (wrangler exit ${listed.code}); is it deployed, and are you signed in to wrangler? Nothing was set.`)
  process.exit(2)
}
const set = NAMES.filter((n) => have.includes(n))
if (set.length && !args.has('--rotate')) {
  console.log(`the relay already has ${set.join(' and ')}; nothing was set. Replacing it stops every phone's notifications until it allows them again: pass --rotate for that.`)
  process.exit(0)
}
for (const [name, value] of [[NAMES[0], publicKey], [NAMES[1], privateKey]]) {
  const r = wrangler(['secret', 'put', name], value)
  if (r.code !== 0) {
    console.log(`FAILED: wrangler could not set ${name} (exit ${r.code}). ${name === NAMES[1] ? `${NAMES[0]} is set without its private half: run this again with --rotate.` : 'Nothing was set.'}`)
    process.exit(1)
  }
  console.log(`set ${name}`)
}
console.log('the relay signs pushes with its new key; a phone that allows notifications subscribes under it')
