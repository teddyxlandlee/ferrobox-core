import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises'
import { join, basename } from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { TextEncoder, TextDecoder } from 'node:util'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'

async function streamToUint8Array(stream) {
  const reader = stream.getReader()
  const chunks = []
  let total = 0

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    total += value.byteLength
  }

  const output = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.byteLength
  }
  return output
}

function makeReadableStream(bytes) {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    }
  })
}

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function randomSlug(prefix) {
  return `${prefix}-${crypto.randomBytes(6).toString('hex')}`
}

async function makeDataUrl(bytes) {
  const base64 = Buffer.from(bytes).toString('base64')
  return `data:application/octet-stream;base64,${base64}`
}

async function main() {
  const module = await import('../dist/index.mjs')
  const { upload, download } = module

  const tempDir = await mkdtemp(join(os.tmpdir(), 'f01-7c7-icu-'))

  let server = null
  try {
    const encoder = new TextEncoder()
    const decoder = new TextDecoder()
    const plaintext = encoder.encode('FerroBox upload/download test. '.repeat(2048))
    await writeFile(join(tempDir, 'source.bin'), plaintext)

    const dataSlug = randomSlug('data')
    const metaSlug = randomSlug('meta')
    const dataFilePath = join(tempDir, `${dataSlug}.bin`)
    const metaFilePath = (mode) => join(tempDir, `${metaSlug}@${mode}.json`)

    // start a tiny static HTTP server to serve files from tempDir
    const http = await import('node:http')
    server = http.createServer(async (req, res) => {
      try {
        const p = decodeURIComponent(req.url?.slice(1) || '')
        const full = join(tempDir, p)
        const data = await readFile(full)
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
        res.end(data)
      } catch (err) {
        res.writeHead(404)
        res.end('Not Found')
      }
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    // @ts-ignore address may be string | AddressInfo
    const port = address && typeof address === 'object' ? address.port : 0

    let savedMetaOut = null
    let savedKey = null

    // Run two modes: 1) data URL returned by uploadData, 2) server-stored file (file://) returned by uploadData
    for (const mode of ['data-url', 'stored-file']) {
      savedMetaOut = null
      savedKey = null
      // prepare per-mode engine
      const engine = {
        async uploadData(input) {
          savedKey = input.key
          const encryptedData = await streamToUint8Array(input.encodedStream)
          if (mode === 'data-url') {
            // return data URL (no reliance on written file)
            return makeDataUrl(encryptedData)
          } else {
            // write to randomized data file and return http:// URL served by our server
            await writeFile(dataFilePath, encryptedData)
            return `http://127.0.0.1:${port}/${basename(dataFilePath)}`
          }
        },
        async uploadMeta(metaOut) {
          savedMetaOut = metaOut
          await writeFile(metaFilePath(mode), JSON.stringify(metaOut, null, 2))
          return metaSlug
        }
      }

      const result = await upload(makeReadableStream(plaintext), engine, { mime: 'application/octet-stream' })
      assert(result === metaSlug, 'upload should return a random metadata slug')
      assert(savedMetaOut !== null, 'Saved metadata must be available')
      assert(savedKey !== null, 'Saved key must be available')

      if (mode === 'stored-file') {
        const writtenData = await readFile(dataFilePath)
        assert(writtenData.length > 0, 'Randomized data file should exist')
      }

      const decryptedStream = await download(savedMetaOut, savedKey)
      const decryptedBytes = await streamToUint8Array(decryptedStream)

      assert(decryptedBytes.length === plaintext.length, `Downloaded plaintext length must match for mode ${mode}`)
      assert(decoder.decode(decryptedBytes) === decoder.decode(plaintext), `Downloaded plaintext must equal original for mode ${mode}`)
    }

    console.log('PASS: upload/download round-trip')
    } finally {
      if (server && typeof server.close === 'function') {
        server.close()
      }
      if (!process.env.KEEP_FERROBOX_TEMP) {
        await rm(tempDir, { recursive: true, force: true })
      } else {
        console.log(`Temp directory preserved at ${tempDir} due to KEEP_FERROBOX_TEMP env var`)
      }
    }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
