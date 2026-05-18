import { TextEncoder, TextDecoder } from 'node:util'

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

async function main() {
  const module = await import('../dist/index.mjs')
  const { encrypt, decrypt } = module

  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const plaintext = encoder.encode('Segmented AEAD test. '.repeat(4096))

  const encrypted = await encrypt(makeReadableStream(plaintext))
  const encryptedData = await streamToUint8Array(encrypted.encodedStream)

  assert(encryptedData.length > 0, 'Encrypted stream should produce output')
  assert(encrypted.size === plaintext.length, 'Encrypt size should match plaintext length')

  const decryptedStream = await decrypt({
    data: makeReadableStream(encryptedData),
    key: encrypted.key,
    nonce: encrypted.nonceIn,
    verification: {
      sha512Hash: encrypted.sha512Hash,
      size: encrypted.size
    }
  })

  const decryptedData = await streamToUint8Array(decryptedStream)
  assert(decryptedData.length === plaintext.length, 'Decrypted length should match plaintext length')
  assert(decoder.decode(decryptedData) === decoder.decode(plaintext), 'Decrypted content should equal plaintext')

  console.log('PASS: segmented AEAD round-trip')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
