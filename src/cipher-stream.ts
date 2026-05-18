import { chacha20 } from '@noble/ciphers/chacha.js'
import { Poly1305 } from '@noble/ciphers/_poly1305.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { sha512 } from '@noble/hashes/sha2.js'
import {
    DecryptInput, DecryptResult,
    EncryptInput, EncryptResult
} from './types.js'

const FRAME_SIZE = 64 * 1024
const TAG_LENGTH = 16

function concatUint8(a: Uint8Array, b: Uint8Array | ArrayBufferLike): Uint8Array {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b as ArrayBufferLike)
    const result = new Uint8Array(a.length + bArr.length)
    result.set(a, 0)
    result.set(bArr, a.length)
    return result
}

function writeUint32BE(value: number, out: Uint8Array, offset = 0): void {
    new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(offset, value, false); // false = BE
}

function writeUint64LE(value: bigint, out: Uint8Array, offset = 0): void {
    new DataView(out.buffer, out.byteOffset, out.byteLength).setBigUint64(offset, value, true); // true = LE
}

function readUint32BE(input: Uint8Array, offset = 0): number {
      return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(offset, false);
}

function normalizeInputChunk(value: unknown): Uint8Array {
    if (value instanceof Uint8Array) {
        return value
    }
    if (value instanceof ArrayBuffer) {
        return new Uint8Array(value)
    }
    if (ArrayBuffer.isView(value)) {
        return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    }
    if (typeof value === 'string') {
        return new TextEncoder().encode(value)
    }
    return new TextEncoder().encode(String(value))
}

function addUint64LEToBytes(out: Uint8Array, offset: number, value: bigint): void {
    let carry = value
    for (let i = 0; i < 8; i++) {
        const sum = BigInt(out[offset + i]) + (carry & 0xffn)
        out[offset + i] = Number(sum & 0xffn)
        carry = (carry >> 8n) + (sum >> 8n)
    }
}

function deriveRecordNonce(baseNonce: Uint8Array, recordIndex: number): Uint8Array {
    if (baseNonce.length !== 12) {
        throw new Error('Nonce must be 12 bytes')
    }

    const nonce = new Uint8Array(baseNonce)
    addUint64LEToBytes(nonce, 4, BigInt(recordIndex))
    return nonce
}

function makeAad(recordIndex: number): Uint8Array {
    const aad = new Uint8Array(4)
    writeUint32BE(recordIndex, aad)
    return aad
}

function makeLengthsBlock(aadLength: bigint, ciphertextLength: bigint): Uint8Array {
    const block = new Uint8Array(16)
    writeUint64LE(aadLength, block, 0)
    writeUint64LE(ciphertextLength, block, 8)
    return block
}

function computePoly1305Tag(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array
): Uint8Array {
    const authKey = new Uint8Array(32)
    chacha20(key, nonce, new Uint8Array(32), authKey, 0)
    const poly = new Poly1305(authKey)

    if (aad.length > 0) {
        poly.update(aad)
        if (aad.length % 16 !== 0) {
            poly.update(new Uint8Array(16 - (aad.length % 16)))
        }
    }

    if (ciphertext.length > 0) {
        poly.update(ciphertext)
        if (ciphertext.length % 16 !== 0) {
            poly.update(new Uint8Array(16 - (ciphertext.length % 16)))
        }
    }

    poly.update(makeLengthsBlock(BigInt(aad.length), BigInt(ciphertext.length)))
    return poly.digest()
}

function encryptChunk(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array
): { ciphertext: Uint8Array; tag: Uint8Array } {
    const ciphertext = new Uint8Array(plaintext.length)
    chacha20(key, nonce, plaintext, ciphertext, 1)
    const tag = computePoly1305Tag(key, nonce, aad, ciphertext)
    return { ciphertext, tag }
}

function decryptChunk(
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array
): Uint8Array {
    const expectedTag = computePoly1305Tag(key, nonce, aad, ciphertext)
    if (!equalBytes(expectedTag, tag)) {
        throw new Error('ChaCha20-Poly1305 authentication failed')
    }

    const plaintext = new Uint8Array(ciphertext.length)
    chacha20(key, nonce, ciphertext, plaintext, 1)
    return plaintext
}

export async function pumpEncrypt(
    source: ReadableStream<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>,
    key: Uint8Array,
    nonceIn: Uint8Array,
    result: EncryptResult
): Promise<void> {
    const hash = sha512.create()
    let size = 0
    let recordIndex = 0
    const reader = source.getReader()

    try {
        while (true) {
            const { done, value } = await reader.read()
            if (done) {
                break
            }

            const plaintext = normalizeInputChunk(value)
            let offset = 0
            while (offset < plaintext.length) {
                const chunk = plaintext.subarray(offset, Math.min(offset + FRAME_SIZE, plaintext.length))
                hash.update(chunk)
                size += chunk.length

                const nonce = deriveRecordNonce(nonceIn, recordIndex)
                const aad = makeAad(recordIndex)
                const { ciphertext, tag } = encryptChunk(key, nonce, aad, chunk)

                const header = new Uint8Array(4)
                writeUint32BE(ciphertext.length, header)
                await writer.write(header)
                if (ciphertext.length > 0) {
                    await writer.write(ciphertext)
                }
                await writer.write(tag)

                recordIndex += 1
                offset += chunk.length
            }
        }

        result.sha512Hash = new Uint8Array(hash.digest())
        result.size = size
        await writer.close()
    } catch (error) {
        await writer.abort(error)
        throw error
    } finally {
        reader.releaseLock()
    }
}

export async function pumpDecrypt(
    source: ReadableStream<Uint8Array>,
    writer: WritableStreamDefaultWriter<Uint8Array>,
    key: Uint8Array,
    nonce: Uint8Array,
    verification: DecryptInput['verification']
): Promise<void> {
    const reader = source.getReader()
    const hash = verification?.sha512Hash ? sha512.create() : undefined
    let plaintextSize = 0
    let recordIndex = 0

    try {
        let pending: Uint8Array = new Uint8Array(0)
        while (true) {
            const { done, value } = await reader.read()
            if (done) {
                break
            }
            const chunk = normalizeInputChunk(value)
            pending = concatUint8(pending, chunk)

            while (pending.length >= 4) {
                const recordLength = readUint32BE(pending, 0)
                if (recordLength > FRAME_SIZE) {
                    throw new Error('Invalid record length')
                }

                const totalLength = 4 + recordLength + TAG_LENGTH
                if (pending.length < totalLength) {
                    break
                }

                const ciphertext = pending.subarray(4, 4 + recordLength)
                const tag = pending.subarray(4 + recordLength, totalLength)
                const nonceValue = deriveRecordNonce(nonce, recordIndex)
                const aad = makeAad(recordIndex)
                const plaintext = decryptChunk(key, nonceValue, aad, ciphertext, tag)

                if (hash) hash.update(plaintext)
                plaintextSize += plaintext.length
                await writer.write(plaintext)

                recordIndex += 1
                pending = pending.subarray(totalLength)
            }
        }

        if (pending.length !== 0) {
            throw new Error('Encrypted stream ended with incomplete record')
        }

        if (hash) {
            const actualHash = new Uint8Array(hash.digest())
            if (!equalBytes(actualHash, verification?.sha512Hash ?? new Uint8Array(0))) {
                throw new Error('SHA-512 verification failed')
            }
        }

        if (verification?.size != null && plaintextSize !== verification.size) {
            throw new Error('Size verification failed')
        }

        await writer.close()
    } catch (error) {
        await writer.abort(error)
        throw error
    } finally {
        reader.releaseLock()
    }
}

export async function encrypt(input: EncryptInput, extra?: { mime?: string }): Promise<EncryptResult> {
    const key = randomBytes(32)
    const nonceIn = randomBytes(12)
    const nonceOut = randomBytes(12)

    const stream = new TransformStream<Uint8Array, Uint8Array>()
    const writer = stream.writable.getWriter()
    const source = input instanceof Blob ? (input.stream() as unknown as ReadableStream<Uint8Array>) : (input as ReadableStream<Uint8Array>)

    const result: EncryptResult = {
        key,
        nonceIn,
        nonceOut,
        sha512Hash: new Uint8Array(0),
        size: 0,
        encodedStream: stream.readable
    }

    pumpEncrypt(source, writer, key, nonceIn, result).catch((error) => {
        void writer.abort(error)
    })

    return result
}

export async function decrypt(input: DecryptInput): Promise<DecryptResult> {
    const source = input.data instanceof Blob ? (input.data.stream() as unknown as ReadableStream<Uint8Array>) : (input.data as ReadableStream<Uint8Array>)
    const stream = new TransformStream<Uint8Array, Uint8Array>()
    const writer = stream.writable.getWriter()

    pumpDecrypt(source, writer, input.key, input.nonce, input.verification).catch((error) => {
        void writer.abort(error)
    })

    return stream.readable
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false
        }
    }
    return true
}
