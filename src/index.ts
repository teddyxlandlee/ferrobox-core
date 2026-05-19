import {
    DataSourceResolver,
    DataUploadRequest,
    DecryptInput, DecryptResult,
    EncryptInput, EncryptResult,
    MetaIn, MetaInV1, MetaOut, MetaOutV10, MetaUploadRequest,
    PadRule,
    UploadExtraArgs,
} from './types.js'

import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { Base64 } from 'js-base64'
import { encrypt as streamEncrypt, decrypt as streamDecrypt } from './cipher-stream.js'
import { randomBytes } from '@noble/ciphers/utils.js'

async function encrypt(input: EncryptInput): Promise<EncryptResult> {
    return streamEncrypt(input)
}

async function upload(
    input: EncryptInput,
    engine: {
        uploadMeta: MetaUploadRequest,
        uploadData: DataUploadRequest
    },
    extra?: UploadExtraArgs
): Promise<string> {
    const encryptResult = await encrypt(input)
    const dataUri = await engine.uploadData(encryptResult)
    const metaOut = await createMetaOut(encryptResult, dataUri, extra)
    return engine.uploadMeta(metaOut)
}

async function createMetaOut(
    meta: EncryptResult,
    dataUri: string,
    extra?: UploadExtraArgs
): Promise<MetaOutV10> {
    const rawMetaIn = {
        schema_in: 1,
        nonce_in: Base64.fromUint8Array(meta.nonceIn),
        data_in: dataUri,
        hash: Base64.fromUint8Array(meta.sha512Hash),
        size: meta.size,
        mime: extra?.mime
    }

    const rawMetaInJson = JSON.stringify(rawMetaIn)
    const cipherOut = chacha20poly1305(meta.key, meta.nonceOut)
    const metaInCiphertext = cipherOut.encrypt(randomPad(
        new TextEncoder().encode(rawMetaInJson),
        extra?.metaPadRule,
    ))
    // const paddedMetaInCiphertext = randomPad(metaInCiphertext, extra?.metaPadRule)

    return {
        schema_out: 10,
        nonce_out: Base64.fromUint8Array(meta.nonceOut),
        meta_in: Base64.fromUint8Array(metaInCiphertext)
    }
}

function randomPad(original: Uint8Array, padRule: PadRule | undefined): Uint8Array {
    if (padRule === null) {
        return original;
    } else if (padRule === undefined) {
        padRule = (size: number) => Math.ceil(size / 1024) * 1024
    } else if (typeof padRule === 'number') {
        padRule = (size: number) => size;
    }
    const originalSize = original.length;
    const targetSize = padRule(originalSize);
    if (targetSize <= originalSize) return original;

    const padding = randomBytes(targetSize - originalSize);
    return concatUint8(original, padding);
}

function concatUint8(a: Uint8Array, b: Uint8Array | ArrayBufferLike): Uint8Array {
    const bArr = b instanceof Uint8Array ? b : new Uint8Array(b as ArrayBufferLike)
    const result = new Uint8Array(a.length + bArr.length)
    result.set(a, 0)
    result.set(bArr, a.length)
    return result
}

async function decrypt(input: DecryptInput): Promise<DecryptResult> {
    return streamDecrypt(input)
}

async function download(metaOut: MetaOut, key: Uint8Array, resolveDataStream: DataSourceResolver = defaultFetchDataSource): Promise<DecryptResult> {
    if (!isMetaOutV10(metaOut)) {
        throw new Error('Unsupported metadata schema version')
    }

    const nonceOut = Base64.toUint8Array(metaOut.nonce_out)
    const metaInCiphertext = Base64.toUint8Array(metaOut.meta_in)
    const cipherOut = chacha20poly1305(key, nonceOut)
    const rawMetaIn = cipherOut.decrypt(metaInCiphertext)
    const rawMetaInText = new TextDecoder().decode(rawMetaIn)
    const metaJson = parseJsonRoot<MetaIn>(rawMetaInText)
    validateMetaInV1(metaJson)

    const source = await resolveDataStream(metaJson.data_in)
    return streamDecrypt({
        data: source,
        key,
        nonce: Base64.toUint8Array(metaJson.nonce_in),
        verification: {
            sha512Hash: Base64.toUint8Array(metaJson.hash),
            size: metaJson.size
        }
    })
}

function parseJsonRoot<T extends object>(text: string): T {
    if (typeof text !== 'string' || text.length === 0 || text[0] !== '{') {
        throw new Error('Invalid JSON: not an object')
    }

    let depth = 0
    let inString = false
    let escape = false

    for (let i = 0; i < text.length; i++) {
        const ch = text[i]
        if (inString) {
            if (escape) {
                escape = false
            } else if (ch === '\\') {
                escape = true
            } else if (ch === '"') {
                inString = false
            }
            continue
        }

        if (ch === '"') {
            inString = true
        } else if (ch === '{') {
            depth++
        } else if (ch === '}') {
            depth--
            if (depth === 0) {
                return JSON.parse(text.slice(0, i + 1))
            }
        }
    }

    throw new Error('Failed to parse raw_meta_in JSON')
}

function validateMetaInV1(meta: MetaIn): asserts meta is MetaInV1 {
    if (meta.schema_in !== 1) {
        throw new Error('Unsupported raw_meta_in schema version')
    }
    const metaJson = meta as MetaInV1   // typesafe
    
    if (typeof metaJson.data_in !== 'string') {
        throw new Error('raw_meta_in.data_in must be a string')
    }
    if (typeof metaJson.nonce_in !== 'string') {
        throw new Error('raw_meta_in.nonce_in must be a base64 string')
    }
    if (typeof metaJson.hash !== 'string') {
        throw new Error('raw_meta_in.hash must be a base64 string')
    }
    if (typeof metaJson.size !== 'number') {
        throw new Error('raw_meta_in.size must be a number')
    }
}

async function defaultFetchDataSource(dataIn: string): Promise<ReadableStream<Uint8Array>> {
    if (dataIn.startsWith('data:')) {
        const commaIndex = dataIn.indexOf(',')
        if (commaIndex < 0) {
            throw new Error('Invalid data URL')
        }
        const metadata = dataIn.slice(5, commaIndex)
        const dataPart = dataIn.slice(commaIndex + 1)
        const isBase64 = metadata.endsWith(';base64')
        const bytes = isBase64
            ? Base64.toUint8Array(dataPart)
            : new TextEncoder().encode(decodeURIComponent(dataPart))
        return new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(bytes)
                controller.close()
            }
        })
    }

    const response = await fetch(dataIn)
    if (!response.ok) {
        throw new Error(`Fetch failed: ${response.status} ${response.statusText}`)
    }
    if (!response.body) {
        throw new Error('Fetch response has no body')
    }
    return response.body as ReadableStream<Uint8Array>
}

function isMetaOutV10(meta: MetaOut): meta is MetaOutV10 {
    return meta.schema_out === 10 && 'nonce_out' in meta && 'meta_in' in meta
}

export { encrypt, upload, decrypt, download, defaultFetchDataSource }
