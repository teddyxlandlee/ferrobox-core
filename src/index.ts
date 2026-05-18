import {
    DataUploadRequest,
    DecryptInput, DecryptResult,
    EncryptInput, EncryptResult,
    MetaGenerator, MetaIn, MetaInV1, MetaOut, MetaOutV10, MetaUploadRequest
} from './types.js'

import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { Base64 } from 'js-base64'
import { encrypt as streamEncrypt, decrypt as streamDecrypt } from './cipher-stream.js'

async function encrypt(input: EncryptInput, extra?: { mime?: string }): Promise<EncryptResult> {
    return streamEncrypt(input, extra)
}

async function upload(
    input: EncryptInput,
    engine: {
        uploadMeta: MetaUploadRequest,
        uploadData: DataUploadRequest,
        genMeta: MetaGenerator
    },
    extra?: { mime?: string }
): Promise<string> {
    const encryptResult = await encrypt(input, extra)
    const dataUri = await engine.uploadData(encryptResult)
    const metaOut = await engine.genMeta(encryptResult, dataUri)
    return engine.uploadMeta(metaOut)
}

async function decrypt(input: DecryptInput): Promise<DecryptResult> {
    return streamDecrypt(input)
}

async function download(metaOut: MetaOut, key: Uint8Array): Promise<DecryptResult> {
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

    const source = await fetchDataSource(metaJson.data_in)
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

async function fetchDataSource(dataIn: string): Promise<ReadableStream<Uint8Array>> {
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

export { encrypt, upload, decrypt, download }
