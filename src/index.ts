import {
    DataUploadRequest,
    DecryptInput, DecryptResult,
    EncryptInput, EncryptResult,
    MetaGenerator, MetaOut, MetaUploadRequest
} from './types.js'

declare function encrypt(input: EncryptInput, extra?: {
    mime?: string
}): Promise<EncryptResult>;

declare function upload(input: EncryptInput, engine: {
    uploadMeta: MetaUploadRequest,
    uploadData: DataUploadRequest,
    genMeta: MetaGenerator
}, extra?: {
    mime?: string
}): Promise<string>;

declare function decrypt(input: DecryptInput): Promise<DecryptResult>;

declare function download(metaOut: MetaOut, key: Uint8Array) : Promise<DecryptResult>;