// meta
export type Base64String = string;

export interface MetaOut {
    schema_out: number
}

export interface MetaOutV10 extends MetaOut {
    /** Must be 10 */
    schema_out: number,
    /** base64(random(bytes=12)) */
    nonce_out: Base64String,
    /** base64(chacha20poly1305(
     *    key=key,
     *    nonce=nonce_out,
     *    data=aligned(raw_meta_in)
     *  ))
    */
    meta_in: Base64String,
}

export interface MetaIn {
    schema_in: number
}

export interface MetaInV1 extends MetaIn {
    /** Must be 1 */
    schema_in: number,
    /** base64(random(bytes=12)) */
    nonce_in: Base64String,
    /** URI */
    data_in: string,

    hash: Base64String
    size: number,
    mime?: string | undefined,
}

// encrypt
export type EncryptInput = ReadableStream | Blob;

export interface EncryptMeta {  // only related to data encryption, irrelevant to meta
    key: Uint8Array,
    nonceIn: Uint8Array,
    nonceOut: Uint8Array,

    sha512Hash: Uint8Array,
    size: number,
}

export interface EncryptResult extends EncryptMeta {
    encodedStream: typeof TransformStream.prototype.readable,
}

// decrypt
export interface DecryptInput { // only related to data decryption. irrelevant to meta
    data: ReadableStream | Blob,
    key: Uint8Array,
    nonce: Uint8Array,  // here is nonceIn

    verification?: {
        sha512Hash?: Uint8Array,
        size?: number
    }
};

export type DecryptResult = typeof TransformStream.prototype.readable;

// web api
// - upload
/** @returns data uri */
export type DataUploadRequest = (input: EncryptResult) => Promise<string>
/** @returns slug */
export type MetaUploadRequest = (input: MetaOutV10) => Promise<string>

export type PadRule = ((originalSize: number) => number) | null | number;

export interface UploadExtraArgs {
    mime?: string,
    /**
     *  @returns null -> no padding;
     *           undefined -> use default;
     *           number -> constant;
     *           function -> use the returned value as target size
     */
    metaPadRule?: PadRule,
}
// - download
export type DataSourceResolver = (uri: string) => Promise<ReadableStream<Uint8Array>>;