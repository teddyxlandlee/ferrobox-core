export type Base64String = string;
export interface MetaOut {
    schema_out: number;
}
export interface MetaOutV10 extends MetaOut {
    /** Must be 10 */
    schema_out: 10;
    /** base64(random(bytes=12)) */
    nonce_out: Base64String;
    /** base64(chacha20poly1305(
     *    key=key,
     *    nonce=nonce_out,
     *    data=aligned(raw_meta_in)
     *  ))
    */
    meta_in: Base64String;
}
export interface MetaIn {
    schema_in: number;
}
export interface MetaInV1 extends MetaIn {
    /** Must be 1 */
    schema_in: 1;
    /** base64(random(bytes=12)) */
    nonce_in: Base64String;
    /** URI */
    data_in: string;
    hash: Base64String;
    size: number;
    mime?: string | undefined;
}
export type EncryptInput = ReadableStream | Blob;
export interface EncryptMeta {
    key: Uint8Array;
    nonceIn: Uint8Array;
    nonceOut: Uint8Array;
    sha512Hash: Uint8Array;
    size: number;
}
export interface EncryptResult extends EncryptMeta {
    encodedStream: typeof TransformStream.prototype.readable;
}
export interface DecryptInput {
    data: ReadableStream | Blob;
    key: Uint8Array;
    nonce: Uint8Array;
    verification?: {
        sha512Hash?: Uint8Array;
        size?: number;
    };
}
export type DecryptResult = typeof TransformStream.prototype.readable;
/** @returns data uri */
export type DataUploadRequest = (input: EncryptResult) => Promise<string>;
/** @returns slug */
export type MetaUploadRequest = (input: MetaOutV10) => Promise<string>;
export type PadRule = ((originalSize: number) => number) | null | number;
export interface UploadExtraArgs {
    mime?: string;
    /**
     *  @returns null -> no padding;
     *           undefined -> use default;
     *           number -> constant;
     *           function -> use the returned value as target size
     */
    metaPadRule?: PadRule;
}
export type DataSourceResolver = (uri: string) => Promise<ReadableStream<Uint8Array>>;
