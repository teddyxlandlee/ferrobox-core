import { DecryptInput, DecryptResult, EncryptInput, EncryptResult } from './types.js';
export declare function pumpEncrypt(source: ReadableStream<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>, key: Uint8Array, nonceIn: Uint8Array, result: EncryptResult): Promise<void>;
export declare function pumpDecrypt(source: ReadableStream<Uint8Array>, writer: WritableStreamDefaultWriter<Uint8Array>, key: Uint8Array, nonce: Uint8Array, verification: DecryptInput['verification']): Promise<void>;
export declare function encrypt(input: EncryptInput): Promise<EncryptResult>;
export declare function decrypt(input: DecryptInput): Promise<DecryptResult>;
