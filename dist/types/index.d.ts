import { DataUploadRequest, DecryptInput, DecryptResult, EncryptInput, EncryptResult, MetaOut, MetaUploadRequest } from './types.js';
declare function encrypt(input: EncryptInput): Promise<EncryptResult>;
declare function upload(input: EncryptInput, engine: {
    uploadMeta: MetaUploadRequest;
    uploadData: DataUploadRequest;
}, extra?: {
    mime?: string;
}): Promise<string>;
declare function decrypt(input: DecryptInput): Promise<DecryptResult>;
declare function download(metaOut: MetaOut, key: Uint8Array): Promise<DecryptResult>;
export { encrypt, upload, decrypt, download };
