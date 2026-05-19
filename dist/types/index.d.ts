import { DataSourceResolver, DataUploadRequest, DecryptInput, DecryptResult, EncryptInput, EncryptResult, MetaOut, MetaUploadRequest, UploadExtraArgs } from './types.js';
declare function encrypt(input: EncryptInput): Promise<EncryptResult>;
declare function upload(input: EncryptInput, engine: {
    uploadMeta: MetaUploadRequest;
    uploadData: DataUploadRequest;
}, extra?: UploadExtraArgs): Promise<string>;
declare function decrypt(input: DecryptInput): Promise<DecryptResult>;
declare function download(metaOut: MetaOut, key: Uint8Array, resolveDataStream?: DataSourceResolver): Promise<DecryptResult>;
declare function defaultFetchDataSource(dataIn: string): Promise<ReadableStream<Uint8Array>>;
export { encrypt, upload, decrypt, download, defaultFetchDataSource };
