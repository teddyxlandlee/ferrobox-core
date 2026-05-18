# FerroBox Core

**English** | [中文](#中文)

## English

FerroBox Core is a TypeScript library for secure, client-side encryption and decryption using **ChaCha20-Poly1305** segmented AEAD streaming. Designed for browser and Node.js environments, it provides end-to-end encryption for file storage where only the client holds the symmetric key.

### Features

- 🔐 **ChaCha20-Poly1305 AEAD Encryption**: Industry-standard authenticated encryption
- 🌊 **Segmented Streaming**: 64KiB per-record framing with independent verification
- 🔑 **Client-Controlled Keys**: Server never accesses plaintext or encryption keys
- 🌐 **Browser Compatible**: Works in modern browsers via Web Crypto APIs
- 📦 **TypeScript**: Full type definitions for IDE support
- 🚀 **Zero Dependencies on Crypto Primitives**: Uses `@noble/ciphers` for AEAD operations

### Installation

```bash
npm install github:teddyxlandlee/ferrobox-core
```

Or from a Git repository:

```json
{
  "dependencies": {
    "ferrobox-core": "github:teddyxlandlee/ferrobox-core"
  }
}
```

### Quick Start

#### Encryption & Upload

```typescript
import { encrypt, upload } from 'ferrobox-core'

// Prepare data
const data = new TextEncoder().encode('Secret content')

// Encrypt data
const encryptResult = await encrypt(data)

const UPLOAD_THRESHOLD = 512;

// Upload to your backend or return a data URL
const uploadEngine = {
  async uploadData(input) {
    const encryptedBytes = await streamToUint8Array(input.encodedStream)
    if (encryptedBytes.byteLength > UPLOAD_THRESHOLD) {
      return await yourBackend.uploadData(encryptedBytes)
    }
    return `data:application/octet-stream;base64,${base64Encode(encryptedBytes)}`
  },
  async uploadMeta(metaOut) {
    return await yourBackend.uploadMeta(metaOut)
  }
}

const metaSlug = await upload(data, uploadEngine, { mime: 'text/plain' })
```

#### Download & Decryption

```typescript
import { download } from 'ferrobox-core'

// Fetch metadata from server
const metaOut = await yourBackend.fetchMeta(metaSlug)

// Decrypt with the original key
const decryptedStream = await download(metaOut, encryptionKey)

// Read the plaintext
const plaintext = await streamToUint8Array(decryptedStream)
```

### API

#### `encrypt(input: EncryptInput): Promise<EncryptResult>`

Encrypts a stream or Blob with random key and nonce.

**Returns**: Encryption metadata and an encoded stream.

#### `upload(input: EncryptInput, engine: UploadEngine, extra?: { mime?: string }): Promise<string>`

Encrypts data, then calls `engine.uploadData` to store the encrypted payload. That function may upload the data to a real server or return a `data:` URL instead. If your application prefers a hybrid strategy, use a size threshold in `engine.uploadData`: upload large payloads to the server, and encode small payloads as a data URL.

#### `download(metaOut: MetaOut, key: Uint8Array): Promise<DecryptResult>`

Decrypts metadata and returns a decrypted stream.

#### `decrypt(input: DecryptInput): Promise<DecryptResult>`

Decrypts a stream with verification.

### Architecture

- **Data Format**: 64KiB segmented chunks with per-record Poly1305 tags
- **Metadata**: Encrypted JSON containing encryption parameters and data reference
- **Key Derivation**: Random keys per file; nonces from Crypto API
- **Verification**: SHA-512 hash of plaintext for integrity checking

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

### License

Licensed under the Apache License, Version 2.0. See [LICENSE.txt](LICENSE.txt) for details.

---

## 中文

FerroBox Core 是一个 TypeScript 库，提供基于 **ChaCha20-Poly1305** 分段 AEAD 流加密的安全客户端加密和解密功能。针对浏览器和 Node.js 环境设计，为文件存储提供端对端加密，只有客户端持有对称密钥。

### 特性

- 🔐 **ChaCha20-Poly1305 AEAD 加密**: 业界标准的认证加密
- 🌊 **分段流式处理**: 64KiB 每条记录，独立验证
- 🔑 **客户端控制密钥**: 服务器永远无法访问明文或加密密钥
- 🌐 **浏览器兼容**: 在现代浏览器中通过 Web Crypto API 工作
- 📦 **TypeScript**: 完整的类型定义，IDE 自动补全
- 🚀 **加密依赖最小化**: 使用 `@noble/ciphers` 提供 AEAD 操作

### 安装

```bash
npm install github:teddyxlandlee/ferrobox-core
```

或从 Git 仓库安装：

```json
{
  "dependencies": {
    "ferrobox-core": "github:teddyxlandlee/ferrobox-core"
  }
}
```

### 快速开始

#### 加密与上传

```typescript
import { encrypt, upload } from 'ferrobox-core'

// 准备数据
const data = new TextEncoder().encode('秘密内容')

// 加密数据
const encryptResult = await encrypt(data)

// 上传到后端或返回 data URL
const UPLOAD_THRESHOLD = 512;

const uploadEngine = {
  async uploadData(input) {
    const encryptedBytes = await streamToUint8Array(input.encodedStream)
    if (encryptedBytes.byteLength > UPLOAD_THRESHOLD) {
      return await yourBackend.uploadData(encryptedBytes)
    }
    return `data:application/octet-stream;base64,${base64Encode(encryptedBytes)}`
  },
  async uploadMeta(metaOut) {
    return await yourBackend.uploadMeta(metaOut)
  }
}

const metaSlug = await upload(data, uploadEngine, { mime: 'text/plain' })
```

#### 下载与解密

```typescript
import { download } from 'ferrobox-core'

// 从服务器获取元数据
const metaOut = await yourBackend.fetchMeta(metaSlug)

// 使用原始密钥解密
const decryptedStream = await download(metaOut, encryptionKey)

// 读取明文
const plaintext = await streamToUint8Array(decryptedStream)
```

### API 文档

#### `encrypt(input: EncryptInput): Promise<EncryptResult>`

使用随机密钥和 nonce 加密流或 Blob。

**返回**: 加密元数据和编码流。

#### `upload(input: EncryptInput, engine: UploadEngine, extra?: { mime?: string }): Promise<string>`

加密数据后会调用 `engine.uploadData` 来存储加密后的内容。该函数可以上传到真正的服务器，也可以返回 `data:` URL。推荐根据数据大小设定阈值：较大时上传到服务器，较小时保留为 data URL。

#### `download(metaOut: MetaOut, key: Uint8Array): Promise<DecryptResult>`

解密元数据并返回解密流。

#### `decrypt(input: DecryptInput): Promise<DecryptResult>`

解密流并进行完整性验证。

### 架构设计

- **数据格式**: 64KiB 分段块，每条记录独立 Poly1305 标签
- **元数据**: 包含加密参数和数据引用的加密 JSON
- **密钥生成**: 每个文件使用随机密钥；nonce 来自 Crypto API
- **验证**: SHA-512 哈希用于完整性检查

详见 [ARCHITECTURE.md](ARCHITECTURE.md)。

### 许可证

根据 Apache 许可证 2.0 版本许可。详见 [LICENSE.txt](LICENSE.txt)。
