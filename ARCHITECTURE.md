# FerroBox - Architecture
FerroBox是一个对称加密存储文件的工具链，可在浏览器等客户端进行加密/上传、下载/解密。

加密核心算法为ChaCha20Poly1305。任何不知道对称密钥的人（包括服务器后端）都无法获取原始数据。

对称密钥由客户端生成，每个文件加密时必须生成新的密钥。

## 数据结构
一个FerroBox实现会存储两种数据：Meta和Data。

## Data
Data是原数据（raw_data）通过分段 ChaCha20-Poly1305 AEAD 加密后的二进制数据。

每个 Data 记录采用固定 64KiB 分块加密，记录格式为：

- `record_length`：4 字节大端整数，表示本条记录的 ciphertext 长度
- `ciphertext`：记录的加密数据
- `tag`：16 字节 ChaCha20-Poly1305 认证标签

每个记录使用独立 nonce，nonce 从 `nonce_in` 派生，记录号 `record_index` 作为 AAD。
这保证了每条记录都是“先验证、后输出”的安全流式处理。

Data 的文件路径可反映加密**后**数据的 SHA-512 值。

## Meta
Meta是JSON对象格式的文档，它的slug是访问对应文件的路径。

slug由上传后端指派，一般可为随机的NanoID。为避免文件数量等信息的泄露，slug不得与时间戳、文件数量等相关。

slug的符号限定为`^[0-9a-zA-Z_-]+$`。

Meta的格式如下：
```json
{
    "schema_out": 10,
    "nonce_out": base64(random(bytes=12)),
    "meta_in": base64(chacha20poly1305(
        key=key,
        nonce=nonce_out,
        data=aligned(raw_meta_in)
    ))
}
```
加密前的raw_meta_in为JSON对象格式。为避免基于数据长度的破译攻击，可以在raw_meta_in之后填充随机字节到固定的一个或几个长度。
解密时，根对象闭合后的字符应一律忽略。

> ![NOTE]
> raw_meta_in的具体格式暂未确定，以下是草稿：
```json
{
    "schema_in": 1,
    "nonce_in": base64(random(bytes=12)),
    "data_in": <uri_to_encrypted_data>,
    "hash": sha512(raw_data),
    "size": size(raw_data),
    "mime"?: string
}
```

`data_in` 可以是直接指向加密数据的服务器 URL，也可以是包含加密内容的 `data:` URL。对于小文件，推荐将其编码为 `data:` URL；对于大文件，则上传到后端服务器。通常的实现方式是在 `engine.uploadData` 里根据大小设定阈值，超过阈值时使用服务器存储，低于阈值时返回 `data:` URL。

Data和meta_in加密时使用的key为同一个key，nonce为不同的nonce。
