# DuckDB encrypted_parquet 扩展

[English README](README.md)

本仓库只保留一套实现：`parquet-native-encryptedwithconfig`。

它基于 DuckDB 自带的 Parquet 扩展构建 `encrypted_parquet` 可加载扩展，增加 Parquet Modular Encryption 写入、parquet-java/Spark 兼容模式，以及按单次 `COPY` 隔离的 Direct-KMS 元数据支持。

## 功能

- Parquet Modular Encryption 写入，支持文件级和模块级 AAD。
- parquet-java/Spark 兼容的 uniform encryption，语义对齐 `PropertiesDrivenCryptoFactory` 和 `InMemoryKMS`。
- COPY-local Direct-KMS 元数据，不同 `COPY` 可以使用独立的 KMS ID、URL 和类名配置。
- Direct-KMS 推荐通过 `footer_key_value` 配合 `from_base64()` / `from_hex()` 显式传入二进制 AES Key。
- Linux x86_64 与 Windows x64/MSVC 构建和打包脚本。
- Linux/Windows CI 验证扩展加载、二进制 Key 写入/读取回环，以及 COPY-local 元数据隔离。

## 目录结构

```text
parquet-native-encryptedwithconfig/
├── prepare_extension.py
├── prepare_extension_java_compat_final.py
├── prepare_extension_direct_kms_final.py
├── build-linux-native-final.sh
├── build-windows-native-final.ps1
├── java_compat_usage.sql
└── direct_kms_usage.sql
```

`prepare_extension.py` 是统一对外入口。两个 `*_final.py` 暂时保留为内部实现层，因为 Direct-KMS 逻辑本身就是在已经验证过的 Java-compatible 生成器上继续叠加 patch；这样可以减少重写核心加密逻辑带来的风险。

## 在已有 DuckDB 源码上生成扩展

默认模式包含 Java-compatible 基础层和 Direct-KMS overlay：

```bash
python3 parquet-native-encryptedwithconfig/prepare_extension.py /path/to/duckdb
```

如果只需要 Java-compatible 层：

```bash
python3 parquet-native-encryptedwithconfig/prepare_extension.py /path/to/duckdb --mode java-compat
```

生成后会得到：

```text
/path/to/duckdb/extension/encrypted_parquet/
/path/to/duckdb/extension/extension_config_encrypted_parquet.cmake
```

## 构建

当前构建脚本默认克隆 DuckDB `v1.5.5`。

### Linux

依赖：Python 3、Git、CMake、Ninja 和 C++ 编译器。

```bash
bash parquet-native-encryptedwithconfig/build-linux-native-final.sh
```

产物目录：

```text
parquet-native-encryptedwithconfig/dist/linux_amd64/
parquet-native-encryptedwithconfig/dist/linux_amd64.tar.gz
```

### Windows

依赖：Python 3、Git、带 C++ workload 的 Visual Studio Build Tools，以及 Visual Studio 自带的 CMake。

```powershell
.\parquet-native-encryptedwithconfig\build-windows-native-final.ps1
```

产物目录：

```text
parquet-native-encryptedwithconfig\dist\windows_amd64\
parquet-native-encryptedwithconfig\dist\windows_amd64.zip
```

## 加载扩展

使用允许加载 unsigned extension 的 DuckDB shell：

```bash
./duckdb -unsigned
```

然后执行：

```sql
LOAD 'encrypted_parquet.duckdb_extension';
```

## Java-compatible uniform encryption

完整示例见：`parquet-native-encryptedwithconfig/java_compat_usage.sql`。

配置接口：

```sql
PRAGMA set_encrypted_parquet_config('name', 'value');
PRAGMA unset_encrypted_parquet_config('name');
PRAGMA clear_encrypted_parquet_config;
```

当前兼容层实现 Hadoop-style uniform encryption。按列的 Hadoop-style encryption 目前有意不实现。

## Direct-KMS 元数据

完整示例见：`parquet-native-encryptedwithconfig/direct_kms_usage.sql`。

新代码推荐把实际 AES Key 作为二进制数据传给 `footer_key_value`。Base64 或 Hex 文本应显式解码，避免 Key 长度判断歧义：

```sql
COPY (SELECT 1 AS id, 'secret' AS payload)
TO 'direct_kms.parquet' (
  FORMAT encrypted_parquet,
  ENCRYPTION_CONFIG {
    footer_key_value: from_base64('MDEyMzQ1Njc4OWFiY2RlZg=='),
    master_key_id: 'kms-master-key-123',
    kms_instance_id: 'production-kms',
    kms_instance_url: 'https://kms.example.invalid',
    crypto_factory_class: 'com.company.DirectKmsCryptoFactory',
    kms_client_class: 'com.company.DirectKmsClient'
  }
);
```

解码后 16、24、32 字节分别对应 AES-128、AES-192、AES-256。这样可以避免继承自原有 Key 接口的 raw string / Base64 歧义：16 字节 AES-128 Key 编码成 Base64 后是 24 个字符，而 24 字符本身又刚好可能被当作 raw AES-192 Key。

`master_key_id` 以及其他 Direct-KMS 字段都只是元数据。现有 `add_encrypted_parquet_key` + `footer_key: 'alias'` 仍作为兼容路径保留。

Direct-KMS 元数据绑定到当前这一次 `COPY`。同时保留旧的 PRAGMA-based Direct-KMS fallback，但它是 database-scoped，不适合要求并发 COPY 配置隔离的场景。

## 验证状态

PR #3 的二进制 Direct-KMS Key 路径已经在 CI 之外实际使用并验证。CI 同时覆盖 Linux/Windows 下的 AES-128 Base64、AES-128 Hex、AES-256 Base64、旧 key alias 路径，以及 COPY-local 元数据隔离。

## 升级说明

生成器通过匹配 DuckDB 源码中的预期文本进行 patch。这是有意设计：DuckDB 上游源码发生变化时，生成过程会直接失败，而不是静默生成只 patch 一半的扩展。升级 DuckDB 版本时，应运行 CI，并逐项检查所有失效的 patch anchor。

仓库里的示例 Key、KMS ID、类名和 URL 都只是占位内容，不应直接用于生产环境。
