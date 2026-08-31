#!/usr/bin/env python3
from pathlib import Path
import shutil, sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
SRC = ROOT / 'extension' / 'parquet'
DST = ROOT / 'extension' / 'encrypted_parquet'
if not SRC.exists():
    raise SystemExit(f'not a DuckDB source tree: {SRC} missing')
if DST.exists():
    shutil.rmtree(DST)
shutil.copytree(SRC, DST)


def rep(rel, old, new, count=1):
    p = DST / rel
    s = p.read_text(encoding='utf-8')
    actual = s.count(old)
    if actual != count:
        raise RuntimeError(f'{rel}: expected {count} occurrence(s), found {actual}: {old[:120]!r}')
    p.write_text(s.replace(old, new), encoding='utf-8')

# ---- CMake: build as a distinct loadable extension ----
rep('CMakeLists.txt', 'project(ParquetExtension)', 'project(EncryptedParquetExtension)')
rep('CMakeLists.txt', 'build_static_extension(parquet ${PARQUET_EXTENSION_FILES})',
    'build_static_extension(encrypted_parquet ${PARQUET_EXTENSION_FILES})')
rep('CMakeLists.txt', 'build_loadable_extension(parquet ${PARAMETERS} ${PARQUET_EXTENSION_FILES})',
    'build_loadable_extension(encrypted_parquet ${PARAMETERS} ${PARQUET_EXTENSION_FILES})')
rep('CMakeLists.txt', 'target_link_libraries(parquet_loadable_extension duckdb_mbedtls duckdb_zstd)',
    'target_link_libraries(encrypted_parquet_loadable_extension duckdb_mbedtls duckdb_zstd)')
rep('CMakeLists.txt', 'TARGETS parquet_extension', 'TARGETS encrypted_parquet_extension')

# The copied Parquet subdirectories define object-library targets. Give them
# distinct names so the built-in parquet extension can be enabled alongside us.
# 复制的 Parquet 子目录定义对象库目标；使用不同名称以便与内置 parquet 扩展同时启用。
for rel in (
    'decoder/CMakeLists.txt',
    'reader/CMakeLists.txt',
    'reader/variant/CMakeLists.txt',
    'writer/CMakeLists.txt',
    'writer/variant/CMakeLists.txt',
):
    p = DST / rel
    s = p.read_text(encoding='utf-8')
    if 'duckdb_parquet_' not in s:
        raise RuntimeError(f'{rel}: expected a Parquet object-library target')
    p.write_text(s.replace('duckdb_parquet_', 'duckdb_encrypted_parquet_'), encoding='utf-8')

# ---- Crypto API: writer accepts module AAD, mirroring the existing reader ----
rep('include/parquet_crypto.hpp',
'''\tstatic uint32_t Write(const TBase &object, TProtocol &oprot, const string &key,\n\t                      const EncryptionUtil &encryption_util_p);''',
'''\tstatic uint32_t Write(const TBase &object, TProtocol &oprot, const string &key,\n\t                      const EncryptionUtil &encryption_util_p, const CryptoMetaData &crypto_meta_data);''')
rep('include/parquet_crypto.hpp',
'''\tstatic uint32_t WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,\n\t                          const string &key, const EncryptionUtil &encryption_util_p);''',
'''\tstatic uint32_t WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,\n\t                          const string &key, const EncryptionUtil &encryption_util_p,\n\t                          const CryptoMetaData &crypto_meta_data);''')
rep('include/parquet_crypto.hpp',
'''\tconst string &GetFooterKey() const;''',
'''\tconst string &GetFooterKey() const;\n\tconst string &GetFooterKeyMetadata() const;''')

rep('parquet_crypto.cpp',
'''\tEncryptionTransport(TProtocol &prot_p, const string &key, const EncryptionUtil &encryption_util_p)\n\t    : prot(prot_p), trans(*prot.getTransport()),\n\t      allocator(Allocator::DefaultAllocator(), ParquetCrypto::CRYPTO_BLOCK_SIZE) {\n\t\tauto metadata = make_uniq<EncryptionStateMetadata>(EncryptionTypes::GCM, key.size(),\n\t\t                                                   EncryptionTypes::EncryptionVersion::NONE);\n\t\taes = encryption_util_p.CreateEncryptionState(std::move(metadata));\n\n\t\tInitialize(key);\n\t}''',
'''\tEncryptionTransport(TProtocol &prot_p, const string &key, const EncryptionUtil &encryption_util_p,\n\t                    const CryptoMetaData &crypto_meta_data)\n\t    : prot(prot_p), trans(*prot.getTransport()),\n\t      allocator(Allocator::DefaultAllocator(), ParquetCrypto::CRYPTO_BLOCK_SIZE) {\n\t\tauto metadata = make_uniq<EncryptionStateMetadata>(EncryptionTypes::GCM, key.size(),\n\t\t                                                   EncryptionTypes::EncryptionVersion::NONE);\n\t\taes = encryption_util_p.CreateEncryptionState(std::move(metadata));\n\n\t\tInitialize(key, crypto_meta_data);\n\t}''')
rep('parquet_crypto.cpp',
'''\tvoid Initialize(const string &key) {\n\t\t// Generate Nonce\n\t\taes->GenerateRandomData(nonce.data(), nonce.size());\n\t\t// Initialize Encryption\n\t\taes->InitializeEncryption(nonce, reinterpret_cast<const_data_ptr_t>(key.data()));\n\t}''',
'''\tvoid Initialize(const string &key, const CryptoMetaData &crypto_meta_data) {\n\t\t// Generate Nonce\n\t\taes->GenerateRandomData(nonce.data(), nonce.size());\n\t\t// Initialize Encryption with the standard Parquet module AAD\n\t\tif (!crypto_meta_data.IsEmpty()) {\n\t\t\taes->InitializeEncryption(nonce, reinterpret_cast<const_data_ptr_t>(key.data()),\n\t\t\t                          crypto_meta_data.additional_authenticated_data->data(),\n\t\t\t                          crypto_meta_data.additional_authenticated_data->size());\n\t\t\tcrypto_meta_data.additional_authenticated_data->Rewind();\n\t\t} else {\n\t\t\taes->InitializeEncryption(nonce, reinterpret_cast<const_data_ptr_t>(key.data()));\n\t\t}\n\t}''')
rep('parquet_crypto.cpp',
'''uint32_t ParquetCrypto::Write(const TBase &object, TProtocol &oprot, const string &key,\n                              const EncryptionUtil &encryption_util_p) {\n\t// Create encryption protocol\n\tTCompactProtocolFactoryT<EncryptionTransport> tproto_factory;\n\tauto eprot =\n\t    tproto_factory.getProtocol(duckdb_base_std::make_shared<EncryptionTransport>(oprot, key, encryption_util_p));''',
'''uint32_t ParquetCrypto::Write(const TBase &object, TProtocol &oprot, const string &key,\n                              const EncryptionUtil &encryption_util_p, const CryptoMetaData &crypto_meta_data) {\n\t// Create encryption protocol\n\tTCompactProtocolFactoryT<EncryptionTransport> tproto_factory;\n\tauto eprot = tproto_factory.getProtocol(\n\t    duckdb_base_std::make_shared<EncryptionTransport>(oprot, key, encryption_util_p, crypto_meta_data));''')
rep('parquet_crypto.cpp',
'''uint32_t ParquetCrypto::WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,\n                                  const string &key, const EncryptionUtil &encryption_util_p) {\n\t// FIXME: we know the size upfront so we could do a streaming write instead of this\n\t// Create encryption protocol\n\tTCompactProtocolFactoryT<EncryptionTransport> tproto_factory;\n\tauto eprot =\n\t    tproto_factory.getProtocol(duckdb_base_std::make_shared<EncryptionTransport>(oprot, key, encryption_util_p));''',
'''uint32_t ParquetCrypto::WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,\n                                  const string &key, const EncryptionUtil &encryption_util_p,\n                                  const CryptoMetaData &crypto_meta_data) {\n\t// FIXME: we know the size upfront so we could do a streaming write instead of this\n\t// Create encryption protocol\n\tTCompactProtocolFactoryT<EncryptionTransport> tproto_factory;\n\tauto eprot = tproto_factory.getProtocol(\n\t    duckdb_base_std::make_shared<EncryptionTransport>(oprot, key, encryption_util_p, crypto_meta_data));''')
# Keep the key name as standard key metadata. Reuse serialized column_keys storage to avoid changing generated serializer code.
rep('parquet_crypto.cpp',
'''\t\t\tconst auto &keys = ParquetKeys::Get(context);\n\t\t\tfooter_key = keys.GetKey(footer_key_name);''',
'''\t\t\tconst auto &keys = ParquetKeys::Get(context);\n\t\t\tfooter_key = keys.GetKey(footer_key_name);\n\t\t\tcolumn_keys["__encrypted_parquet_footer_key_metadata"] = footer_key_name;''')
rep('parquet_crypto.cpp',
'''const string &ParquetEncryptionConfig::GetFooterKey() const {\n\treturn footer_key;\n}''',
'''const string &ParquetEncryptionConfig::GetFooterKey() const {\n\treturn footer_key;\n}\n\nconst string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {\n\tstatic const string empty;\n\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");\n\treturn entry == column_keys.end() ? empty : entry->second;\n}''')
# Keep a separate key namespace from the built-in parquet extension.
rep('parquet_crypto.cpp', 'return "parquet_keys";', 'return "encrypted_parquet_keys";')

# ---- Writer: per-file AAD, module AAD, correct footer metadata and page sizes ----
rep('include/parquet_writer.hpp',
'''\tuint32_t Write(const duckdb_apache::thrift::TBase &object);\n\tuint32_t WriteData(const const_data_ptr_t buffer, const uint32_t buffer_size);''',
'''\tuint32_t Write(const duckdb_apache::thrift::TBase &object, int8_t module = -1,\n\t               int16_t row_group_ordinal = -1, int16_t column_ordinal = -1, int16_t page_ordinal = -1);\n\tuint32_t WriteData(const const_data_ptr_t buffer, const uint32_t buffer_size, int8_t module = -1,\n\t                   int16_t row_group_ordinal = -1, int16_t column_ordinal = -1, int16_t page_ordinal = -1);\n\tbool IsEncrypted() const {\n\t\treturn encryption_config != nullptr;\n\t}''')
rep('include/parquet_writer.hpp',
'''\tshared_ptr<EncryptionUtil> encryption_util;\n\tParquetVersion parquet_version;''',
'''\tshared_ptr<EncryptionUtil> encryption_util;\n\t//! 8-byte unique file identifier used by the Parquet Modular Encryption AAD suffix\n\tstring file_aad;\n\tParquetVersion parquet_version;''')

rep('parquet_writer.cpp',
'''uint32_t ParquetWriter::Write(const duckdb_apache::thrift::TBase &object) {\n\tif (encryption_config) {\n\t\treturn ParquetCrypto::Write(object, *protocol, encryption_config->GetFooterKey(), *encryption_util);\n\t} else {\n\t\treturn object.write(protocol.get());\n\t}\n}\n\nuint32_t ParquetWriter::WriteData(const const_data_ptr_t buffer, const uint32_t buffer_size) {\n\tif (encryption_config) {\n\t\treturn ParquetCrypto::WriteData(*protocol, buffer, buffer_size, encryption_config->GetFooterKey(),\n\t\t                                *encryption_util);\n\t} else {\n\t\tprotocol->getTransport()->write(buffer, buffer_size);\n\t\treturn buffer_size;\n\t}\n}''',
'''uint32_t ParquetWriter::Write(const duckdb_apache::thrift::TBase &object, int8_t module,\n                              int16_t row_group_ordinal, int16_t column_ordinal, int16_t page_ordinal) {\n\tif (encryption_config) {\n\t\tCryptoMetaData crypto_metadata(Allocator::DefaultAllocator());\n\t\tcrypto_metadata.Initialize(file_aad, row_group_ordinal, column_ordinal, module, page_ordinal);\n\t\tParquetCrypto::GenerateAdditionalAuthenticatedData(Allocator::DefaultAllocator(), crypto_metadata);\n\t\treturn ParquetCrypto::Write(object, *protocol, encryption_config->GetFooterKey(), *encryption_util,\n\t\t                            crypto_metadata);\n\t}\n\treturn object.write(protocol.get());\n}\n\nuint32_t ParquetWriter::WriteData(const const_data_ptr_t buffer, const uint32_t buffer_size, int8_t module,\n                                  int16_t row_group_ordinal, int16_t column_ordinal, int16_t page_ordinal) {\n\tif (encryption_config) {\n\t\tCryptoMetaData crypto_metadata(Allocator::DefaultAllocator());\n\t\tcrypto_metadata.Initialize(file_aad, row_group_ordinal, column_ordinal, module, page_ordinal);\n\t\tParquetCrypto::GenerateAdditionalAuthenticatedData(Allocator::DefaultAllocator(), crypto_metadata);\n\t\treturn ParquetCrypto::WriteData(*protocol, buffer, buffer_size, encryption_config->GetFooterKey(),\n\t\t                                *encryption_util, crypto_metadata);\n\t}\n\tprotocol->getTransport()->write(buffer, buffer_size);\n\treturn buffer_size;\n}''')

rep('parquet_writer.cpp',
'''\tif (encryption_config) {\n\t\t// Get the encryption util\n\t\tencryption_util = context.db->GetEncryptionUtil(false);\n\t\t// encrypted parquet files start with the string "PARE"\n\t\twriter->WriteData(const_data_ptr_cast("PARE"), 4);\n\t\t// we only support this one for now, not "AES_GCM_CTR_V1"\n\t\tfile_meta_data.encryption_algorithm.__isset.AES_GCM_V1 = true;\n\t} else {''',
'''\tif (encryption_config) {\n\t\t// Get the encryption util and generate the per-file unique AAD component.\n\t\tencryption_util = context.db->GetEncryptionUtil(false);\n\t\tauto random_metadata = make_uniq<EncryptionStateMetadata>(\n\t\t    EncryptionTypes::GCM, encryption_config->GetFooterKey().size(), EncryptionTypes::EncryptionVersion::NONE);\n\t\tauto random_state = encryption_util->CreateEncryptionState(std::move(random_metadata));\n\t\tfile_aad.resize(ParquetCrypto::UNIQUE_FILE_ID_LEN);\n\t\trandom_state->GenerateRandomData(reinterpret_cast<data_ptr_t>(&file_aad[0]), file_aad.size());\n\t\t// encrypted parquet files start with the string "PARE"\n\t\twriter->WriteData(const_data_ptr_cast("PARE"), 4);\n\t\t// IMPORTANT: encryption_algorithm belongs in FileCryptoMetaData for encrypted-footer files.\n\t} else {''')

rep('parquet_writer.cpp',
'''\trow_group.file_offset = NumericCast<int64_t>(writer->GetTotalWritten());\n\tfor (idx_t col_idx = 0; col_idx < states.size(); col_idx++) {''',
'''\tif (encryption_config) {\n\t\tconst auto row_group_ordinal = file_meta_data.row_groups.size();\n\t\tif (row_group_ordinal > std::numeric_limits<int16_t>::max()) {\n\t\t\tthrow InvalidInputException("RowGroup ordinal exceeds 32767 when encryption enabled");\n\t\t}\n\t\t// AAD for pages needs the row-group ordinal before any column/page is written.\n\t\trow_group.ordinal = NumericCast<int16_t>(row_group_ordinal);\n\t\trow_group.__isset.ordinal = true;\n\t}\n\n\trow_group.file_offset = NumericCast<int64_t>(writer->GetTotalWritten());\n\tfor (idx_t col_idx = 0; col_idx < states.size(); col_idx++) {''')
rep('parquet_writer.cpp',
'''\n\tif (encryption_config) {\n\t\tconst auto row_group_ordinal = file_meta_data.row_groups.size();\n\t\tif (row_group_ordinal > std::numeric_limits<int16_t>::max()) {\n\t\t\tthrow InvalidInputException("RowGroup ordinal exceeds 32767 when encryption enabled");\n\t\t}\n\t\trow_group.ordinal = NumericCast<int16_t>(row_group_ordinal);\n\t\trow_group.__isset.ordinal = true;\n\t}\n\n\t// append the row group to the file metadata''',
'''\n\t// append the row group to the file metadata''')

rep('parquet_writer.cpp',
'''\t\tduckdb_parquet::AesGcmV1 aes_gcm_v1;\n\t\tduckdb_parquet::EncryptionAlgorithm alg;\n\t\talg.__set_AES_GCM_V1(aes_gcm_v1);\n\t\tcrypto_metadata.__set_encryption_algorithm(alg);\n\t\tcrypto_metadata.write(protocol.get());''',
'''\t\tduckdb_parquet::AesGcmV1 aes_gcm_v1;\n\t\taes_gcm_v1.__set_aad_file_unique(file_aad);\n\t\tduckdb_parquet::EncryptionAlgorithm alg;\n\t\talg.__set_AES_GCM_V1(aes_gcm_v1);\n\t\tcrypto_metadata.__set_encryption_algorithm(alg);\n\t\tif (!encryption_config->GetFooterKeyMetadata().empty()) {\n\t\t\tcrypto_metadata.__set_key_metadata(encryption_config->GetFooterKeyMetadata());\n\t\t}\n\t\tcrypto_metadata.write(protocol.get());''')
rep('parquet_writer.cpp', '\tWrite(file_meta_data);',
'''\tif (encryption_config) {\n\t\tWrite(file_meta_data, ParquetCrypto::FOOTER);\n\t} else {\n\t\tWrite(file_meta_data);\n\t}''')

# ---- Column/page crypto metadata and AAD ----
rep('writer/primitive_column_writer.cpp',
'''\tcolumn_chunk.meta_data.type = writer.GetType(SchemaIndex());\n\trow_group.columns.push_back(std::move(column_chunk));''',
'''\tcolumn_chunk.meta_data.type = writer.GetType(SchemaIndex());\n\tif (writer.IsEncrypted()) {\n\t\tduckdb_parquet::ColumnCryptoMetaData crypto_metadata;\n\t\tcrypto_metadata.__set_ENCRYPTION_WITH_FOOTER_KEY(duckdb_parquet::EncryptionWithFooterKey());\n\t\tcolumn_chunk.__set_crypto_metadata(crypto_metadata);\n\t}\n\trow_group.columns.push_back(std::move(column_chunk));''')

rep('writer/primitive_column_writer.cpp',
'''\t// write the individual pages to disk\n\tidx_t total_uncompressed_size = 0;\n\tfor (auto &write_info : state.write_info) {\n\t\t// set the data page offset whenever we see the *first* data page\n\t\tif (column_chunk.meta_data.data_page_offset == 0 && (write_info.page_header.type == PageType::DATA_PAGE ||\n\t\t                                                     write_info.page_header.type == PageType::DATA_PAGE_V2)) {\n\t\t\tcolumn_chunk.meta_data.data_page_offset = UnsafeNumericCast<int64_t>(column_writer.GetTotalWritten());\n\t\t}\n\t\tD_ASSERT(write_info.page_header.uncompressed_page_size > 0);\n\t\tauto header_start_offset = column_writer.GetTotalWritten();\n\t\twriter.Write(write_info.page_header);\n\t\t// total uncompressed size in the column chunk includes the header size (!)\n\t\ttotal_uncompressed_size += column_writer.GetTotalWritten() - header_start_offset;\n\t\ttotal_uncompressed_size += write_info.page_header.uncompressed_page_size;\n\t\twriter.WriteData(write_info.compressed_data, write_info.compressed_size);\n\t}''',
'''\t// write the individual pages to disk\n\tidx_t total_uncompressed_size = 0;\n\tint16_t data_page_ordinal = 0;\n\tfor (auto &write_info : state.write_info) {\n\t\t// set the data page offset whenever we see the *first* data page\n\t\tif (column_chunk.meta_data.data_page_offset == 0 && (write_info.page_header.type == PageType::DATA_PAGE ||\n\t\t                                                     write_info.page_header.type == PageType::DATA_PAGE_V2)) {\n\t\t\tcolumn_chunk.meta_data.data_page_offset = UnsafeNumericCast<int64_t>(column_writer.GetTotalWritten());\n\t\t}\n\t\tD_ASSERT(write_info.page_header.uncompressed_page_size > 0);\n\n\t\tint8_t header_module = -1;\n\t\tint8_t data_module = -1;\n\t\tint16_t module_page_ordinal = -1;\n\t\tint16_t row_group_ordinal = -1;\n\t\tint16_t column_ordinal = -1;\n\t\tif (writer.IsEncrypted()) {\n\t\t\tif (!state.row_group.__isset.ordinal || state.col_idx > std::numeric_limits<int16_t>::max()) {\n\t\t\t\tthrow InvalidInputException("Invalid Parquet encryption row-group/column ordinal");\n\t\t\t}\n\t\t\trow_group_ordinal = state.row_group.ordinal;\n\t\t\tcolumn_ordinal = NumericCast<int16_t>(state.col_idx);\n\n\t\t\tswitch (write_info.page_header.type) {\n\t\t\tcase PageType::DICTIONARY_PAGE:\n\t\t\t\theader_module = ParquetCrypto::DICTIONARY_PAGE_HEADER;\n\t\t\t\tdata_module = ParquetCrypto::DICTIONARY_PAGE;\n\t\t\t\tbreak;\n\t\t\tcase PageType::DATA_PAGE:\n\t\t\tcase PageType::DATA_PAGE_V2:\n\t\t\t\theader_module = ParquetCrypto::DATA_PAGE_HEADER;\n\t\t\t\tdata_module = ParquetCrypto::DATA_PAGE;\n\t\t\t\tmodule_page_ordinal = data_page_ordinal++;\n\t\t\t\tbreak;\n\t\t\tdefault:\n\t\t\t\tthrow InternalException("Unsupported encrypted Parquet page type");\n\t\t\t}\n\n\t\t\t// compressed_page_size is the encrypted page module size on disk, including length+nonce+tag.\n\t\t\twrite_info.page_header.compressed_page_size += NumericCast<int32_t>(\n\t\t\t    ParquetCrypto::LENGTH_BYTES + ParquetCrypto::NONCE_BYTES + ParquetCrypto::TAG_BYTES);\n\t\t}\n\n\t\tauto header_start_offset = column_writer.GetTotalWritten();\n\t\twriter.Write(write_info.page_header, header_module, row_group_ordinal, column_ordinal, module_page_ordinal);\n\t\t// total uncompressed size in the column chunk includes the header size (!)\n\t\ttotal_uncompressed_size += column_writer.GetTotalWritten() - header_start_offset;\n\t\ttotal_uncompressed_size += write_info.page_header.uncompressed_page_size;\n\t\twriter.WriteData(write_info.compressed_data, write_info.compressed_size, data_module, row_group_ordinal,\n\t\t                 column_ordinal, module_page_ordinal);\n\t}''')

# Need parquet_crypto symbols in this source.
rep('writer/primitive_column_writer.cpp', '#include "parquet_writer.hpp"',
    '#include "parquet_writer.hpp"\n#include "parquet_crypto.hpp"')

# ---- Registration: writer-only custom COPY format, no conflicts with built-in parquet ----
p = DST / 'parquet_extension.cpp'
s = p.read_text(encoding='utf-8')
start = s.index('static void LoadInternal(ExtensionLoader &loader) {')
end = s.index('\nvoid ParquetExtension::Load(ExtensionLoader &loader) {', start)
minimal = r'''static void LoadInternal(ExtensionLoader &loader) {
	CopyFunction function("encrypted_parquet");
	function.copy_to_select = ParquetWriteSelect;
	function.copy_to_bind = ParquetWriteBind;
	function.copy_options = ParquetListCopyOptions;
	function.copy_to_initialize_global = ParquetWriteInitializeGlobal;
	function.copy_to_initialize_local = ParquetWriteInitializeLocal;
	function.copy_to_get_written_statistics = ParquetWriteGetWrittenStatistics;
	function.copy_to_sink = ParquetWriteSink;
	function.copy_to_combine = ParquetWriteCombine;
	function.copy_to_finalize = ParquetWriteFinalize;
	function.execution_mode = ParquetWriteExecutionMode;
	function.initialize_operator = ParquetWriteInitializeOperator;
	function.prepare_batch = ParquetWritePrepareBatch;
	function.flush_batch = ParquetWriteFlushBatch;
	function.desired_batch_size = ParquetWriteDesiredBatchSize;
	function.rotate_files = ParquetWriteRotateFiles;
	function.rotate_next_file = ParquetWriteRotateNextFile;
	function.serialize = ParquetCopySerialize;
	function.deserialize = ParquetCopyDeserialize;
	function.extension = "encrypted_parquet";
	loader.RegisterFunction(function);

	// Separate namespace from the built-in parquet extension to avoid ObjectCache/pragma collisions.
	auto parquet_key_fun = PragmaFunction::PragmaCall("add_encrypted_parquet_key", ParquetCrypto::AddKey,
	                                                  {LogicalType::VARCHAR, LogicalType::VARCHAR});
	loader.RegisterFunction(parquet_key_fun);
}
'''
s = s[:start] + minimal + s[end:]
s = s.replace('return "parquet";', 'return "encrypted_parquet";', 1)
s = s.replace('DUCKDB_CPP_EXTENSION_ENTRY(parquet, loader)', 'DUCKDB_CPP_EXTENSION_ENTRY(encrypted_parquet, loader)', 1)
p.write_text(s, encoding='utf-8')

# Build config consumed by DuckDB root CMake.
config = ROOT / 'extension' / 'extension_config_encrypted_parquet.cmake'
config.write_text('''duckdb_extension_load(encrypted_parquet\n    DONT_LINK\n    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/encrypted_parquet\n)\n''', encoding='utf-8')

print(DST)
print(config)


# ===========================================================================
# Additive parquet-java / Spark Hadoop Configuration compatibility layer.
# The validated base generator above is intentionally left unchanged.
# ===========================================================================
# ---------------------------------------------------------------------------
# Hadoop Configuration-like String -> String storage, isolated to this ext.
# ---------------------------------------------------------------------------
rep('include/parquet_crypto.hpp',
'''class ParquetEncryptionConfig {''',
'''class EncryptedParquetConfiguration : public ObjectCacheEntry {
public:
\tstatic EncryptedParquetConfiguration &Get(ClientContext &context);
\tvoid Set(const string &name, const string &value);
\tvoid Unset(const string &name);
\tvoid Clear();
\tbool Has(const string &name) const;
\tstring GetValue(const string &name) const;

\tstatic string ObjectType();
\tstring GetObjectType() override;
\toptional_idx GetEstimatedCacheMemory() const override {
\t\treturn optional_idx {};
\t}

private:
\tunordered_map<string, string> properties;
};

class ParquetEncryptionConfig {''')

rep('include/parquet_crypto.hpp',
'''\tstatic shared_ptr<ParquetEncryptionConfig> Create(ClientContext &context, const Value &arg);
\tconst string &GetFooterKey() const;
\tconst string &GetFooterKeyMetadata() const;''',
'''\tstatic shared_ptr<ParquetEncryptionConfig> Create(ClientContext &context, const Value &arg);
\t//! Creates parquet-java PropertiesDrivenCryptoFactory compatible uniform encryption.
\t//! Returns nullptr when no Hadoop-style encryption properties are configured.
\tstatic shared_ptr<ParquetEncryptionConfig> CreateFromHadoopConfiguration(ClientContext &context);
\tconst string &GetFooterKey() const;
\tconst string &GetFooterKeyMetadata() const;''')

rep('include/parquet_crypto.hpp',
'''\tstatic void AddKey(ClientContext &context, const FunctionParameters &parameters);
\tstatic bool ValidKey(const std::string &key);''',
'''\tstatic void AddKey(ClientContext &context, const FunctionParameters &parameters);
\tstatic void SetConfig(ClientContext &context, const FunctionParameters &parameters);
\tstatic void UnsetConfig(ClientContext &context, const FunctionParameters &parameters);
\tstatic void ClearConfig(ClientContext &context, const FunctionParameters &parameters);
\tstatic bool ValidKey(const std::string &key);''')

rep('parquet_crypto.cpp', '#include "duckdb/common/allocator.hpp"',
    '#include "duckdb/common/allocator.hpp"\n#include <cctype>\n#include <limits>')

rep('parquet_crypto.cpp',
'''string ParquetKeys::GetObjectType() {
\treturn ObjectType();
}''',
'''string ParquetKeys::GetObjectType() {
\treturn ObjectType();
}

EncryptedParquetConfiguration &EncryptedParquetConfiguration::Get(ClientContext &context) {
\tauto &cache = ObjectCache::GetObjectCache(context);
\treturn *cache.GetOrCreate<EncryptedParquetConfiguration>(EncryptedParquetConfiguration::ObjectType());
}

void EncryptedParquetConfiguration::Set(const string &name, const string &value) {
\tproperties[name] = value;
}

void EncryptedParquetConfiguration::Unset(const string &name) {
\tproperties.erase(name);
}

void EncryptedParquetConfiguration::Clear() {
\tproperties.clear();
}

bool EncryptedParquetConfiguration::Has(const string &name) const {
\treturn properties.find(name) != properties.end();
}

string EncryptedParquetConfiguration::GetValue(const string &name) const {
\tauto entry = properties.find(name);
\treturn entry == properties.end() ? string() : entry->second;
}

string EncryptedParquetConfiguration::ObjectType() {
\treturn "encrypted_parquet_hadoop_configuration";
}

string EncryptedParquetConfiguration::GetObjectType() {
\treturn ObjectType();
}''')

# ---------------------------------------------------------------------------
# parquet-java key-tools compatibility for uniform encryption.
# - PropertiesDrivenCryptoFactory semantics
# - InMemoryKMS key-list semantics
# - PKMT1 internal key material JSON
# - Java AES-GCM wrapped key layout: nonce + ciphertext + tag, Base64
# Existing ENCRYPTION_CONFIG path is not changed.
# ---------------------------------------------------------------------------
rep('parquet_crypto.cpp',
'''const string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {
\tstatic const string empty;
\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");
\treturn entry == column_keys.end() ? empty : entry->second;
}''',
'''const string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {
\tstatic const string empty;
\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");
\treturn entry == column_keys.end() ? empty : entry->second;
}

static string TrimConfigValue(const string &value) {
\tidx_t start = 0;
\tidx_t end = value.size();
\twhile (start < end && std::isspace(static_cast<unsigned char>(value[start]))) {
\t\tstart++;
\t}
\twhile (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
\t\tend--;
\t}
\treturn value.substr(start, end - start);
}

static bool ParseConfigBool(const EncryptedParquetConfiguration &config, const string &name, bool default_value) {
\tif (!config.Has(name)) {
\t\treturn default_value;
\t}
\tauto value = StringUtil::Lower(TrimConfigValue(config.GetValue(name)));
\tif (value == "true" || value == "1") {
\t\treturn true;
\t}
\tif (value == "false" || value == "0") {
\t\treturn false;
\t}
\tthrow InvalidInputException("Invalid boolean value for %s: %s", name, config.GetValue(name));
}

static int ParseConfigKeyLength(const EncryptedParquetConfiguration &config, const string &name, int default_bits) {
\tif (!config.Has(name)) {
\t\treturn default_bits;
\t}
\tint bits;
\ttry {
\t\tbits = std::stoi(TrimConfigValue(config.GetValue(name)));
\t} catch (...) {
\t\tthrow InvalidInputException("Invalid integer value for %s: %s", name, config.GetValue(name));
\t}
\tif (bits != 128 && bits != 192 && bits != 256) {
\t\tthrow InvalidInputException("%s must be 128, 192, or 256", name);
\t}
\treturn bits;
}

static string DecodeBase64ConfigKey(const string &encoded) {
\tauto result_size = Blob::FromBase64Size(encoded);
\tstring result(result_size, '\\0');
\tif (result_size > 0) {
\t\tBlob::FromBase64(encoded, reinterpret_cast<data_ptr_t>(&result[0]), result_size);
\t}
\treturn result;
}

static unordered_map<string, string> ParseJavaInMemoryKeyList(const string &key_list) {
\tunordered_map<string, string> result;
\tidx_t start = 0;
\twhile (start <= key_list.size()) {
\t\tauto comma = key_list.find(',', start);
\t\tauto item = TrimConfigValue(key_list.substr(start, comma == string::npos ? string::npos : comma - start));
\t\tif (!item.empty()) {
\t\t\tauto colon = item.find(':');
\t\t\tif (colon == string::npos || item.find(':', colon + 1) != string::npos) {
\t\t\t\tthrow InvalidInputException("Invalid parquet.encryption.key.list entry: %s", item);
\t\t\t}
\t\t\tauto key_name = TrimConfigValue(item.substr(0, colon));
\t\t\tauto encoded_key = TrimConfigValue(item.substr(colon + 1));
\t\t\tif (key_name.empty() || encoded_key.empty()) {
\t\t\t\tthrow InvalidInputException("Invalid parquet.encryption.key.list entry: %s", item);
\t\t\t}
\t\t\tstring key;
\t\t\ttry {
\t\t\t\tkey = DecodeBase64ConfigKey(encoded_key);
\t\t\t} catch (const Exception &) {
\t\t\t\tthrow InvalidInputException("Could not decode master key '%s' from parquet.encryption.key.list", key_name);
\t\t\t}
\t\t\tif (!ParquetCrypto::ValidKey(key)) {
\t\t\t\tthrow InvalidInputException("Master key '%s' must be 128, 192, or 256 bits", key_name);
\t\t\t}
\t\t\tresult[key_name] = std::move(key);
\t\t}
\t\tif (comma == string::npos) {
\t\t\tbreak;
\t\t}
\t\tstart = comma + 1;
\t}
\treturn result;
}

static string GenerateCryptoRandom(ClientContext &context, idx_t length) {
\tauto encryption_util = context.db->GetEncryptionUtil(false);
\tauto metadata = make_uniq<EncryptionStateMetadata>(EncryptionTypes::GCM, 16,
\t                                                  EncryptionTypes::EncryptionVersion::NONE);
\tauto state = encryption_util->CreateEncryptionState(std::move(metadata));
\tstring result(length, '\\0');
\tif (length > 0) {
\t\tstate->GenerateRandomData(reinterpret_cast<data_ptr_t>(&result[0]), result.size());
\t}
\treturn result;
}

// Same byte layout as parquet-java KeyToolkit.encryptKeyLocally(false):
// nonce(12) + ciphertext + GCM tag(16), then standard Base64.
static string JavaEncryptKeyLocally(ClientContext &context, const string &plain_key, const string &wrapping_key,
                                    const string &aad) {
\tauto encryption_util = context.db->GetEncryptionUtil(false);
\tauto metadata = make_uniq<EncryptionStateMetadata>(EncryptionTypes::GCM, wrapping_key.size(),
\t                                                  EncryptionTypes::EncryptionVersion::NONE);
\tauto aes = encryption_util->CreateEncryptionState(std::move(metadata));
\tEncryptionNonce nonce;
\taes->GenerateRandomData(nonce.data(), nonce.size());
\taes->InitializeEncryption(nonce, reinterpret_cast<const_data_ptr_t>(wrapping_key.data()),
\t                          reinterpret_cast<const_data_ptr_t>(aad.data()), aad.size());

\tstring encrypted(ParquetCrypto::NONCE_BYTES + plain_key.size() + ParquetCrypto::TAG_BYTES, '\\0');
\tmemcpy(&encrypted[0], nonce.data(), ParquetCrypto::NONCE_BYTES);
\tauto out = reinterpret_cast<data_ptr_t>(&encrypted[ParquetCrypto::NONCE_BYTES]);
\tauto written = aes->Process(reinterpret_cast<const_data_ptr_t>(plain_key.data()), plain_key.size(), out,
\t                            plain_key.size());
\tif (written != plain_key.size()) {
\t\tthrow InternalException("Unexpected AES-GCM wrapped-key ciphertext size");
\t}
\tdata_t tag[ParquetCrypto::TAG_BYTES];
\tdata_t final_buffer[ParquetCrypto::BLOCK_SIZE];
\tauto final_written = aes->Finalize(final_buffer, 0, tag, ParquetCrypto::TAG_BYTES);
\tif (final_written != 0) {
\t\tthrow InternalException("Unexpected AES-GCM wrapped-key final block");
\t}
\tmemcpy(&encrypted[ParquetCrypto::NONCE_BYTES + plain_key.size()], tag, ParquetCrypto::TAG_BYTES);
\treturn Blob::ToBase64(string_t(encrypted));
}

static string JsonEscapeConfig(const string &value) {
\tstatic const char *HEX = "0123456789ABCDEF";
\tstring result;
\tfor (auto ch : value) {
\t\tauto c = static_cast<unsigned char>(ch);
\t\tswitch (ch) {
\t\tcase '\\\\': result += "\\\\\\\\"; break;
\t\tcase '"': result += "\\\\\\\""; break;
\t\tcase '\\n': result += "\\\\n"; break;
\t\tcase '\\r': result += "\\\\r"; break;
\t\tcase '\\t': result += "\\\\t"; break;
\t\tdefault:
\t\t\tif (c < 0x20) {
\t\t\t\tresult += "\\\\u00";
\t\t\t\tresult += HEX[(c >> 4) & 0x0F];
\t\t\t\tresult += HEX[c & 0x0F];
\t\t\t} else {
\t\t\t\tresult += ch;
\t\t\t}
\t\t}
\t}
\treturn result;
}

static string JavaInternalFooterKeyMaterial(const string &kms_id, const string &kms_url, const string &master_key_id,
                                            const string &wrapped_dek, bool double_wrapping,
                                            const string &encoded_kek_id, const string &wrapped_kek) {
\tstring json = "{\\\"keyMaterialType\\\":\\\"PKMT1\\\",\\\"internalStorage\\\":true,"
\t              "\\\"isFooterKey\\\":true,\\\"kmsInstanceID\\\":\\\"" + JsonEscapeConfig(kms_id) +
\t              "\\\",\\\"kmsInstanceURL\\\":\\\"" + JsonEscapeConfig(kms_url) +
\t              "\\\",\\\"masterKeyID\\\":\\\"" + JsonEscapeConfig(master_key_id) +
\t              "\\\",\\\"wrappedDEK\\\":\\\"" + JsonEscapeConfig(wrapped_dek) +
\t              "\\\",\\\"doubleWrapping\\\":" + (double_wrapping ? "true" : "false");
\tif (double_wrapping) {
\t\tjson += ",\\\"keyEncryptionKeyID\\\":\\\"" + JsonEscapeConfig(encoded_kek_id) +
\t\t        "\\\",\\\"wrappedKEK\\\":\\\"" + JsonEscapeConfig(wrapped_kek) + "\\\"";
\t}
\tjson += "}";
\treturn json;
}

shared_ptr<ParquetEncryptionConfig> ParquetEncryptionConfig::CreateFromHadoopConfiguration(ClientContext &context) {
\tauto &config = EncryptedParquetConfiguration::Get(context);
\tconst auto uniform_key_id = TrimConfigValue(config.GetValue("parquet.encryption.uniform.key"));
\tconst auto footer_key_id = TrimConfigValue(config.GetValue("parquet.encryption.footer.key"));
\tconst auto column_keys_config = TrimConfigValue(config.GetValue("parquet.encryption.column.keys"));

\tif (uniform_key_id.empty()) {
\t\tif (!footer_key_id.empty() || !column_keys_config.empty()) {
\t\t\tthrow NotImplementedException(
\t\t\t    "Hadoop-style encrypted_parquet currently supports parquet.encryption.uniform.key only; "
\t\t\t    "column-specific encryption is intentionally not changed");
\t\t}
\t\treturn nullptr;
\t}
\tif (!footer_key_id.empty() || !column_keys_config.empty()) {
\t\tthrow InvalidInputException(
\t\t    "Uniform encryption cannot be combined with parquet.encryption.footer.key or parquet.encryption.column.keys");
\t}
\tif (ParseConfigBool(config, "parquet.encryption.complete.columns", false)) {
\t\tthrow InvalidInputException("parquet.encryption.complete.columns cannot be used with uniform encryption");
\t}

\tconst auto factory = TrimConfigValue(config.GetValue("parquet.crypto.factory.class"));
\tif (!factory.empty() && factory != "org.apache.parquet.crypto.keytools.PropertiesDrivenCryptoFactory") {
\t\tthrow NotImplementedException("Unsupported parquet.crypto.factory.class: %s", factory);
\t}
\tconst auto kms_class = TrimConfigValue(config.GetValue("parquet.encryption.kms.client.class"));
\tif (!kms_class.empty() && kms_class != "org.apache.parquet.crypto.keytools.mocks.InMemoryKMS") {
\t\tthrow NotImplementedException(
\t\t    "Hadoop-style wrapping currently implements parquet-java InMemoryKMS semantics only: %s", kms_class);
\t}

\tconst auto algorithm = TrimConfigValue(config.GetValue("parquet.encryption.algorithm"));
\tif (!algorithm.empty() && algorithm != "AES_GCM_V1") {
\t\tthrow NotImplementedException("Only parquet.encryption.algorithm=AES_GCM_V1 is supported");
\t}
\tif (ParseConfigBool(config, "parquet.encryption.plaintext.footer", false)) {
\t\tthrow NotImplementedException("parquet.encryption.plaintext.footer=true is not supported");
\t}
\tif (!ParseConfigBool(config, "parquet.encryption.key.material.store.internally", true)) {
\t\tthrow NotImplementedException("External Parquet key material storage is not supported");
\t}

\tconst auto key_list = config.GetValue("parquet.encryption.key.list");
\tif (TrimConfigValue(key_list).empty()) {
\t\tthrow InvalidInputException("No encryption key list in parquet.encryption.key.list");
\t}
\tauto master_keys = ParseJavaInMemoryKeyList(key_list);
\tauto master_key_entry = master_keys.find(uniform_key_id);
\tif (master_key_entry == master_keys.end()) {
\t\tthrow InvalidInputException("Key not found in parquet.encryption.key.list: %s", uniform_key_id);
\t}

\tconst auto dek_length = ParseConfigKeyLength(config, "parquet.encryption.data.key.length.bits", 128) / 8;
\tconst auto kek_length = ParseConfigKeyLength(config, "parquet.encryption.kek.length.bits", 128) / 8;
\tconst bool double_wrapping = ParseConfigBool(config, "parquet.encryption.double.wrapping", true);
\tconst auto kms_id = config.Has("parquet.encryption.kms.instance.id")
\t                        ? TrimConfigValue(config.GetValue("parquet.encryption.kms.instance.id"))
\t                        : string("DEFAULT");
\tconst auto kms_url = config.Has("parquet.encryption.kms.instance.url")
\t                         ? TrimConfigValue(config.GetValue("parquet.encryption.kms.instance.url"))
\t                         : string("DEFAULT");

\t// parquet-java creates a fresh random DEK for every file.
\tauto dek = GenerateCryptoRandom(context, dek_length);
\tstring wrapped_dek;
\tstring encoded_kek_id;
\tstring wrapped_kek;
\tif (double_wrapping) {
\t\tauto kek = GenerateCryptoRandom(context, kek_length);
\t\tauto kek_id = GenerateCryptoRandom(context, 16); // FileKeyWrapper.KEK_ID_LENGTH
\t\twrapped_kek = JavaEncryptKeyLocally(context, kek, master_key_entry->second, uniform_key_id);
\t\twrapped_dek = JavaEncryptKeyLocally(context, dek, kek, kek_id);
\t\tencoded_kek_id = Blob::ToBase64(string_t(kek_id));
\t} else {
\t\twrapped_dek = JavaEncryptKeyLocally(context, dek, master_key_entry->second, uniform_key_id);
\t}

\tauto result = shared_ptr<ParquetEncryptionConfig>(new ParquetEncryptionConfig(std::move(dek)));
\tresult->column_keys["__encrypted_parquet_footer_key_metadata"] = JavaInternalFooterKeyMaterial(
\t    kms_id.empty() ? "DEFAULT" : kms_id, kms_url.empty() ? "DEFAULT" : kms_url, uniform_key_id, wrapped_dek,
\t    double_wrapping, encoded_kek_id, wrapped_kek);
\treturn result;
}''')

# Configuration mutators. No reads/writes are redirected through the built-in parquet extension.
rep('parquet_crypto.cpp',
'''\t\tkeys.AddKey(key_name, decoded_key);
\t}
}

CryptoMetaData::CryptoMetaData(Allocator &allocator) {''',
'''\t\tkeys.AddKey(key_name, decoded_key);
\t}
}

void ParquetCrypto::SetConfig(ClientContext &context, const FunctionParameters &parameters) {
\tconst auto &name = StringValue::Get(parameters.values[0]);
\tconst auto &value = StringValue::Get(parameters.values[1]);
\tEncryptedParquetConfiguration::Get(context).Set(name, value);
}

void ParquetCrypto::UnsetConfig(ClientContext &context, const FunctionParameters &parameters) {
\tconst auto &name = StringValue::Get(parameters.values[0]);
\tEncryptedParquetConfiguration::Get(context).Unset(name);
}

void ParquetCrypto::ClearConfig(ClientContext &context, const FunctionParameters &parameters) {
\tEncryptedParquetConfiguration::Get(context).Clear();
}

CryptoMetaData::CryptoMetaData(Allocator &allocator) {''')

# Resolve config at writer creation, not bind time: rotated/multiple files get a fresh Java-style DEK.
# Existing explicit COPY ENCRYPTION_CONFIG has priority and is therefore behavior-preserving.
rep('parquet_extension.cpp',
'''\tauto &fs = FileSystem::GetFileSystem(context);
\tglobal_state->writer = make_uniq<ParquetWriter>(
\t    context, fs, file_path, parquet_bind.sql_types, parquet_bind.column_names, parquet_bind.codec,
\t    parquet_bind.field_ids.Copy(), parquet_bind.shredding_types.Copy(), parquet_bind.kv_metadata,
\t    parquet_bind.encryption_config, parquet_bind.dictionary_size_limit,''',
'''\tauto &fs = FileSystem::GetFileSystem(context);
\tauto encryption_config = parquet_bind.encryption_config;
\tif (!encryption_config) {
\t\tencryption_config = ParquetEncryptionConfig::CreateFromHadoopConfiguration(context);
\t}
\tglobal_state->writer = make_uniq<ParquetWriter>(
\t    context, fs, file_path, parquet_bind.sql_types, parquet_bind.column_names, parquet_bind.codec,
\t    parquet_bind.field_ids.Copy(), parquet_bind.shredding_types.Copy(), parquet_bind.kv_metadata,
\t    encryption_config, parquet_bind.dictionary_size_limit,''')

# Add isolated SQL API without removing add_encrypted_parquet_key.
p = DST / 'parquet_extension.cpp'
s = p.read_text(encoding='utf-8')
old = '''\tloader.RegisterFunction(parquet_key_fun);
}'''
new = '''\tloader.RegisterFunction(parquet_key_fun);

\t// Hadoop Configuration-style String -> String properties for this extension only.
\tauto set_config_fun = PragmaFunction::PragmaCall("set_encrypted_parquet_config", ParquetCrypto::SetConfig,
\t                                                {LogicalType::VARCHAR, LogicalType::VARCHAR});
\tloader.RegisterFunction(set_config_fun);
\tauto unset_config_fun = PragmaFunction::PragmaCall("unset_encrypted_parquet_config", ParquetCrypto::UnsetConfig,
\t                                                  {LogicalType::VARCHAR});
\tloader.RegisterFunction(unset_config_fun);
\tauto clear_config_fun =
\t    PragmaFunction::PragmaCall("clear_encrypted_parquet_config", ParquetCrypto::ClearConfig, {});
\tloader.RegisterFunction(clear_config_fun);
}'''
if s.count(old) != 1:
    raise RuntimeError('parquet_extension.cpp: registration anchor not found exactly once')
p.write_text(s.replace(old, new), encoding='utf-8')

# DuckDB v1.5.5 includes io.h but not unistd.h in the Windows linenoise path.
# MinGW declares getpid in unistd.h, so include it only in that conditional branch.
p = ROOT / 'tools' / 'shell' / 'linenoise' / 'linenoise.cpp'
s = p.read_text(encoding='utf-8')
old = '#include <io.h>\n'
if s.count(old) != 1:
    raise RuntimeError('linenoise.cpp: MinGW getpid include anchor not found exactly once')
p.write_text(s.replace(old, old + '#include <unistd.h>\n'), encoding='utf-8')

print('Java-compatible Hadoop Configuration layer applied:', DST)

