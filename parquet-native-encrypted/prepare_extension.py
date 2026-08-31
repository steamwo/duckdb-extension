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
