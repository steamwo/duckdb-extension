#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
HERE = Path(__file__).resolve().parent
BASE = HERE / 'prepare_extension_java_compat_final.py'

if not BASE.exists():
    raise SystemExit(f'base generator not found: {BASE}')

subprocess.check_call([sys.executable, str(BASE), str(ROOT)])

# The base generator adds unistd.h after io.h for the MinGW getpid path.
# MSVC does not provide unistd.h, so keep that include MinGW-only.
linenoise = ROOT / 'tools' / 'shell' / 'linenoise' / 'linenoise.cpp'
linenoise_text = linenoise.read_text(encoding='utf-8')
base_include = '#include <io.h>\n#include <unistd.h>\n'
fixed_include = (
    '#include <io.h>\n'
    '#if defined(__MINGW32__) || defined(__MINGW64__)\n'
    '#include <unistd.h>\n'
    '#endif\n'
)
if base_include in linenoise_text:
    linenoise.write_text(linenoise_text.replace(base_include, fixed_include, 1), encoding='utf-8')

DST = ROOT / 'extension' / 'encrypted_parquet'


def rep(rel, old, new, count=1):
    p = DST / rel
    s = p.read_text(encoding='utf-8')
    actual = s.count(old)
    if actual != count:
        raise RuntimeError(f'{rel}: expected {count} occurrence(s), found {actual}: {old[:160]!r}')
    p.write_text(s.replace(old, new), encoding='utf-8')

# DuckDB v1.5.5 does not provide a usable zero-argument PRAGMA_CALL syntax for
# loadable extensions, and PRAGMA_STATEMENT registration is not resolving for
# this loadable extension at runtime. Make clear/reset a real zero-argument
# table function, which DuckDB explicitly supports through CALL.
rep('include/parquet_crypto.hpp',
'''\tstatic void ClearConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic bool ValidKey(const std::string &key);''',
'''\tstatic void ClearConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void ClearConfiguration(ClientContext &context);\n\tstatic bool ValidKey(const std::string &key);''')

rep('parquet_crypto.cpp',
'''void ParquetCrypto::ClearConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tEncryptedParquetConfiguration::Get(context).Clear();\n}''',
'''void ParquetCrypto::ClearConfiguration(ClientContext &context) {\n\tEncryptedParquetConfiguration::Get(context).Clear();\n}\n\nvoid ParquetCrypto::ClearConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tClearConfiguration(context);\n}''')

clear_helpers = r'''class ClearEncryptedParquetConfigBindData : public TableFunctionData {
};

static unique_ptr<FunctionData> ClearEncryptedParquetConfigBind(ClientContext &context, TableFunctionBindInput &input,
                                                                vector<LogicalType> &return_types,
                                                                vector<string> &names) {
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("Success");
	return make_uniq<ClearEncryptedParquetConfigBindData>();
}

static void ClearEncryptedParquetConfigTable(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	ParquetCrypto::ClearConfiguration(context);
	output.SetCardinality(0);
}

static void LoadInternal(ExtensionLoader &loader) {'''
rep('parquet_extension.cpp',
'''static void LoadInternal(ExtensionLoader &loader) {''',
clear_helpers)

rep('parquet_extension.cpp',
'''\tauto clear_config_fun =\n\t    PragmaFunction::PragmaCall("clear_encrypted_parquet_config", ParquetCrypto::ClearConfig, {});\n\tloader.RegisterFunction(clear_config_fun);''',
'''\tauto clear_config_fun =\n\t    TableFunction("clear_encrypted_parquet_config", {}, ClearEncryptedParquetConfigTable,\n\t                  ClearEncryptedParquetConfigBind, nullptr, nullptr);\n\tloader.RegisterFunction(clear_config_fun);''')

# Public API: explicit ENCRYPTION_CONFIG keeps owning the real AES key while
# Hadoop-style properties can attach external/direct-KMS key metadata.
rep('include/parquet_crypto.hpp',
'''\tstatic shared_ptr<ParquetEncryptionConfig> CreateFromHadoopConfiguration(ClientContext &context);\n\tconst string &GetFooterKey() const;\n\tconst string &GetFooterKeyMetadata() const;''',
'''\tstatic shared_ptr<ParquetEncryptionConfig> CreateFromHadoopConfiguration(ClientContext &context);\n\tstatic void ApplyExternalKeyMetadata(ClientContext &context, ParquetEncryptionConfig &encryption_config);\n\tconst string &GetFooterKey() const;\n\tconst string &GetFooterKeyMetadata() const;\n\tvoid SetFooterKeyMetadata(string metadata);''')

rep('parquet_crypto.cpp',
'''const string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {\n\tstatic const string empty;\n\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");\n\treturn entry == column_keys.end() ? empty : entry->second;\n}\n\nstatic string TrimConfigValue(const string &value) {''',
'''const string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {\n\tstatic const string empty;\n\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");\n\treturn entry == column_keys.end() ? empty : entry->second;\n}\n\nvoid ParquetEncryptionConfig::SetFooterKeyMetadata(string metadata) {\n\tcolumn_keys["__encrypted_parquet_footer_key_metadata"] = std::move(metadata);\n}\n\nstatic string TrimConfigValue(const string &value) {''')

# PKMT1 remains the key_metadata payload. Unknown JSON fields are intentionally
# preserved for custom Spark readers; parquet-java's KeyMaterial parser ignores
# fields it does not use.
anchor = '''\tjson += "}";\n\treturn json;\n}\n\nshared_ptr<ParquetEncryptionConfig> ParquetEncryptionConfig::CreateFromHadoopConfiguration(ClientContext &context) {'''
insert = '''\tjson += "}";\n\treturn json;\n}\n\nstatic string DirectKmsFooterKeyMaterial(const string &kms_id, const string &kms_url, const string &master_key_id,\n                                         const string &factory_class, const string &kms_client_class) {\n\tstring json = "{\\\"keyMaterialType\\\":\\\"PKMT1\\\",\\\"internalStorage\\\":true,"\n\t              "\\\"isFooterKey\\\":true,\\\"kmsInstanceID\\\":\\\"" + JsonEscapeConfig(kms_id) +\n\t              "\\\",\\\"kmsInstanceURL\\\":\\\"" + JsonEscapeConfig(kms_url) +\n\t              "\\\",\\\"masterKeyID\\\":\\\"" + JsonEscapeConfig(master_key_id) +\n\t              "\\\",\\\"parquet.encryption.footer.key\\\":\\\"" + JsonEscapeConfig(master_key_id) +\n\t              "\\\",\\\"wrappedDEK\\\":\\\"\\\",\\\"doubleWrapping\\\":false,"\n\t              "\\\"duckdbDirectKey\\\":true";\n\tif (!factory_class.empty()) {\n\t\tjson += ",\\\"parquet.crypto.factory.class\\\":\\\"" + JsonEscapeConfig(factory_class) + "\\\"";\n\t}\n\tif (!kms_client_class.empty()) {\n\t\tjson += ",\\\"parquet.encryption.kms.client.class\\\":\\\"" + JsonEscapeConfig(kms_client_class) + "\\\"";\n\t}\n\tjson += "}";\n\treturn json;\n}\n\nvoid ParquetEncryptionConfig::ApplyExternalKeyMetadata(ClientContext &context,\n                                                        ParquetEncryptionConfig &encryption_config) {\n\tauto &config = EncryptedParquetConfiguration::Get(context);\n\tconst auto master_key_id = TrimConfigValue(config.GetValue("parquet.encryption.footer.key"));\n\tif (master_key_id.empty()) {\n\t\treturn;\n\t}\n\n\tconst auto factory_class = TrimConfigValue(config.GetValue("parquet.crypto.factory.class"));\n\tconst auto kms_client_class = TrimConfigValue(config.GetValue("parquet.encryption.kms.client.class"));\n\tconst auto kms_id = config.Has("parquet.encryption.kms.instance.id")\n\t                        ? TrimConfigValue(config.GetValue("parquet.encryption.kms.instance.id"))\n\t                        : string("DEFAULT");\n\tconst auto kms_url = config.Has("parquet.encryption.kms.instance.url")\n\t                         ? TrimConfigValue(config.GetValue("parquet.encryption.kms.instance.url"))\n\t                         : string("DEFAULT");\n\n\tencryption_config.SetFooterKeyMetadata(DirectKmsFooterKeyMaterial(\n\t    kms_id.empty() ? "DEFAULT" : kms_id, kms_url.empty() ? "DEFAULT" : kms_url, master_key_id, factory_class,\n\t    kms_client_class));\n}\n\nshared_ptr<ParquetEncryptionConfig> ParquetEncryptionConfig::CreateFromHadoopConfiguration(ClientContext &context) {'''
rep('parquet_crypto.cpp', anchor, insert)

# Explicit COPY ENCRYPTION_CONFIG remains authoritative for the real AES key.
# Only when it exists do we overlay external/direct-KMS metadata. The old
# Hadoop-only InMemoryKMS path stays unchanged when ENCRYPTION_CONFIG is absent.
rep('parquet_extension.cpp',
'''\tauto encryption_config = parquet_bind.encryption_config;\n\tif (!encryption_config) {\n\t\tencryption_config = ParquetEncryptionConfig::CreateFromHadoopConfiguration(context);\n\t}\n\tglobal_state->writer = make_uniq<ParquetWriter>(''',
'''\tauto encryption_config = parquet_bind.encryption_config;\n\tif (encryption_config) {\n\t\tParquetEncryptionConfig::ApplyExternalKeyMetadata(context, *encryption_config);\n\t} else {\n\t\tencryption_config = ParquetEncryptionConfig::CreateFromHadoopConfiguration(context);\n\t}\n\tglobal_state->writer = make_uniq<ParquetWriter>(''')

print('Direct-KMS metadata overlay applied:', DST)
