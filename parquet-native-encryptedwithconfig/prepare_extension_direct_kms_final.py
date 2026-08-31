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

# DuckDB v1.5.5 loadable extensions are not resolving our custom PragmaFunction
# registrations at runtime. Use regular table functions for every mutable SQL
# control API and invoke them through CALL instead.
rep('include/parquet_crypto.hpp',
'''\tstatic void AddKey(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void SetConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void UnsetConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void ClearConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic bool ValidKey(const std::string &key);''',
'''\tstatic void AddKey(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void SetConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void UnsetConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void ClearConfig(ClientContext &context, const FunctionParameters &parameters);\n\tstatic void AddKeyValue(ClientContext &context, const string &key_name, const string &key);\n\tstatic void SetConfiguration(ClientContext &context, const string &name, const string &value);\n\tstatic void UnsetConfiguration(ClientContext &context, const string &name);\n\tstatic void ClearConfiguration(ClientContext &context);\n\tstatic bool ValidKey(const std::string &key);''')

rep('parquet_crypto.cpp',
'''void ParquetCrypto::AddKey(ClientContext &context, const FunctionParameters &parameters) {\n\tconst auto &key_name = StringValue::Get(parameters.values[0]);\n\tconst auto &key = StringValue::Get(parameters.values[1]);\n\n\tauto &keys = ParquetKeys::Get(context);\n\tif (ValidKey(key)) {\n\t\tkeys.AddKey(key_name, key);\n\t} else {\n\t\tstring decoded_key;\n\t\ttry {\n\t\t\tdecoded_key = Base64Decode(key);\n\t\t} catch (const ConversionException &e) {\n\t\t\tthrow InvalidInputException("Invalid AES key. Not a plain AES key NOR a base64 encoded string");\n\t\t}\n\t\tif (!ValidKey(decoded_key)) {\n\t\t\tthrow InvalidInputException(\n\t\t\t    "Invalid AES key. Must have a length of 128, 192, or 256 bits (16, 24, or 32 bytes)");\n\t\t}\n\t\tkeys.AddKey(key_name, decoded_key);\n\t}\n}''',
'''void ParquetCrypto::AddKeyValue(ClientContext &context, const string &key_name, const string &key) {\n\tauto &keys = ParquetKeys::Get(context);\n\tif (ValidKey(key)) {\n\t\tkeys.AddKey(key_name, key);\n\t} else {\n\t\tstring decoded_key;\n\t\ttry {\n\t\t\tdecoded_key = Base64Decode(key);\n\t\t} catch (const ConversionException &e) {\n\t\t\tthrow InvalidInputException("Invalid AES key. Not a plain AES key NOR a base64 encoded string");\n\t\t}\n\t\tif (!ValidKey(decoded_key)) {\n\t\t\tthrow InvalidInputException(\n\t\t\t    "Invalid AES key. Must have a length of 128, 192, or 256 bits (16, 24, or 32 bytes)");\n\t\t}\n\t\tkeys.AddKey(key_name, decoded_key);\n\t}\n}\n\nvoid ParquetCrypto::AddKey(ClientContext &context, const FunctionParameters &parameters) {\n\tAddKeyValue(context, StringValue::Get(parameters.values[0]), StringValue::Get(parameters.values[1]));\n}''')

rep('parquet_crypto.cpp',
'''void ParquetCrypto::SetConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tconst auto &name = StringValue::Get(parameters.values[0]);\n\tconst auto &value = StringValue::Get(parameters.values[1]);\n\tEncryptedParquetConfiguration::Get(context).Set(name, value);\n}\n\nvoid ParquetCrypto::UnsetConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tconst auto &name = StringValue::Get(parameters.values[0]);\n\tEncryptedParquetConfiguration::Get(context).Unset(name);\n}\n\nvoid ParquetCrypto::ClearConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tEncryptedParquetConfiguration::Get(context).Clear();\n}''',
'''void ParquetCrypto::SetConfiguration(ClientContext &context, const string &name, const string &value) {\n\tEncryptedParquetConfiguration::Get(context).Set(name, value);\n}\n\nvoid ParquetCrypto::UnsetConfiguration(ClientContext &context, const string &name) {\n\tEncryptedParquetConfiguration::Get(context).Unset(name);\n}\n\nvoid ParquetCrypto::ClearConfiguration(ClientContext &context) {\n\tEncryptedParquetConfiguration::Get(context).Clear();\n}\n\nvoid ParquetCrypto::SetConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tSetConfiguration(context, StringValue::Get(parameters.values[0]), StringValue::Get(parameters.values[1]));\n}\n\nvoid ParquetCrypto::UnsetConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tUnsetConfiguration(context, StringValue::Get(parameters.values[0]));\n}\n\nvoid ParquetCrypto::ClearConfig(ClientContext &context, const FunctionParameters &parameters) {\n\tClearConfiguration(context);\n}''')

call_helpers = r'''class EncryptedParquetMutationBindData : public TableFunctionData {
public:
	EncryptedParquetMutationBindData() = default;
	EncryptedParquetMutationBindData(string first_p, string second_p = string())
	    : first(std::move(first_p)), second(std::move(second_p)) {
	}

	string first;
	string second;
};

static unique_ptr<FunctionData> BindEncryptedParquetMutation2(ClientContext &context, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("Success");
	return make_uniq<EncryptedParquetMutationBindData>(input.inputs[0].GetValue<string>(),
	                                                   input.inputs[1].GetValue<string>());
}

static unique_ptr<FunctionData> BindEncryptedParquetMutation1(ClientContext &context, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("Success");
	return make_uniq<EncryptedParquetMutationBindData>(input.inputs[0].GetValue<string>());
}

static unique_ptr<FunctionData> BindEncryptedParquetMutation0(ClientContext &context, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	return_types.emplace_back(LogicalType::BOOLEAN);
	names.emplace_back("Success");
	return make_uniq<EncryptedParquetMutationBindData>();
}

static void AddEncryptedParquetKeyTable(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	const auto &bind = data.bind_data->Cast<EncryptedParquetMutationBindData>();
	ParquetCrypto::AddKeyValue(context, bind.first, bind.second);
	output.SetCardinality(0);
}

static void SetEncryptedParquetConfigTable(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	const auto &bind = data.bind_data->Cast<EncryptedParquetMutationBindData>();
	ParquetCrypto::SetConfiguration(context, bind.first, bind.second);
	output.SetCardinality(0);
}

static void UnsetEncryptedParquetConfigTable(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	const auto &bind = data.bind_data->Cast<EncryptedParquetMutationBindData>();
	ParquetCrypto::UnsetConfiguration(context, bind.first);
	output.SetCardinality(0);
}

static void ClearEncryptedParquetConfigTable(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	ParquetCrypto::ClearConfiguration(context);
	output.SetCardinality(0);
}

static void LoadInternal(ExtensionLoader &loader) {'''
rep('parquet_extension.cpp',
'''static void LoadInternal(ExtensionLoader &loader) {''',
call_helpers)

rep('parquet_extension.cpp',
'''\t// Separate namespace from the built-in parquet extension to avoid ObjectCache/pragma collisions.\n\tauto parquet_key_fun = PragmaFunction::PragmaCall("add_encrypted_parquet_key", ParquetCrypto::AddKey,\n\t                                                  {LogicalType::VARCHAR, LogicalType::VARCHAR});\n\tloader.RegisterFunction(parquet_key_fun);\n\n\t// Hadoop Configuration-style String -> String properties for this extension only.\n\tauto set_config_fun = PragmaFunction::PragmaCall("set_encrypted_parquet_config", ParquetCrypto::SetConfig,\n\t                                                {LogicalType::VARCHAR, LogicalType::VARCHAR});\n\tloader.RegisterFunction(set_config_fun);\n\tauto unset_config_fun = PragmaFunction::PragmaCall("unset_encrypted_parquet_config", ParquetCrypto::UnsetConfig,\n\t                                                  {LogicalType::VARCHAR});\n\tloader.RegisterFunction(unset_config_fun);\n\tauto clear_config_fun =\n\t    PragmaFunction::PragmaCall("clear_encrypted_parquet_config", ParquetCrypto::ClearConfig, {});\n\tloader.RegisterFunction(clear_config_fun);''',
'''\t// Mutable extension APIs are ordinary table functions so loadable-extension\n\t// catalog resolution is deterministic in DuckDB v1.5.5.\n\tauto add_key_fun = TableFunction("add_encrypted_parquet_key", {LogicalType::VARCHAR, LogicalType::VARCHAR},\n\t                                 AddEncryptedParquetKeyTable, BindEncryptedParquetMutation2, nullptr, nullptr);\n\tloader.RegisterFunction(add_key_fun);\n\n\tauto set_config_fun = TableFunction("set_encrypted_parquet_config", {LogicalType::VARCHAR, LogicalType::VARCHAR},\n\t                                    SetEncryptedParquetConfigTable, BindEncryptedParquetMutation2, nullptr, nullptr);\n\tloader.RegisterFunction(set_config_fun);\n\n\tauto unset_config_fun = TableFunction("unset_encrypted_parquet_config", {LogicalType::VARCHAR},\n\t                                      UnsetEncryptedParquetConfigTable, BindEncryptedParquetMutation1, nullptr, nullptr);\n\tloader.RegisterFunction(unset_config_fun);\n\n\tauto clear_config_fun = TableFunction("clear_encrypted_parquet_config", {}, ClearEncryptedParquetConfigTable,\n\t                                      BindEncryptedParquetMutation0, nullptr, nullptr);\n\tloader.RegisterFunction(clear_config_fun);''')

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
