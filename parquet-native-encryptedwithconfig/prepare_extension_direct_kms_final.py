#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
HERE = Path(__file__).resolve().parent
BASE = HERE / 'prepare_extension_java_compat_final.py'

if not BASE.exists():
    raise SystemExit(f'base generator not found: {BASE}')

# Keep the original java-compat generator authoritative for all existing SQL
# APIs, including add/set/unset/clear PRAGMA registration.
subprocess.check_call([sys.executable, str(BASE), str(ROOT)])

# The base generator adds unistd.h after io.h for a MinGW getpid path. MSVC
# does not provide unistd.h, so keep that include MinGW-only.
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

# Direct-KMS adds COPY-local metadata behavior. The legacy PRAGMA overlay remains
# available only as a backward-compatible fallback when the explicit COPY does
# not carry any Direct-KMS metadata fields.
rep('include/parquet_crypto.hpp',
'''\tstatic shared_ptr<ParquetEncryptionConfig> CreateFromHadoopConfiguration(ClientContext &context);\n\tconst string &GetFooterKey() const;\n\tconst string &GetFooterKeyMetadata() const;''',
'''\tstatic shared_ptr<ParquetEncryptionConfig> CreateFromHadoopConfiguration(ClientContext &context);\n\tstatic void ApplyExternalKeyMetadata(ClientContext &context, ParquetEncryptionConfig &encryption_config);\n\tconst string &GetFooterKey() const;\n\tconst string &GetFooterKeyMetadata() const;\n\tvoid SetFooterKeyMetadata(string metadata);\n\tbool HasDirectKmsKeyMetadata() const;''')

rep('parquet_crypto.cpp',
'''const string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {\n\tstatic const string empty;\n\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");\n\treturn entry == column_keys.end() ? empty : entry->second;\n}\n\nstatic string TrimConfigValue(const string &value) {''',
'''const string &ParquetEncryptionConfig::GetFooterKeyMetadata() const {\n\tstatic const string empty;\n\tauto entry = column_keys.find("__encrypted_parquet_footer_key_metadata");\n\treturn entry == column_keys.end() ? empty : entry->second;\n}\n\nvoid ParquetEncryptionConfig::SetFooterKeyMetadata(string metadata) {\n\tcolumn_keys["__encrypted_parquet_footer_key_metadata"] = std::move(metadata);\n}\n\nbool ParquetEncryptionConfig::HasDirectKmsKeyMetadata() const {\n\tconst auto &metadata = GetFooterKeyMetadata();\n\treturn metadata.find("\\\"duckdbDirectKey\\\":true") != string::npos;\n}\n\nstatic string TrimConfigValue(const string &value) {''')

# Build Direct-KMS metadata from the explicit COPY struct at bind time. This is
# deliberately independent of EncryptedParquetConfiguration/ObjectCache, so two
# COPY statements bound in the same DatabaseInstance retain independent values.
rep('parquet_crypto.cpp',
'''ParquetEncryptionConfig::ParquetEncryptionConfig(string footer_key_p) : footer_key(std::move(footer_key_p)) {\n}\n\nParquetEncryptionConfig::ParquetEncryptionConfig(ClientContext &context, const Value &arg) {\n\tif (arg.type().id() != LogicalTypeId::STRUCT) {\n\t\tthrow BinderException("Parquet encryption_config must be of type STRUCT");\n\t}\n\tconst auto &child_types = StructType::GetChildTypes(arg.type());\n\tauto &children = StructValue::GetChildren(arg);\n\tconst auto &keys = ParquetKeys::Get(context);\n\tfor (idx_t i = 0; i < StructType::GetChildCount(arg.type()); i++) {\n\t\tauto &struct_key = child_types[i].first;\n\t\tif (StringUtil::Lower(struct_key) == "footer_key") {\n\t\t\tconst auto footer_key_name = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\tif (!keys.HasKey(footer_key_name)) {\n\t\t\t\tthrow BinderException(\n\t\t\t\t    "No key with name \\\"%s\\\" exists. Add it with PRAGMA add_parquet_key('<key_name>','<key>');",\n\t\t\t\t    footer_key_name);\n\t\t\t}\n\t\t\t// footer key name provided - read the key from the config\n\t\t\tconst auto &keys = ParquetKeys::Get(context);\n\t\t\tfooter_key = keys.GetKey(footer_key_name);\n\t\t\tcolumn_keys["__encrypted_parquet_footer_key_metadata"] = footer_key_name;\n\t\t} else if (StringUtil::Lower(struct_key) == "footer_key_value") {\n\t\t\tfooter_key = StringValue::Get(children[i].DefaultCastAs(LogicalType::BLOB));\n\t\t} else if (StringUtil::Lower(struct_key) == "column_keys") {\n\t\t\tthrow NotImplementedException("Parquet encryption_config column_keys not yet implemented");\n\t\t} else {\n\t\t\tthrow BinderException("Unknown key in encryption_config \\\"%s\\\"", struct_key);\n\t\t}\n\t}\n}''',
'''ParquetEncryptionConfig::ParquetEncryptionConfig(string footer_key_p) : footer_key(std::move(footer_key_p)) {\n}\n\nstatic string DirectKmsFooterKeyMaterial(const string &kms_id, const string &kms_url, const string &master_key_id,\n                                         const string &factory_class, const string &kms_client_class);\n\nParquetEncryptionConfig::ParquetEncryptionConfig(ClientContext &context, const Value &arg) {\n\tif (arg.type().id() != LogicalTypeId::STRUCT) {\n\t\tthrow BinderException("Parquet encryption_config must be of type STRUCT");\n\t}\n\tconst auto &child_types = StructType::GetChildTypes(arg.type());\n\tauto &children = StructValue::GetChildren(arg);\n\tconst auto &keys = ParquetKeys::Get(context);\n\tstring master_key_id;\n\tstring kms_instance_id = "DEFAULT";\n\tstring kms_instance_url = "DEFAULT";\n\tstring crypto_factory_class;\n\tstring kms_client_class;\n\tbool has_direct_kms_metadata = false;\n\tfor (idx_t i = 0; i < StructType::GetChildCount(arg.type()); i++) {\n\t\tauto &struct_key = child_types[i].first;\n\t\tconst auto lower_key = StringUtil::Lower(struct_key);\n\t\tif (lower_key == "footer_key") {\n\t\t\tconst auto footer_key_name = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\tif (!keys.HasKey(footer_key_name)) {\n\t\t\t\tthrow BinderException(\n\t\t\t\t    "No key with name \\\"%s\\\" exists. Add it with PRAGMA add_parquet_key('<key_name>','<key>');",\n\t\t\t\t    footer_key_name);\n\t\t\t}\n\t\t\t// footer_key remains the DuckDB-local key alias and sole source of the actual AES key.\n\t\t\tconst auto &keys = ParquetKeys::Get(context);\n\t\t\tfooter_key = keys.GetKey(footer_key_name);\n\t\t\tcolumn_keys["__encrypted_parquet_footer_key_metadata"] = footer_key_name;\n\t\t} else if (lower_key == "footer_key_value") {\n\t\t\tfooter_key = StringValue::Get(children[i].DefaultCastAs(LogicalType::BLOB));\n\t\t} else if (lower_key == "master_key_id") {\n\t\t\tmaster_key_id = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\thas_direct_kms_metadata = true;\n\t\t} else if (lower_key == "kms_instance_id") {\n\t\t\tkms_instance_id = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\thas_direct_kms_metadata = true;\n\t\t} else if (lower_key == "kms_instance_url") {\n\t\t\tkms_instance_url = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\thas_direct_kms_metadata = true;\n\t\t} else if (lower_key == "crypto_factory_class") {\n\t\t\tcrypto_factory_class = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\thas_direct_kms_metadata = true;\n\t\t} else if (lower_key == "kms_client_class") {\n\t\t\tkms_client_class = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));\n\t\t\thas_direct_kms_metadata = true;\n\t\t} else if (lower_key == "column_keys") {\n\t\t\tthrow NotImplementedException("Parquet encryption_config column_keys not yet implemented");\n\t\t} else {\n\t\t\tthrow BinderException("Unknown key in encryption_config \\\"%s\\\"", struct_key);\n\t\t}\n\t}\n\n\tif (has_direct_kms_metadata) {\n\t\tif (master_key_id.empty()) {\n\t\t\tthrow BinderException("Direct-KMS ENCRYPTION_CONFIG requires non-empty master_key_id");\n\t\t}\n\t\tif (footer_key.empty()) {\n\t\t\tthrow BinderException("Direct-KMS ENCRYPTION_CONFIG requires footer_key or footer_key_value");\n\t\t}\n\t\tSetFooterKeyMetadata(DirectKmsFooterKeyMaterial(\n\t\t    kms_instance_id.empty() ? "DEFAULT" : kms_instance_id,\n\t\t    kms_instance_url.empty() ? "DEFAULT" : kms_instance_url, master_key_id, crypto_factory_class,\n\t\t    kms_client_class));\n\t}\n}''')

anchor = '''\tjson += "}";\n\treturn json;\n}\n\nshared_ptr<ParquetEncryptionConfig> ParquetEncryptionConfig::CreateFromHadoopConfiguration(ClientContext &context) {'''
insert = '''\tjson += "}";\n\treturn json;\n}\n\nstatic string DirectKmsFooterKeyMaterial(const string &kms_id, const string &kms_url, const string &master_key_id,\n                                         const string &factory_class, const string &kms_client_class) {\n\tstring json = "{\\\"keyMaterialType\\\":\\\"PKMT1\\\",\\\"internalStorage\\\":true,"\n\t              "\\\"isFooterKey\\\":true,\\\"kmsInstanceID\\\":\\\"" + JsonEscapeConfig(kms_id) +\n\t              "\\\",\\\"kmsInstanceURL\\\":\\\"" + JsonEscapeConfig(kms_url) +\n\t              "\\\",\\\"masterKeyID\\\":\\\"" + JsonEscapeConfig(master_key_id) +\n\t              "\\\",\\\"parquet.encryption.footer.key\\\":\\\"" + JsonEscapeConfig(master_key_id) +\n\t              "\\\",\\\"wrappedDEK\\\":\\\"\\\",\\\"doubleWrapping\\\":false,"\n\t              "\\\"duckdbDirectKey\\\":true";\n\tif (!factory_class.empty()) {\n\t\tjson += ",\\\"parquet.crypto.factory.class\\\":\\\"" + JsonEscapeConfig(factory_class) + "\\\"";\n\t}\n\tif (!kms_client_class.empty()) {\n\t\tjson += ",\\\"parquet.encryption.kms.client.class\\\":\\\"" + JsonEscapeConfig(kms_client_class) + "\\\"";\n\t}\n\tjson += "}";\n\treturn json;\n}\n\nvoid ParquetEncryptionConfig::ApplyExternalKeyMetadata(ClientContext &context,\n                                                        ParquetEncryptionConfig &encryption_config) {\n\t// COPY-local Direct-KMS metadata is authoritative. Return before touching the\n\t// database-level PRAGMA configuration so concurrent COPY operations cannot\n\t// observe each other's master_key_id or related metadata values.\n\tif (encryption_config.HasDirectKmsKeyMetadata()) {\n\t\treturn;\n\t}\n\n\t// Backward-compatible PR #1 fallback for callers that still provide only\n\t// footer_key in ENCRYPTION_CONFIG and Direct-KMS metadata via PRAGMA. This\n\t// legacy mode remains database-scoped and is not the concurrency-safe path.\n\tauto &config = EncryptedParquetConfiguration::Get(context);\n\tconst auto master_key_id = TrimConfigValue(config.GetValue("parquet.encryption.footer.key"));\n\tif (master_key_id.empty()) {\n\t\treturn;\n\t}\n\n\tconst auto factory_class = TrimConfigValue(config.GetValue("parquet.crypto.factory.class"));\n\tconst auto kms_client_class = TrimConfigValue(config.GetValue("parquet.encryption.kms.client.class"));\n\tconst auto kms_id = config.Has("parquet.encryption.kms.instance.id")\n\t                        ? TrimConfigValue(config.GetValue("parquet.encryption.kms.instance.id"))\n\t                        : string("DEFAULT");\n\tconst auto kms_url = config.Has("parquet.encryption.kms.instance.url")\n\t                         ? TrimConfigValue(config.GetValue("parquet.encryption.kms.instance.url"))\n\t                         : string("DEFAULT");\n\n\tencryption_config.SetFooterKeyMetadata(DirectKmsFooterKeyMaterial(\n\t    kms_id.empty() ? "DEFAULT" : kms_id, kms_url.empty() ? "DEFAULT" : kms_url, master_key_id, factory_class,\n\t    kms_client_class));\n}\n\nshared_ptr<ParquetEncryptionConfig> ParquetEncryptionConfig::CreateFromHadoopConfiguration(ClientContext &context) {'''
rep('parquet_crypto.cpp', anchor, insert)

# Explicit COPY ENCRYPTION_CONFIG remains authoritative for the actual AES key.
# COPY-local Direct-KMS metadata is already attached during binding; the call
# below only preserves the PR #1 legacy PRAGMA fallback when no such metadata
# was supplied in the COPY struct.
rep('parquet_extension.cpp',
'''\tauto encryption_config = parquet_bind.encryption_config;\n\tif (!encryption_config) {\n\t\tencryption_config = ParquetEncryptionConfig::CreateFromHadoopConfiguration(context);\n\t}\n\tglobal_state->writer = make_uniq<ParquetWriter>(''',
'''\tauto encryption_config = parquet_bind.encryption_config;\n\tif (encryption_config) {\n\t\tParquetEncryptionConfig::ApplyExternalKeyMetadata(context, *encryption_config);\n\t} else {\n\t\tencryption_config = ParquetEncryptionConfig::CreateFromHadoopConfiguration(context);\n\t}\n\tglobal_state->writer = make_uniq<ParquetWriter>(''')

# Hard guard: this overlay must never rewrite the original PRAGMA API.
registration = (DST / 'parquet_extension.cpp').read_text(encoding='utf-8')
for expected in (
    'PragmaFunction::PragmaCall("add_encrypted_parquet_key"',
    'PragmaFunction::PragmaCall("set_encrypted_parquet_config"',
    'PragmaFunction::PragmaCall("unset_encrypted_parquet_config"',
    'PragmaFunction::PragmaCall("clear_encrypted_parquet_config"',
):
    if expected not in registration:
        raise RuntimeError(f'original PRAGMA registration missing after Direct-KMS overlay: {expected}')

print('Direct-KMS COPY-local metadata overlay applied without changing PRAGMA API:', DST)
