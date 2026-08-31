param(
  [string]$Work = "$PSScriptRoot\work-windows-msvc"
)
$ErrorActionPreference = "Stop"

$VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path -LiteralPath $VsWhere)) {
  throw "Visual Studio Installer (vswhere.exe) was not found. Install Visual Studio Build Tools with the C++ workload."
}

$VsPath = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$VsPath) {
  throw "No Visual Studio C++ Build Tools installation was found."
}

$Cmake = Join-Path $VsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$VcVars = Join-Path $VsPath "VC\Auxiliary\Build\vcvars64.bat"
if (!(Test-Path -LiteralPath $Cmake)) { throw "CMake not found: $Cmake" }
if (!(Test-Path -LiteralPath $VcVars)) { throw "vcvars64.bat not found: $VcVars" }

if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
New-Item -ItemType Directory -Force $Work | Out-Null

$Duck = Join-Path $Work "duckdb"
git clone --depth 1 --branch v1.5.5 https://github.com/duckdb/duckdb.git $Duck
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python "$PSScriptRoot\prepare_extension_direct_kms_runtime_final.py" $Duck
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Config = (Join-Path $Duck "extension\extension_config_encrypted_parquet.cmake").Replace('\','/')
$Build = Join-Path $Duck "build\win64"
$Python = (Get-Command python -ErrorAction Stop).Source

$ConfigureCommand = 'call "' + $VcVars + '" && "' + $Cmake + '" -S "' + $Duck + '" -B "' + $Build +
  '" -G Ninja "-DCMAKE_BUILD_TYPE=Release" "-DDUCKDB_EXTENSION_CONFIGS=' + $Config +
  '" "-DPython3_EXECUTABLE=' + $Python +
  '" "-DBUILD_SHELL=ON" "-DBUILD_UNITTESTS=OFF" "-DBUILD_BENCHMARKS=OFF" "-DNATIVE_ARCH=OFF"'

& cmd.exe /d /c $ConfigureCommand
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$BuildCommand = 'call "' + $VcVars + '" && "' + $Cmake + '" --build "' + $Build + '" --parallel 4'
& cmd.exe /d /c $BuildCommand
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$DuckExe = Get-ChildItem -Path $Build -Recurse -File -Filter "duckdb.exe" | Select-Object -First 1
$Extension = Get-ChildItem -Path $Build -Recurse -File -Filter "encrypted_parquet.duckdb_extension" | Select-Object -First 1
if (!$DuckExe) { throw "duckdb.exe was not produced" }
if (!$Extension) { throw "encrypted_parquet.duckdb_extension was not produced" }

$DistRoot = Join-Path $PSScriptRoot "dist"
$Dist = Join-Path $DistRoot "windows_amd64"
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Force $Dist | Out-Null

Copy-Item -Force $DuckExe.FullName (Join-Path $Dist "duckdb.exe")
Copy-Item -Force $Extension.FullName (Join-Path $Dist "encrypted_parquet.duckdb_extension")
Copy-Item -Force "$PSScriptRoot\java_compat_usage.sql" (Join-Path $Dist "java_compat_usage.sql")
if (Test-Path "$PSScriptRoot\direct_kms_usage.sql") {
  Copy-Item -Force "$PSScriptRoot\direct_kms_usage.sql" (Join-Path $Dist "direct_kms_usage.sql")
}

@"
DuckDB v1.5.5 + encrypted_parquet (windows_amd64 / MSVC)

Start:
    duckdb.exe -unsigned

Then:
    LOAD 'encrypted_parquet.duckdb_extension';

Use java_compat_usage.sql for parquet-java/InMemoryKMS wrapping.
Use direct_kms_usage.sql for explicit AES encryption plus direct-KMS metadata.
Keep this MSVC duckdb.exe and MSVC extension together.
"@ | Set-Content -Encoding UTF8 (Join-Path $Dist "RUN-WINDOWS.txt")

$Zip = Join-Path $DistRoot "windows_amd64.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path $Dist -DestinationPath $Zip

Write-Host ""
Write-Host "DONE"
Write-Host "  DuckDB:    $(Join-Path $Dist 'duckdb.exe')"
Write-Host "  Extension: $(Join-Path $Dist 'encrypted_parquet.duckdb_extension')"
Write-Host "  Package:   $Zip"
