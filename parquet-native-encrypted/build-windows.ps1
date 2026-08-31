param(
  [string]$Work = "$PSScriptRoot\work-windows"
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
if (!(Test-Path -LiteralPath $Cmake)) {
  throw "CMake was not found in Visual Studio Build Tools: $VsPath"
}
$VcVars = Join-Path $VsPath "VC\Auxiliary\Build\vcvars64.bat"
if (!(Test-Path -LiteralPath $VcVars)) {
  throw "The Visual Studio x64 developer environment was not found: $VsPath"
}

if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
New-Item -ItemType Directory -Force $Work | Out-Null
$Duck = Join-Path $Work "duckdb"
git clone --depth 1 --branch v1.5.5 https://github.com/duckdb/duckdb.git $Duck
python "$PSScriptRoot\prepare_extension.py" $Duck
$Config = (Join-Path $Duck "extension\extension_config_encrypted_parquet.cmake").Replace('\','/')
$Build = Join-Path $Duck "build\encrypted-release"
$ConfigureCommand = 'call "' + $VcVars + '" && "' + $Cmake + '" -S "' + $Duck + '" -B "' + $Build +
  '" -G Ninja "-DCMAKE_BUILD_TYPE=Release" "-DDUCKDB_EXTENSION_CONFIGS=' + $Config +
  '" "-DPython3_EXECUTABLE=' + (Get-Command python -ErrorAction Stop).Source + '"'
& cmd.exe /d /c $ConfigureCommand
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$BuildCommand = 'call "' + $VcVars + '" && "' + $Cmake + '" --build "' + $Build +
  '" --target encrypted_parquet_loadable_extension --parallel 4'
& cmd.exe /d /c $BuildCommand
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$Out = Join-Path $Duck "build\encrypted-release\extension\encrypted_parquet\encrypted_parquet.duckdb_extension"
Write-Host ""
Write-Host "Built: $Out"
