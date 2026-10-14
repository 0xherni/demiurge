# Arma el instalador de Demiurge: artifacts\DemiurgeSetup.msi
#   1. Corre los tests.
#   2. Publica la app autocontenida (incluye .NET: el usuario no tiene que instalar nada) y compila la interfaz.
#   3. Compila el MSI con WiX.
# Uso: .\build-installer.ps1 [-Version 0.1.0] [-SkipTests]
param([string]$Version = "0.1.0", [switch]$SkipTests)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$dotnet = "C:\Program Files\dotnet\dotnet.exe"
$found = Get-Command dotnet -ErrorAction SilentlyContinue
if ($found) { $dotnet = $found.Source }
$publish = Join-Path $root "artifacts\publish"
$out = Join-Path $root "artifacts"

if (-not $SkipTests) {
    & $dotnet test (Join-Path $root "Demiurge.sln") -c Release --nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Los tests fallaron: no se arma el instalador." }
}

if (Test-Path $publish) { Remove-Item -Recurse -Force $publish }
& $dotnet publish (Join-Path $root "src\Demiurge.App\Demiurge.App.csproj") -c Release -r win-x64 --self-contained true `
    -p:Version=$Version -p:DebugType=none -p:SatelliteResourceLanguages=es -o $publish --nologo
if ($LASTEXITCODE -ne 0) { throw "Falló la publicación de la app." }
if (-not (Test-Path (Join-Path $publish "wwwroot\index.html"))) { throw "La publicación no incluye la interfaz (wwwroot)." }

# Herramientas incluidas (YARA-X, HollowsHunter): versión y hashes fijados en tools.lock.json.
# Se verifica el hash del zip descargado y el del ejecutable; si algo no coincide, no se arma el instalador.
$lock = Get-Content (Join-Path $root "src\Demiurge.Core\Resources\tools.lock.json") -Raw | ConvertFrom-Json
$cache = Join-Path $root "artifacts\cache"
New-Item -ItemType Directory -Force $cache | Out-Null
$notices = @("Demiurge incluye las siguientes herramientas de terceros, cada una con su licencia:", "")
foreach ($prop in $lock.tools.PSObject.Properties) {
    $t = $prop.Value
    $zip = Join-Path $cache ("{0}-{1}.zip" -f $prop.Name, $t.version)
    if (-not (Test-Path $zip)) { Invoke-WebRequest $t.url -OutFile $zip -UseBasicParsing }
    $zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
    if ($zipHash -ne $t.zipSha256) { Remove-Item $zip; throw "El hash del zip de $($t.name) no coincide ($zipHash). No se arma el instalador." }

    $dest = Join-Path $publish ("tools\" + $t.dir)
    New-Item -ItemType Directory -Force $dest | Out-Null
    $tmp = Join-Path $cache ("x-" + $prop.Name)
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive $zip -DestinationPath $tmp
    $exe = Get-ChildItem $tmp -Recurse -Filter $t.exe | Select-Object -First 1
    if (-not $exe) { throw "No se encontró $($t.exe) dentro del zip de $($t.name)." }
    $exeHash = (Get-FileHash $exe.FullName -Algorithm SHA256).Hash.ToLower()
    if ($exeHash -ne $t.exeSha256) { throw "El hash de $($t.exe) no coincide ($exeHash). No se arma el instalador." }
    if ($t.copyAll) { Copy-Item (Join-Path $exe.DirectoryName "*") $dest -Recurse -Force }
    else { Copy-Item $exe.FullName $dest }
    Remove-Item -Recurse -Force $tmp

    $licenseFile = Join-Path $dest "LICENSE.txt"
    Invoke-WebRequest $t.licenseUrl -OutFile $licenseFile -UseBasicParsing
    $line = "- $($t.name) $($t.version) ($($t.license)): tools\$($t.dir)\LICENSE.txt"
    if ($t.sourceUrl) { $line += ". Código fuente de esta versión: $($t.sourceUrl)" }
    $notices += $line
}
$notices += "", "Reglas YARA: se descargan en la PC del usuario desde YARA Forge (https://github.com/YARAHQ/yara-forge); cada regla conserva su autor y licencia en sus metadatos."
$notices | Set-Content -Encoding utf8 (Join-Path $publish "THIRD-PARTY-NOTICES.txt")
"Herramientas incluidas y verificadas: $(($lock.tools.PSObject.Properties | ForEach-Object { $_.Value.name }) -join ', ')"

& $dotnet build (Join-Path $root "installer\Demiurge.Installer.wixproj") -c Release -p:ProductVersion=$Version -p:PublishDir="$publish\" -o $out --nologo
if ($LASTEXITCODE -ne 0) { throw "Falló la compilación del instalador." }

$msi = Get-ChildItem $out -Recurse -Filter "DemiurgeSetup*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
"Instalador listo: $($msi.FullName) ($([math]::Round($msi.Length / 1MB, 1)) MB)"
"Nota: el MSI no está firmado. Windows SmartScreen va a mostrar una advertencia hasta que se firme con un certificado de firma de código."
