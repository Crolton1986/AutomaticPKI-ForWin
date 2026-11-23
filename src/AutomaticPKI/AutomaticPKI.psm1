Set-StrictMode -Version 3.0

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
$public  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "AutomaticPKI: failed to load $($file.FullName): $_"
    }
}

# Public function names must match their file names.
Export-ModuleMember -Function ($public | ForEach-Object { $_.BaseName })
