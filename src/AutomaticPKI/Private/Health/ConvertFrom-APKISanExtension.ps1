function ConvertFrom-APKISanExtension {
    <#
    .SYNOPSIS
        Extracts dNSName entries from a DER-encoded subjectAltName extension (OID 2.5.29.17).
    .DESCRIPTION
        Parses the ASN.1 directly instead of X509Extension.Format(), whose text is localised
        ("DNS Name=" vs "DNS-Name=") and differs between .NET Framework and .NET.
        GeneralNames ::= SEQUENCE OF GeneralName; dNSName is [2] IMPLICIT IA5String (tag 0x82).
        Other GeneralName types are skipped.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$RawData
    )

    $names = New-Object System.Collections.Generic.List[string]
    if ($RawData.Length -lt 2 -or $RawData[0] -ne 0x30) {
        throw 'subjectAltName is not a DER SEQUENCE.'
    }

    $pos = 1
    $end = $RawData.Length    # replaced by the SEQUENCE end after its length is read
    $isSequenceHeader = $true

    while ($true) {
        if (-not $isSequenceHeader) {
            if ($pos -ge $end) { break }
            $tag = [int]$RawData[$pos]
            $pos++
        }

        # DER length (short form, or long form with 1-4 length bytes).
        if ($pos -ge $RawData.Length) { throw 'Truncated DER length.' }
        $first = [int]$RawData[$pos]
        $pos++
        $len = 0
        if ($first -lt 0x80) {
            $len = $first
        }
        else {
            $count = $first -band 0x7F
            if ($count -lt 1 -or $count -gt 4) { throw 'Unsupported DER length encoding.' }
            for ($i = 0; $i -lt $count; $i++) {
                if ($pos -ge $RawData.Length) { throw 'Truncated DER length.' }
                $len = ($len * 256) + [int]$RawData[$pos]
                $pos++
            }
        }

        if ($isSequenceHeader) {
            $end = $pos + $len
            if ($end -gt $RawData.Length) { throw 'subjectAltName SEQUENCE length exceeds data.' }
            $isSequenceHeader = $false
            continue
        }

        if ($pos + $len -gt $end) { throw 'GeneralName length exceeds SEQUENCE.' }
        if ($tag -eq 0x82) {
            $names.Add([System.Text.Encoding]::ASCII.GetString($RawData, $pos, $len))
        }
        $pos += $len
    }

    $names.ToArray()
}
