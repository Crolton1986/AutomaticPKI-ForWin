# Base disk: builds a generalized generation 2 (UEFI/GPT) VHDX from the Server 2022 ISO with in-box
# Storage and DISM cmdlets, unless BaseVhdPath already exists. Applying install.wim gives an image
# that runs specialize/OOBE on first boot, like a sysprepped disk.

function Build-LabBaseImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Lab
    )
    $base = $Lab.BaseImage
    if (Test-Path -LiteralPath $base.BaseVhdPath) {
        Write-LabStep "Base disk exists: $($base.BaseVhdPath)"
        return
    }
    if (-not $base.IsoPath -or -not (Test-Path -LiteralPath $base.IsoPath)) {
        throw "Base disk '$($base.BaseVhdPath)' not found and IsoPath '$($base.IsoPath)' does not exist. Provide one of them (see lab/README.md)."
    }
    if ($Lab.Generation -ne 2) {
        throw 'Building the base disk from an ISO is supported for Generation 2 only. Supply a sysprepped disk for generation 1.'
    }

    $dir = Split-Path -Path $base.BaseVhdPath -Parent
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    $tempVhd = '{0}.building.vhdx' -f $base.BaseVhdPath
    if (Test-Path -LiteralPath $tempVhd) {
        # Leftover from an interrupted build.
        Dismount-VHD -Path $tempVhd -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $tempVhd -Force
    }

    Write-LabStep "Building base disk from $($base.IsoPath) (index $($base.ImageIndex)); this takes 10-20 minutes"
    $iso = Mount-DiskImage -ImagePath $base.IsoPath -PassThru -ErrorAction Stop
    $vhdMounted = $false
    try {
        $isoLetter = ($iso | Get-Volume).DriveLetter
        $wim = '{0}:\sources\install.wim' -f $isoLetter
        if (-not (Test-Path -LiteralPath $wim)) {
            throw "install.wim not found on the ISO ($wim). ESD-based media is not supported."
        }

        $null = New-VHD -Path $tempVhd -SizeBytes $base.SizeBytes -Dynamic -ErrorAction Stop
        $disk = Mount-VHD -Path $tempVhd -Passthru -ErrorAction Stop | Get-Disk
        $vhdMounted = $true
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT -ErrorAction Stop

        # EFI system partition, MSR, Windows.
        $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $null = Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'System' -Confirm:$false
        # The ESP gets no letter by default; bcdboot needs one.
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber -AssignDriveLetter
        $null = New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
        $win = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' -AssignDriveLetter
        $null = Format-Volume -Partition $win -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false

        $efiRoot = '{0}:\' -f (Get-Partition -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber).DriveLetter
        $winRoot = '{0}:\' -f (Get-Partition -DiskNumber $disk.Number -PartitionNumber $win.PartitionNumber).DriveLetter

        Write-LabStep "Applying image to $winRoot"
        $null = Expand-WindowsImage -ImagePath $wim -Index $base.ImageIndex -ApplyPath $winRoot -ErrorAction Stop

        $bcdboot = Join-Path $env:SystemRoot 'System32\bcdboot.exe'
        $out = & $bcdboot (Join-Path $winRoot 'Windows') /s $efiRoot.TrimEnd('\') /f UEFI 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "bcdboot failed ($LASTEXITCODE): $out"
        }
        Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $efi.PartitionNumber -AccessPath $efiRoot -ErrorAction SilentlyContinue
    }
    finally {
        if ($vhdMounted) {
            Dismount-VHD -Path $tempVhd -ErrorAction SilentlyContinue
        }
        Dismount-DiskImage -ImagePath $base.IsoPath -ErrorAction SilentlyContinue | Out-Null
    }

    Move-Item -LiteralPath $tempVhd -Destination $base.BaseVhdPath
    # Differencing disks require an unchanged parent.
    Set-ItemProperty -LiteralPath $base.BaseVhdPath -Name IsReadOnly -Value $true
    Write-LabStep "Base disk ready: $($base.BaseVhdPath)"
}
