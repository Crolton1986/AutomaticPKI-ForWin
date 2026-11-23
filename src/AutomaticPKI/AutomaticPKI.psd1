@{
    RootModule           = 'AutomaticPKI.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6f3c2a7e-4b1d-4e8a-9c55-1d2f8a0b7e41'
    Author               = 'AutomaticPKI contributors'
    Description          = 'Automated certificate issuance, IIS binding and renewal for ADCS (RPC/DCOM and CES/CEP) on Windows Server.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = '*'
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('PKI', 'ADCS', 'IIS', 'Certificates', 'Windows')
            LicenseUri = 'https://github.com/crolton1986/AutomaticPKI-ForWin/blob/main/LICENSE'
            ProjectUri = 'https://github.com/crolton1986/AutomaticPKI-ForWin'
        }
    }
}
