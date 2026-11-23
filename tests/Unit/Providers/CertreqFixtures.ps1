# Captured-style certreq.exe / certutil.exe outputs (en-US Windows Server) used by the AdcsRpc tests.
# Dot-source from a BeforeAll block.

function Get-CertreqFixture {
    param([Parameter(Mandatory)][string]$Name)

    switch ($Name) {
        'NewOk' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    ''
                    'CertReq: Request Created'
                ) }
        }
        'NewFailed' {
            [pscustomobject]@{ ExitCode = -2146893802; Output = [string[]]@(
                    'Certificate Request Processor: Keyset does not exist 0x80090016 (-2146893802 NTE_BAD_KEYSET)'
                ) }
        }
        'SubmitIssued' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'RequestId: 42'
                    'RequestId: "42"'
                    'Certificate retrieved(Issued) Issued'
                ) }
        }
        'SubmitPending' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'RequestId: 43'
                    'RequestId: "43"'
                    'Certificate request is pending: Taken Under Submission (0)'
                ) }
        }
        'SubmitDenied' {
            [pscustomobject]@{ ExitCode = -2146875391; Output = [string[]]@(
                    'RequestId: 44'
                    'RequestId: "44"'
                    'Certificate not issued (Denied) Denied by Policy Module  0x80094801, The request does not contain a certificate template extension or the CertificateTemplate request attribute.'
                    'The request does not contain a certificate template extension or the CertificateTemplate request attribute. 0x80094801 (-2146875391 CERTSRV_E_NO_CERT_TYPE)'
                    'Denied by Policy Module  0x80094801, The request does not contain a certificate template extension or the CertificateTemplate request attribute.'
                ) }
        }
        'SubmitCaOffline' {
            [pscustomobject]@{ ExitCode = -2147023174; Output = [string[]]@(
                    'Certificate Request Processor: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)'
                    'ca01.corp.local\Corp Issuing CA'
                ) }
        }
        'SubmitTemplateNotOnCa' {
            [pscustomobject]@{ ExitCode = -2146875392; Output = [string[]]@(
                    'Certificate Request Processor: The requested certificate template is not supported by this CA. 0x80094800 (-2146875392 CERTSRV_E_UNSUPPORTED_CERT_TYPE)'
                    'Denied by Policy Module'
                ) }
        }
        'Malformed' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Lorem ipsum dolor sit amet'
                    '%%%%'
                ) }
        }
        'Empty' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@() }
        }
        'RetrieveIssued' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Certificate retrieved(Issued) Issued  Resubmitted by CORP\pkiadmin'
                ) }
        }
        'RetrievePending' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Certificate request is pending: Taken Under Submission (0)'
                ) }
        }
        'RetrieveDenied' {
            [pscustomobject]@{ ExitCode = -2146877420; Output = [string[]]@(
                    'Certificate not issued (Denied) Denied by CORP\pkiadmin  0x80094014'
                    'Denied by CORP\pkiadmin  0x80094014'
                ) }
        }
        'RetrieveUnknownId' {
            [pscustomobject]@{ ExitCode = -2147024809; Output = [string[]]@(
                    'Certificate Request Processor: The parameter is incorrect. 0x80070057 (WIN32: 87 ERROR_INVALID_PARAMETER)'
                ) }
        }
        'AcceptOk' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Installed Certificate:'
                    '  Serial Number: 4f00000012ab34cd56ef7890120000000012'
                    '  Subject: CN=www.contoso.com (DNS Name=www.contoso.com, DNS Name=contoso.com)'
                    '  NotBefore: 11/23/2026 9:41 AM'
                    '  NotAfter: 11/23/2028 9:41 AM'
                    '  Thumbprint: 3f2a6c1b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a'
                ) }
        }
        'AcceptNoThumbprint' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Installed Certificate:'
                    '  Serial Number: 4f00000012ab34cd56ef7890120000000012'
                    '  Subject: CN=www.contoso.com'
                ) }
        }
        'AcceptFailed' {
            [pscustomobject]@{ ExitCode = -2146885628; Output = [string[]]@(
                    'Certificate Request Processor: Cannot find object or property. 0x80092004 (-2146885628 CRYPT_E_NOT_FOUND)'
                ) }
        }
        'PingOk' {
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Connecting to ca01.corp.local\Corp Issuing CA ...'
                    'Server "Corp Issuing CA" ICertRequest2 interface is alive (0ms)'
                    'CertUtil: -ping command completed successfully.'
                ) }
        }
        'PingFailed' {
            [pscustomobject]@{ ExitCode = -2147023174; Output = [string[]]@(
                    'Connecting to ca01.corp.local\Corp Issuing CA ...'
                    'Server could not be reached: The RPC server is unavailable. 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE) -- (31ms)'
                    'CertUtil: -ping command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)'
                    'CertUtil: The RPC server is unavailable.'
                ) }
        }
        default { throw "Unknown fixture '$Name'." }
    }
}

function New-AdcsRpcTestOrder {
    param(
        [AllowNull()][string]$Template = 'WebServer',
        [AllowNull()][string]$CAConfig = 'ca01.corp.local\Corp Issuing CA'
    )
    [pscustomobject]@{
        Id               = 'www-contoso-com'
        Status           = 'Approved'
        SiteName         = 'Contoso'
        Hostnames        = @('www.contoso.com', 'contoso.com')
        Provider         = 'AdcsRpc'
        ProviderSettings = [pscustomobject]@{ CAConfig = $CAConfig; Template = $Template }
        Key              = [pscustomobject]@{ Algorithm = 'RSA'; Length = 2048; Exportable = $false }
        KeyMode          = 'OnHost'
    }
}
