function Get-APKIAcceptAnyCertificateCallback {
    <#
    .SYNOPSIS
        Returns a RemoteCertificateValidationCallback that accepts any server certificate.
    .DESCRIPTION
        Used only by the TLS and HTTP health probes. They compare the served thumbprint with the
        expected one; chain trust, revocation and names are verified beforehand by
        Test-APKICertificatePrecheck. The probes must still succeed against 127.0.0.1, where the
        name never matches.

        The delegate is compiled C# rather than a PowerShell scriptblock: a scriptblock delegate
        throws "There is no Runspace available" if the runtime ever invokes it on a thread-pool
        thread (HttpWebRequest may), and a compiled delegate removes that risk regardless of
        which thread SslStream/HttpWebRequest uses. Compiled once per process.
    #>
    [CmdletBinding()]
    [OutputType([System.Net.Security.RemoteCertificateValidationCallback])]
    param()

    $typeName = 'AutomaticPKI.Health.CertificateCallbacks'
    $type = $typeName -as [type]
    if (-not $type) {
        $source = @'
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace AutomaticPKI.Health
{
    public static class CertificateCallbacks
    {
        private static bool AcceptAnyImpl(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        public static RemoteCertificateValidationCallback AcceptAny
        {
            get { return new RemoteCertificateValidationCallback(AcceptAnyImpl); }
        }
    }
}
'@
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
        $type = $typeName -as [type]
    }
    $type::AcceptAny
}
