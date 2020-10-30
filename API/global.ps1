#==================
# GLOBAL
#==================

# Required to force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Required to ignore self-signed certificate error?
	#region: Workaround for SelfSigned Cert an force TLS 1.2
add-type @”
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
“@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion

# Set some variables, replace "foo" with your own API key
$MyAPIToken = 'foo'
$BaseURL = 'https://<ip or hostname>/api'
