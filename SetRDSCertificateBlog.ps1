<#
.SYNOPSIS
Check, configure or update the Remote Desktop TLS configuration for a custom server authentication certificate
As described in https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/custom-server-authentication-certificate-for-tls
.DESCRIPTION
Check if a valid Remote Desktop certificate is available.
If not, check if a valid Server Authentication certificate exists in the My space and configure it to be used in Remote Desktop TLS
Thanks goes to Paul Harrington https://gist.github.com/pharring for the private key access part
I use that script in a sheduled task to keep up w/ auto-renewed certificates
#>
# Get system certificate w/ Server Autehntication
# Get thumbprint of longest living
# Convert to binary reg key
# Check if regkey exists
# If not or different value create/replace

$CertIsValidForRDS = $false
$Today = [DateTime] (Get-Date)
[DateTime]$BestCertValidNotAfter = [DateTime] (Get-Date)
$LocalHostFQDN = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName

# Check if custom certificate is configured
$HashExists = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SSLCertificateSHA1Hash -ErrorAction SilentlyContinue

# Check if a valid certificate exists in Remote Desktop so no registry value needs to be set
# Server Authentication; not expired, not self-issued
$RDCerts = Get-ChildItem -Path "cert:\LocalMachine\Remote Desktop" -SSLServerAuthentication -Recurse
foreach ($RDCert in $RDCerts) {
    $CertIssuer = $RDCert.Issuer
    # Not issued by localhost
    if ($CertIssuer -notmatch $LocalHostFQDN) {
        [DateTime]$CertValidNotBefore = $RDCert.NotBefore
        [DateTime]$CertValidNotAfter = $RDCert.NotAfter
        # An dstill in the valid time period
        if ($CertValidNotBefore -lt $Today ) {
            if ($CertValidNotAfter -gt $Today) {
                $CertIsValidForRDS = $true
            }
        }
    }
}

if (!$CertIsValidForRDS) {
    # No valid RDS certifiacte found, so we will check in My for longest living Server Authentication certificate not self-issued
    $RDCerts = Get-ChildItem -Path "cert:\LocalMachine\My" -SSLServerAuthentication -Recurse
    foreach ($RDCert in $RDCerts) {
        $CertIssuer = $RDCert.Issuer
        $CertSubject = $RDCert.Subject
        if ($CertSubject -match $LocalHostFQDN) { # certificate is issued to the machine
            if ($CertIssuer -notmatch $CertSubject) { # but not self issued
                [DateTime]$CertValidNotBefore = $RDCert.NotBefore
                [DateTime]$CertValidNotAfter = $RDCert.NotAfter
                if ($CertValidNotBefore -lt $Today ) {
                    if ($CertValidNotAfter -gt $Today) {
                        # Certifacte is in a valid time period
                        $CertPath = "cert:\LocalMachine\My\" + $RDCert.Thumbprint
                        $CertChainValid = Test-Certificate -Cert $CertPath -ErrorAction SilentlyContinue
                        if ($CertChainValid) {
                            # Find the longest lasting vailid certificate
                            if ($CertValidNotAfter -gt [DateTime]$BestCertValidNotAfter) {
                                $BestCertThumb = $RDCert.Thumbprint
                                [DateTime]$BestCertValidNotAfter = $CertValidNotAfter
                                $CertIsValidForRDS = $true
                            }    
                        }
                    }
                }
            }    
        }
        
    }
    if ($CertIsValidForRDS) {
        
        $BestCertThumbBytes = for ($i = 0; $i -lt $BestCertThumb.Length; $i += 2) {
            [convert]::ToByte($BestCertThumb.SubString($i, 2),16)
        }
        
        # set registry key
        if ($HashExists) {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SSLCertificateSHA1Hash -PropertyType Binary -Value $BestCertThumbBytes
        }
        else {
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SSLCertificateSHA1Hash -PropertyType Binary -Value $BestCertThumbBytes
        }

        $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )

        try {
            $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

            try {       
                $CertStoreBest = $CertStore.Certificates | Where-Object {$_.Thumbprint -eq $BestCertThumb}

                if (!$CertStoreBest) {
                    Write-Error "Cannot find the certificate with thumbprint $BestCertThumb"
                    exit
                }
                $RSA = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($CertStoreBest)
                $RSAKey = $RSA.Key

        # 0x44 = DACL_SECURITY_INFORMATION | NCRYPT_SILENT_FLAG
        $DaclPropertyOptions = [System.Security.Cryptography.CngPropertyOptions]0x44
        $DaclProperty = $RSAKey.GetProperty("Security Descr", $DaclPropertyOptions)

        $SecurityDescriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($DaclProperty.GetValue(), 0);

        # Find existing NETWORK SERVICE Access control (ACE)
        $ExistingNetworkServiceAce = $SecurityDescriptor.DiscretionaryAcl | Where-Object {$_.SecurityIdentifier.IsWellKnown([System.Security.Principal.WellKnownSidType]::NetworkServiceSid)}

        $DesiredAccessMask = [System.Security.AccessControl.CryptoKeyRights]::GenericRead -bor
                     [System.Security.AccessControl.CryptoKeyRights]::Synchronize -bor
                     [System.Security.AccessControl.CryptoKeyRights]::ReadPermissions -bor
                     [System.Security.AccessControl.CryptoKeyRights]::ReadAttributes -bor
                     [System.Security.AccessControl.CryptoKeyRights]::ReadExtendedAttributes -bor
                     [System.Security.AccessControl.CryptoKeyRights]::ReadData

        if ($ExistingNetworkServiceAce)
        {
            # Verify access mask
            if ($ExistingNetworkServiceAce.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed)
            {
                Write-Host "NETWORK SERVICE already has an entry, but it is not 'Access Allowed'."
                # This would be dangerous to fix since we don't know who set this and why
                exit
            }

            $UpdatedAccessMask = $ExistingNetworkServiceAce.AccessMask -bor $DesiredAccessMask
            if ($UpdatedAccessMask -eq $ExistingNetworkServiceAce.AccessMask)
            {
                Write-Host "NETWORK SERVICE already has read access"
                exit
            }
            else
            {
              Write-Host "Adding Read access to NETWORK SERVICE"
              $ExistingNetworkServiceAce.AccessMask = $UpdatedAccessMask
            }
        }
        else
        {
          Write-Host "Adding NETWORK SERVICE to the access control list with Allow Read access"
          # Create a new ACE
          $NetworkServiceIdentifier = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::NetworkServiceSid, $null)
          $Ace = New-Object System.Security.AccessControl.CommonAce(
                [System.Security.AccessControl.AceFlags]::None,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                $DesiredAccessMask,
                $NetworkServiceIdentifier,
                $false,
                $null)

          # Add it to the DACL
          $SecurityDescriptor.DiscretionaryAcl.InsertAce($SecurityDescriptor.DiscretionaryAcl.Count, $Ace)
        }

        # Write the updated DACL back to the CNG key's security descriptor
        $UpdatedValue = New-Object byte[] $SecurityDescriptor.BinaryLength
        $SecurityDescriptor.GetBinaryForm($UpdatedValue, 0)
        $UpdatedCngProperty = New-Object System.Security.Cryptography.CngProperty("Security Descr", $UpdatedValue, $DaclPropertyOptions)
        $RSAKey.SetProperty($UpdatedCngProperty)

        Write-Host "Security descriptor updated"
    }
    finally
    {
        $CertStore.Close()
    }
}
catch [System.Security.Cryptography.CryptographicException]
{
    Write-Error "Could not open the Local Machine certificate store. Are you running as administrator?"
}
    }
}
