<#
    .SYNOPSIS
    Configures IM Integration on Exchange 2013 servers with the Mailbox server role
    that have a valid certificate assigned for IIS services, and optionally can configure
    all CAS servers.
       
    Michel de Rooij
    michel@eightwone.com
    http://eightwone.com
	
    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE 
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
	
    Version 1.1, August 16th, 2016

    Special thanks to: Maarten Piederiet
	
    .DESCRIPTION
    Configured IM integration by modifying the web.config file on Mailbox servers
    with the UM assigned certificate and specified Lync Pool FQDN. Uses WMI to remotely
    restart the OWA app pool.
    
    .PARAMETER Server
    Specifies server to configure. When omitted, will configure local server. This
    parameter is mutually exclusive to AllMailbox.

    .PARAMETER AllMailbox
    Specifies to configure all Mailbox servers. This switch is mutally exclusive 
    with Server.

    .PARAMETER PoolFQDN
    Specifies the Lync Pool FQDN

    .PARAMETER AllCAS
    Instructs the script to (re)configure all Client Access Servers for IM.

    .PARAMETER Thumbprint
    Instructs the script to use certificate with the specified thumbprint.

    .PARAMETER UM
    Switch instructs the script to look for a certificate bound to UM rather than IIS.

    .LINK
    http://eightwone.com

    Revision History
    ---------------------------------------------------------------------
    1.0     Initial release
    1.1     Added Thumbprint parameter
            Added UM switch
            Changed that the script by default now looks for IIS-bound certificate
            Fixed bug when checking admin version
            Changed picking certificate method

    .EXAMPLE
    This configures IM integration on all Mailbox servers and CAS servers for lync.contoso.com
    Configure-IMIntegration.ps1 -PoolFQDN lync.contoso.com -AllMaibox -AllCAS
    
    .EXAMPLE
    This configures IM integration on the specified server for lync.contoso.com
    Configure-IMIntegration.ps1 -Server mbx1.contoso.com -PoolFQDN lync.contoso.com
#>
#Requires -Version 3.0

[cmdletbinding(SupportsShouldProcess = $true, DefaultParameterSetName= 'Local')]
param(
	[parameter( Mandatory=$true, ParameterSetName = 'Server')]
	[parameter( Mandatory=$false, ParameterSetName = 'Local')]
		[string[]]$Server= $env:ComputerName,
	[parameter( Mandatory=$true, ParameterSetName = 'Server')]
	[parameter( Mandatory=$true, ParameterSetName = 'Local')]
	[parameter( Mandatory=$true, ParameterSetName = 'All')]
		[string]$PoolFQDN=$null,
	[parameter( Mandatory=$false, ParameterSetName = 'Server')]
	[parameter( Mandatory=$false, ParameterSetName = 'Local')]
	[parameter( Mandatory=$false, ParameterSetName = 'All')]
        [switch]$AllCAS,
    [parameter( Mandatory=$true, ParameterSetName = 'All')]
        [switch]$AllMailbox,
	[parameter( Mandatory=$false, ParameterSetName = 'Server')]
	[parameter( Mandatory=$false, ParameterSetName = 'Local')]
	[parameter( Mandatory=$false, ParameterSetName = 'All')]
        [switch]$UM,
	[parameter( Mandatory=$false, ParameterSetName = 'Server')]
	[parameter( Mandatory=$false, ParameterSetName = 'Local')]
	[parameter( Mandatory=$false, ParameterSetName = 'All')]
        [string]$Thumbprint
)

process {

    $ERR_NOEMS                                 = 1001
    $ERR_NOTMAILBOXSERVER                      = 1002
    $ERR_CANTACCESSWEBCONFIG                   = 1004
    $ERR_NOPOOLFQDN                            = 1005

    function Configure-WebConfigItem( [ref]$wc, $key, $value) {
        $Node=$wc.Value.configuration.appsettings.SelectSingleNode("add[translate(@key,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='"+$key.ToLower()+"']")
        if (!$Node) {
            Write-Verbose "Adding Key $key, value $value"
            $Node = $wc.value.CreateElement('add')
            $Node.SetAttribute('key', $key)
            $Node.SetAttribute('value', $value)
            $wc.value.configuration.appSettings.AppendChild( $Node) | Out-Null
        } else {
            Write-Verbose "Setting Key $key, value $value"
            $Node.SetAttribute('value', $value)
        }
    }

    If( -not (Get-ExchangeServer -ErrorAction SilentlyContinue)) {
        Write-Error "Exchange Management Shell not loaded"
        Exit $ERR_NOEMS
    }

    If( $AllMailbox) {
        $ServerList= Get-MailboxServer
    }
    Else {
        $ServerList= $Server
    }

    If( -not( $PoolFQDN)) {
        Write-Error "Lync Pool FQDN not specified."
        Exit $ERR_NOPOOLFQDN
    }
    If( $UM) { 
        $Service= 'UM' 
    } 
    Else { 
        $Service= 'IIS'
    }

    ForEach( $Identity in $ServerList) {
        If( -not ( Get-MailboxServer -Identity $Identity)) {
            Write-Error "Server $Server does not run the Mailbox server role."
            Exit $ERR_NOTMAILBOXSERVER
        }
        Else {
            # Get the thumbprint of the UM assigned certificate
            If( $Thumbprint) {
                Write-Output "Checking for presence of certificate $ThumbPrint on $Identity"
                $CertThumbprint= (Get-ExchangeCertificate -Server $Identity -ThumbPrint $ThumbPrint -ErrorAction SilentlyContinue).ThumbPrint
            }
            Else {
                Write-Output "Determining certificate used for $Service service on $Identity"
                $CertThumbprint= (Get-ExchangeCertificate -Server $Identity | Where-Object {$_.Services -like "*$Service*" -and $_.Status -eq "Valid"} | Sort-Object IsSelfSigned | Select-Object -First 1).Thumbprint 
            }
            If( -not ( $CertThumbPrint) ) {
                Write-Error "Server $Identity does not contain an valid certificate assigned to UM services."
            }
            Else {
                Write-Output "Using certificate $CertThumbPrint"

                # Determine web.config using installation path
                Write-Output "Determining location of web.config"
                $Version= (Get-ExchangeServer -Identity $Identity).AdminDisplayVersion.Major
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Identity)
                $ExInstallPath = $reg.OpenSubKey("SOFTWARE\Microsoft\ExchangeServer\v$Version\Setup").GetValue("MsiInstallPath")
                $WebConfigFile= Join-Path $ExInstallPath "ClientAccess\Owa\web.config"
                $WebConfigFile= Join-Path "\\$Identity\" ( Join-Path ($WebConfigFile.subString(0,1) + '$') $WebConfigFile.subString(2))
                If( -not (Test-Path $WebConfigFile)) {
                    Write-Error "Can't determine or access web.config at $WebConfigFile"
                    Exit $ERR_CANTACCESSWEBCONFIG
                }
        
                # Process web.config
                Write-Output "Modifying $WebConfigFile"
                $wcf=[XML](Get-Content $WebConfigFile)
                Copy-Item $WebConfigFile ($WebConfigFile + "_"+ ( Get-Date).toString("yyyMMddHHmmss")+ ".bak") -Force
                Configure-WebConfigItem ([ref]$wcf) "IMCertificateThumbprint" $CertThumbprint
                Configure-WebConfigItem ([ref]$wcf) "IMServerName" $PoolFQDN
                $wcf.Save( $WebConfigFile)
    
                #Restart OWA app pool
                Write-Output "Restarting MSExchangeOWAAppPool on $Identity"
                $AppPool= Get-WMIObject -ComputerName $Identity -Namespace "root\MicrosoftIISv2" -Class "IIsApplicationPool" -Authentication PacketPrivacy | Where-Object { $_.Name -eq "W3SVC/APPPOOLS/MSExchangeOWAAppPool"}
                $AppPool.Recycle()
            }
        }
    }

    If( $AllCAS) {
        Get-ClientAccessServer | ForEach-Object {
            Write-Output "Configuring IM on CAS server $($_.Name)"
            Set-OwaVirtualDirectory -Identity “$($_.Name)\OWA (Default Web Site)” –InstantMessagingEnabled $true –InstantMessagingType OCS
        }
    }
}