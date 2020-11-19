<#

.SYNOPSIS
    Queries activity from specific list of hostnames then moves the associated sensors to a new sensor group. 

.DESCRIPTION
    This was just a quick script that queries Carbon Black EDR (formely Response) for a list of hostnames then move them to a new(already existing) Sensor Group. This is useful when conducting a hostname targeted Threat Hunt or Responding to an Incident and requiring to move all affected hostnames to a new sensor group.

.EXAMPLE
    C:\PS> .\CbEDR-HMSG.ps1 -API <enter your API Key> -IP <enter IP or hostname of CbEDR server> -group_ID <Group ID to move sensors to> -hostnames <path of file with list of hostnames>

.EXAMPLE
    C:\PS> .\CbEDR-HMSG.ps1 -API 7890218592d9c3940369d1b0f49afd0481952302 -IP 10.10.10.100 -group_ID 1 -usernames .\hostnames.txts

.NOTES 
    Author: Jon @ DigCyber Inc.
    Date: 19 Nov 2020
    Title: CbEDR-HMSG.ps1 -> CbEDR Hostnames Move Sensors Groups

#>

param (
    [string]
    # Your API Key
    $API,
    
    [ipaddress]
    # Server IP
    $IP,
    
    [int]
    # Server Port Number
    $port = "443",

    [int]
    # Enter Group ID where you want to move the Sensors to
    $group_ID,
    
    [string]
    # Enter path for file with list of hostnames. hostnames should be in a single column of a text file.
    $hostnames
    )

if ($API -eq $null) {
$API = read-host -Prompt "Please enter your API key"
}
if ($IP -eq $null) {
$BaseURL = read-host -Prompt "Please enter the IP for the CbEDR server"
}
if ($port -eq $null) {
$port = read-host -Prompt "Please enter the port number for the CbEDR server"
}
if ($group_ID -eq $null) {
$group_ID = read-host -Prompt "Please enter your API key"
}
if ($hostnames -eq $null) {
$hostnames = read-host -Prompt "Please enter path for the file containing the list of hostnames"
}

#==================
# GLOBAL
#==================

# Required to force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Required to ignore self-signed certificate error?
	#region: Workaround for SelfSigned Cert an force TLS 1.2
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion


#==================
# Queries
#==================
# Setting some variables
$MyAPIToken = $API -replace "'","" -replace '"',''
$BaseURL = ("https://'$IP':'$port'/api") -replace "'","" -replace '"',''
$hostnames1 = Get-Content -Path $hostnames | Where-Object { $_.Trim() -ne'' } | foreach {"hostname:" + $_}

#Removing files that might belong to a previous run
Remove-Item .\HMSG* -ErrorAction SilentlyContinue

# Retrieve list of Sensor IDs based on the list of hostnames but without Sensor Group or time limit
$hostnames1 | ForEach {Invoke-RestMethod -Method GET -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/v1/process?q='$_'&cb.group=id'} | ConvertTo-Json | Out-File .\HMSG1.txt
$json = Get-Content .\HMSG1.txt -raw | ConvertFrom-Json
$sensorIDS = ($json.results -Split ";" | Select-String -Pattern 'sensor_id' | sort | Get-Unique | foreach  {$_ -replace ' ',''} | foreach {$_ -replace 'sensor_id=',''})


#=====================
# Moving sensor groups
#=====================

$gID = "`"$group_ID`""
$Body = ('"group_id"')
$combined = "{'$Body':'$gID'}" -replace "'",""

#Pushing sensor IDs collected during the query to move to new Sensor Group ID
$sensorIDS | ForEach-Object {Invoke-RestMethod -Method PUT -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/v1/sensor/'$sensorIDS -Body $combined -ContentType 'application/json'}

# Confirming changes were successful
$sensorIDS | ForEach-Object ({Invoke-RestMethod -Method GET -Headers @{'X-Auth-Token' = $MyAPIToken} -URI $BaseURL'/v1/sensor/'$sensorIDS }) | ConvertTo-Json | Out-File .\HMSG2.txt
$results = Get-Content -Path .\HMSG2.txt | ConvertFrom-Json
$results | foreach-object { 
    if ($_.group_id -ne $group_ID) {
        Write-Host "Sensor_ID:"$_.id" Failed"
        Out-File -Append .\HMSG_Move-Failed.txt
        }
}
IF (Test-Path .\HMSG_Move-Failed.txt) {
        if ((Get-Item .\HMSG_Move-Failed.txt).Length -eq 0kb) {
            Write-Host "Associated Sensors were moved to Sensor Group ID "$gID""
            Remove-Item .\HMSG_Move-Failed.txt
            Remove-Item .\HMSG1.txt
            Remove-Item .\HMSG2.txt
            }
}
ELSE {
    Write-Host "Associated Sensors were moved to Sensor Group ID "$gID""
    Remove-Item .\HMSG1.txt
    Remove-Item .\HMSG2.txt
    }