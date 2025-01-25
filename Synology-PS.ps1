# Synology-PS: Synology API For PowerShell
# © C:Amie 2024 - 2025 https://www.c-amie.co.uk/
# Version 1.2.20250125
# If this was useful to you, feel free to buy me a coffee at https://www.c-amie.co.uk/
#
# Include this file in your own script via:
# . .\Synology-PS.ps1
# -or-
# . C:\Folder\Folder\Synology-PS.ps1
#
# API Guide
# https://cndl.synology.cn/download/Document/Software/DeveloperGuide/Package/FileStation/All/enu/Synology_File_Station_API_Guide.pdf
# https://kb.synology.com/en-us/DG/DSM_Login_Web_API_Guide/2

# Windows 10 and lower do not support TLS 1.3 connections via PowerShell. Ensure that TLS 1.2 or lower are enabled in DSM
# https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/connection_security_advanced?version=7

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
  public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
    return true;
  }
}
"@

<#
    .SYNOPSIS
    Generate a random string using URI legal ASCII characters

    .DESCRIPTION
    Generate a random string using URI legal ASCII characters

    .PARAMETER Length
    Required. The number of characters in the string

    .EXAMPLE
    PS> Synology-GenerateRandom -Length 5
    a4*gU

#>
function Synology-GenerateRandom {
  param(
    [Parameter(Mandatory=$true)]
    [int]$Length
  )
  $TokenSet = @{
    U = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    L = [Char[]]'abcdefghijklmnopqrstuvwxyz'
    N = [Char[]]'0123456789'
    S = [Char[]]'-_~!$&()*'
  }
  $Upper = Get-Random -Count 5 -InputObject $TokenSet.U
  $Lower = Get-Random -Count 5 -InputObject $TokenSet.L
  $Number = Get-Random -Count 5 -InputObject $TokenSet.N
  $Special = Get-Random -Count 5 -InputObject $TokenSet.S

  $StringSet = $Upper + $Lower + $Number + $Special

  (Get-Random -Count 15 -InputObject $StringSet) -join ''
}

<#
    .SYNOPSIS
    Sets the TLS/SSL policy for the current PowerShell session

    .DESCRIPTION
    Sets the TLS/SSL policy for the current PowerShell session. This should match (or at least include) the TLS setting specified 
    under Control Panel > Security > Advanced > TLS / SSL Profile Level on the NAS

    .PARAMETER Ssl30
    Default = $false. Enable SSL 3.0

    .PARAMETER Tls10
    Default = $false. Enable TLS 1.0

    .PARAMETER Tls11
    Default = $false. Enable TLS 1.1

    .PARAMETER Tls12
    Default = $true. Enable TLS 1.2

    .PARAMETER Tls13
    Default = $true. Enable TLS 1.3

    .EXAMPLE
    PS> Synology-SetSessionTlsPolicy -Tls12 $true -Tls13 $true

#>
function Synology-SetSessionTlsPolicy {
  Param (
    [Parameter(Mandatory=$false)]
    [bool]$Ssl30=$false,
    [Parameter(Mandatory=$false)]
    [bool]$Tls10=$false,
    [Parameter(Mandatory=$false)]
    [bool]$Tls11=$false,
    [Parameter(Mandatory=$false)]
    [bool]$Tls12=$true,
    [Parameter(Mandatory=$false)]
    [bool]$Tls13=$true
  )
  if (-Not $($Tls10 -bor $Tls11 -bor $Tls12 -bor $Tls13)) {
    Throw "Invalid TLS Configuration Specified"
  }
  $level = $null
  if ($Ssl30) {
    $level = $level -bor [System.Net.SecurityProtocolType]::Ssl3
  }
  if ($Tls10) {
    $level = $level -bor [System.Net.SecurityProtocolType]::Tls     #[System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Ssl3;
  }
  if ($Tls11) {
    $level = $level -bor [System.Net.SecurityProtocolType]::Tls11
  }
  if ($Tls12) {
    $level = $level -bor [System.Net.SecurityProtocolType]::Tls12
  }
  if ($Tls13) {
    $level = $level -bor [System.Net.SecurityProtocolType]::Tls13
  }
  [System.Net.ServicePointManager]::SecurityProtocol = $level
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

}

<#
    .SYNOPSIS
    Attempts to wake the NAS by sending a Wake-on-LAN Magic Packet

    .DESCRIPTION
    Fires a Wake-on-LAN packet into the current system broadcast domain formatted as a standard WoL Magic Packet

    .PARAMETER MacAddress
    Required. A hexadecimal MAC Address formatted as xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx

    .EXAMPLE
    PS> Synology-WakeOnLan -MacAddress 'xx:xx:xx:xx:xx:xx'

#>
function Synology-WakeOnLan {
  Param (
    [Parameter(Mandatory=$true)]
    [string]$MacAddress
  )
  $MacByteArray = $MacAddress -split "[:-]";
  [Byte[]] $MagicPacket = (,0xFF * 6)
  for ($i = 0; $i -lt 16; $i++) {
    ForEach ($strHex in $MacByteArray) {
      $byte = [Byte] "0x$strHex";
      [Byte[]] $MagicPacket += $byte;
    }
  }
  $UdpClient = New-Object System.Net.Sockets.UdpClient
  $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
  $UdpClient.Send($MagicPacket,$MagicPacket.Length) | out-null
  $UdpClient.Close()
}

<#
    .SYNOPSIS
    Tests to see if the Synology Web Service is online

    .DESCRIPTION
    Tests to see if the Synology Web Service is online

    .PARAMETER UseHttps
    Default = $true. Whether the request should be made using http ($false) or https ($true)

    .PARAMETER Hostname
    Required. The FQDN or IP Address of the NAS

    .PARAMETER Port
    Required. The TCP Port to connect to e.g. 443 or 5001

    .OUTPUTS
    Boolean. $true if the service responsed, $false if it did not

    .EXAMPLE
    PS> Synology-TestConnection -UseHttps $true -Hostname 'mynas.mydomain.com' -Port 5001
    False

#>
function Synology-TestConnection {
  Param (
    [Parameter(Mandatory=$false)]
      $UseHttps=$true,
    [Parameter(Mandatory=$true)]
    [string]$Hostname,
    [Parameter(Mandatory=$true)]
    [int]$Port
  )

  $url = "http$(if($UseHttps) { 's' } else { '' })://$($Hostname):$($Port)"
  $url
  try {
    #[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12 # -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Ssl3;
    #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $response = Invoke-WebRequest -Uri $url -Method GET -ErrorAction SilentlyContinue | Out-Null
    return $($response.StatusCode -eq 200)
  } catch {
    return $false
  }
}

<#
    .SYNOPSIS
    Returns a description for a Synology Error Code

    .DESCRIPTION
    Returns a description for a Synology API Error Code. Note: These error numbers should not be confused with HTTP Status Codes.

    .PARAMETER ErrorCode
    Required. A numeric error number

    .OUTPUTS
    String. An expanded error message description

    .EXAMPLE
    PS> Synology-LookupError -ErrorCode 107
    Session interrupted by duplicate login

#>
function Synology-LookupError {
  Param (
    [Parameter(Mandatory=$true)]
    [int]$ErrorCode
  )
  $dictErrors = @{
    100 = "Unknown error"
    101 = "No parameter of API, method or version"
    102 = "The requested API does not exist"
    103 = "The requested method does not exist"
    104 = "The requested version does not support the functionality"
    105 = "The logged in session does not have permission"
    106 = "Session timeout"
    107 = "Session interrupted by duplicate login"
    119 = "SID not found"
    400 = "Invalid parameter of file operation"
    401 = "Unknown error of file operation"
    402 = "System is too busy"
    403 = "Invalid user does this file operation"
    404 = "Invalid group does this file operation"
    405 = "Invalid user and group does this file operation"
    406 = "Can't get user/group information from the account server"
    407 = "Operation not permitted"
    408 = "No such file or directory"
    409 = "Non-supported file system"
    410 = "Failed to connect internet-based file system (e.g., CIFS)"
    411 = "Read-only file system"
    412 = "Filename too long in the non-encrypted file system"
    413 = "Filename too long in the encrypted file system"
    414 = "File already exists"
    415 = "Disk quota exceeded"
    416 = "No space left on device"
    417 = "Input/OutputFormat error"
    418 = "Illegal name or path"
    419 = "Illegal file name"
    420 = "Illegal file name on FAT file system"
    421 = "Device or resource busy"
    599 = "No such task of the file operation"
    900 = "Failed to delete file(s)/folder(s). More information in <errors> object."
    1200 = "Failed to rename it. More information in <errors> object."
    1800 = "There is no Content-Length information in the HTTP header or the received size doesn't match the value of Content-Length information in the HTTP header."
    1801 = "Wait too long, no date can be received from client (Default maximum wait time is 3600 seconds)."
    1802 = "No filename information in the last part of file content."
    1803 = "Upload connection is cancelled."
    1804 = "Failed to upload oversized file to FAT file system."
    1805 = "Can't overwrite or skip the existing file, if no overwrite parameter is given."

  }
  $return = $dictErrors[$ErrorCode]
  if (-Not $return) {
    $return = "Unknown error code"
  }
  $return
}

<#
    .SYNOPSIS
    Parses a shared folder path

    .DESCRIPTION
    Parses a shared folder path to ensure that the share/folder path does not end in a /

    .PARAMETER Path
    Required. A path in the format of /share/{folder}

    .OUTPUTS
    String. Any trailing / will be dropped from the input

    .EXAMPLE
    PS> Synology-ParseFolderPath -Path "/share/folder/"
    /share/folder

#>
function Synology-ParseFolderPath {
  Param (
    [Parameter(Mandatory=$true)]
    [string]$Path
  )

  while ($Path[$Path.Length-1] -eq '/') {
   $Path = $Path.SubString(0, [math]::min($Path.Length-1,$Path.length))
  }
  return $Path
}

<#
    .SYNOPSIS
    Log-on a user and return an Authenticaion Token instance

    .DESCRIPTION
    Log-on a user and return an Authenticaion Token instance that can be used to make API calls

    .PARAMETER UseHttps
    Default = $true. Whether the request should be made using http ($false) or https ($true)

    .PARAMETER Hostname
    Required. The FQDN or IP Address of the NAS

    .PARAMETER Port
    Required. The TCP Port to connect to e.g. 443 or 5001

    .PARAMETER Username
    Required. The username of the logging on user

    .PARAMETER Password
    Required. The clear-text password of the logging on user

    .OUTPUTS
    An authentication token structure containing the session data necessary to make use of the PowerShell API

    .EXAMPLE
    PS> $authToken = Synology-Login -Hostname "mynas.mydomain.com" -Port 5001 -UseHttps $true -Username "admin" -Password "secret"

#>
function Synology-Login {
  Param (
    [Parameter(Mandatory=$false)]
      [boolean]$UseHttps=$true,
    [Parameter(Mandatory=$true)]
      [string]$Hostname,
    [Parameter(Mandatory=$true)]
      [int]$Port,
    [Parameter(Mandatory=$true)]
      [string]$Username,
    [Parameter(Mandatory=$true)]
      [string]$Password
  )
  $sessionName = 'FileStation' #Synology-GenerateRandom -Length 16: ' All File Station APIs are required to login with SYNO.API.Auth and session=FileStation'
  $url = "http$(if($UseHttps) { 's' } else { '' })://$($Hostname):$Port/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&account=$Username&passwd=$Password&session=$sessionName&format=sid" # or cookie
  
  $dictHeaders = @{ 
    "Content-Type" = "application/x-www-form-urlencoded"
   }

  #[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12 # -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Ssl3;
  #[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

  $response = Invoke-WebRequest -Headers $dictHeaders -Uri $url -Method Get      # Can use -SkipCertificateCheck in PS6+
  $json = $response.Content | Out-String | ConvertFrom-Json
  $return = [PSCustomObject]@{
    PSTypeName = "SynologyAuthToken"
    Success = $json.success
    Did = $json.data.did
    Sid = $json.data.sid
    SessionName = $sessionName
    UseHttps = $UseHttps
    Hostname = $Hostname
    Port = $Port
  }
  $return
}

<#
    .SYNOPSIS
    End the current PowerShell AuthToken by logging off

    .DESCRIPTION
    Notifies the NAS to destroy the current PowerShell users security context

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .EXAMPLE
    PS> Synology-Logout -AuthToken $authToken

#>
function Synology-Logout {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken
  )
  if (-Not $AuthToken) {
    return
  }
  Synology-InvokeMethod -AuthToken $authToken -Target Auth -API "SYNO.API.Auth" -Method "logout" -Parameters @{"session" = $AuthToken.SessionName}
}

<#
    .SYNOPSIS
    Turns off the NAS

    .DESCRIPTION
    Unconditionally signals the NAS to shutdown. It is advised to issue an immediate log-out following running this command.

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .EXAMPLE
    PS> Synology-Shutdown -AuthToken $authToken

#>
function Synology-Shutdown {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken
  )
  if (-Not $AuthToken) {
    return
  }
  Synology-InvokeMethod -AuthToken $authToken -Target Auth -API "SYNO.Core.System" -Method "shutdown"
}

<#
    .SYNOPSIS
    Reboots the NAS

    .DESCRIPTION
    Unconditionally signals the NAS to restart. It is advised to issue an immediate log-out following running this command.

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .EXAMPLE
    PS> Synology-Restart -AuthToken $authToken

#>
function Synology-Restart {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken
  )
  if (-Not $AuthToken) {
    return
  }
  Synology-InvokeMethod -AuthToken $authToken -Target Auth -API "SYNO.Core.System" -Method "reboot"
}

<#
    .SYNOPSIS
    Returns a list of public API call namespaces available on the NAS

    .DESCRIPTION
    Returns a list of public API call namespaces available on the NAS. Note, this does not return 'private' API's such as SYNO.Core.xxx

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Query
    Default = 'all'. API names, separated by a comma "," or use "all" to get all supported APIs.

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> $api = Synology-ListApi -AuthToken $authToken

#>
function Synology-ListApi {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$false)]
      [string]$Query='all'
   )
  if (-Not $AuthToken) {
    return
  }
  return Synology-InvokeMethod -AuthToken $authToken -API 'SYNO.API.Info' -Method 'query' -Parameters @{"query" = $Query} -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Returns a list of shares available on the NAS

    .DESCRIPTION
    Returns a list of the shares available on the NAS

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Offset
    Optional. Specify how many shared folders are skipped before beginning to return listed shared folders.

    .PARAMETER Limit
    Optional. Number of shared folders requested. 0 lists all shared folders.

    .PARAMETER SortBy
    Optional. Specify which file information to sort on [name, user, group, mtime, atime, ctime, crtime or posix].

    .PARAMETER SortDirection
    Optional. Specify to sort ascending or to sort descending [asc or desc].

    .PARAMETER OnlyWritable
    Optional.
       true : List writable shared folders.
      false : List writable and read-only shared folders.

    .PARAMETER Additional
    Optional. Request additional data in the return response [real_path, owner, time, perm, mount_point_type, sync_share, or volume_status]

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> $shares = Synology-ListShares -AuthToken $authToken -OnlyWritable $true -SortBy ctime

#>
function Synology-ListShares {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$false)]
      [int]$Offset,
    [Parameter(Mandatory=$false)]
      [int]$Limit,
    [Parameter(Mandatory=$false)]
    [ValidateSet('name', 'user', 'group', 'mtime', 'atime', 'ctime', 'crtime', 'posix', IgnoreCase = $false)]
      [string]$SortBy,
    [Parameter(Mandatory=$false)]
    [ValidateSet('asc', 'desc', IgnoreCase = $false)]
      [string]$SortDirection='asc',
    [Parameter(Mandatory=$false)]
      [boolean]$OnlyWritable=$false,
    [Parameter(Mandatory=$false)]
    [ValidateSet('real_path', 'size', 'owner', 'time', 'perm', 'mount_point_type', 'volume_status', IgnoreCase = $false)]
      [string]$Additional
  )
  if (-Not $AuthToken) {
    return
  }
  $parameters = @{}
  if ($Offset -is [int]) {
    $parameters.Set_Item("offset", $Offset)
  }
  if ($Limit -is [int]) {
    $parameters.Set_Item("limit", $Limit)
  }
  if ($SortBy) {
    $parameters.Set_Item("sort_by", $SortBy)
  }
  if ($SortDirection -in "asc", "desc") {
    $parameters.Set_Item("sort_direction", $SortDirection)
  }
  if ($OnlyWritable -is [boolean]) {
    $parameters.Set_Item("onlywritable", $([string]$OnlyWritable).ToLower())
  }
  if ($Additional) {
    $parameters.Set_Item("additional", $Additional)
  }
  return Synology-InvokeMethod -AuthToken $authToken -API 'SYNO.FileStation.List' -Method 'list_share' -Version 2 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Returns a list of files/folders at a given path

    .DESCRIPTION
    Returns a list from the NAS of files/folders at the given path

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER FolderPath
    Required. The path on the NAS in which to return the contents list in the format of /share/folder{/folder}

    .PARAMETER Offset
    Optional. Optional. Specify how many files are skipped before beginning to return listed files.

    .PARAMETER Limit
    Optional. Number of files requested. 0 indicates to list all files with a given folder.

    .PARAMETER SortBy
    Optional. Specify which file information to sort on [name, size, user, group, mtime, atime, ctime, crtime, posix or type].

    .PARAMETER SortDirection
    Optional. Specify to sort ascending or to sort descending [asc or desc].

    .PARAMETER Pattern
    Optional. Given glob pattern(s) to find files whose names and extensions match a case-insensitive glob pattern.
              Note:
                1. If the pattern doesn't contain any glob syntax (? and *), * of glob syntax will be added at begin and end
                   of the string automatically for partially matching the pattern.
                2. You can use "," to separate multiple glob patterns.**

    .PARAMETER FileType
    Optional. "file": only enumerate regular files; "dir": only enumerate folders; "all" enumerate regular files and folders.

    .PARAMETER GoToPath
    Optional. Folder path starting with a shared folder. Return all files and sub-folders within folder_path path until goto_path path recursively.
              Note: GoToPath is only valid with parameter "Additional" contains real_path.

    .PARAMETER Additional
    Optional. Request additional data in the return response [real_path, size, owner, time, perm, type or mount_point_type]

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> $files = Synology-ListFiles -AuthToken $authToken -FolderPath '/share'

#>
function Synology-ListFiles {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$FolderPath,
    [Parameter(Mandatory=$false)]
      [int]$Offset,
    [Parameter(Mandatory=$false)]
      [int]$Limit,
    [Parameter(Mandatory=$false)]
    [ValidateSet('name', 'size', 'user', 'group', 'mtime', 'atime', 'ctime', 'crtime', 'posix', 'type', IgnoreCase = $false)]
      [string]$SortBy,
    [Parameter(Mandatory=$false)]
    [ValidateSet('asc', 'desc', IgnoreCase = $false)]
      [string]$SortDirection='asc',
    [Parameter(Mandatory=$false)]
      [string]$Pattern,
    [Parameter(Mandatory=$false)]
      [string]$FileType,
    [Parameter(Mandatory=$false)]
      [string]$GoToPath,
    [Parameter(Mandatory=$false)]
    [ValidateSet('real_path', 'size', 'owner', 'time', 'perm', 'mount_point_type', 'type', IgnoreCase = $false)]
      [string]$Additional
  )
  if (-Not $AuthToken) {
    return
  }
  $parameters = @{}
  $parameters.Set_Item("folder_path", $(Synology-ParseFolderPath -Path $FolderPath))
  if ($Offset -is [int]) {
    $parameters.Set_Item("offset", $Offset)
  }
  if ($Limit -is [int]) {
    $parameters.Set_Item("limit", $Limit)
  }
  if ($SortBy) {
    $parameters.Set_Item("sort_by", $SortBy)
  }
  if ($SortDirection -in "asc", "desc") {
    $parameters.Set_Item("sort_direction", $SortDirection)
  }
  if ($Pattern) {
    $parameters.Set_Item("pattern", $Pattern)
  }
  if ($FileType) {
    $parameters.Set_Item("filetype", $FileType)
  }
  if ($GoToPath) {
    $parameters.Set_Item("goto_path", $GoToPath)
  }
  if ($Additional) {
    $parameters.Set_Item("additional", $Additional)
  }

  return Synology-InvokeMethod -AuthToken $authToken -API 'SYNO.FileStation.List' -Method 'list' -Version 2 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Download a file from the NAS

    .DESCRIPTION
    Downloads a file on the NAS to the local computer

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Path
    Required. The path on the NAS of the file to be downloaded e.g. /share/folder/folder/MyFile.txt or /share/folder/folder
              If /share/path is used, the folder will be zipped before being downloaded

    .PARAMETER DestinationPath
    Required. The folder on the local computer in which to save the file e.g. C:\Users\User\Documents or ~/Documents
              If a folder path is given, the script will attempt to use the last value in the source Path
              parameter a the filename. If Path is a folder and no DestinationPath filename is specified then the
              download file will be a ZIP file in the name of the folder, but lacking the .zip file extension

    .OUTPUTS
    The binary file requested or an error

    .EXAMPLE
    PS> Synology-DownloadFile -AuthToken $authToken -Path '/share/folder/MyFile.txt' -DestinationPath 'C:\Users\User\Documents'

#>
function Synology-DownloadFile {
  Param (
  [Parameter(Mandatory=$true)]
    $AuthToken,
  [Parameter(Mandatory=$true)]
    [string]$Path,
  [Parameter(Mandatory=$true)]
    [string]$DestinationPath
  )
  if (-Not $AuthToken) {
    return
  }
  $apiPath          = 'webapi/entry.cgi'
  $arrSrcPath       = $($Path -Split '/')
  $filename         = $arrSrcPath[-1]
  $Path             = $(Synology-ParseFolderPath -Path $Path).Trim()
  $Path             = $([uri]::EscapeDataString($Path)) # URL Encode
  $DestinationPath  = $DestinationPath.Trim()
  
  if (Test-Path -Path $DestinationPath -PathType Container) { # If the DestinationPath is a folder, attempt to append a source filename
    if ($DestinationPath[-1] -NotIn $('\', '/')) {
      $DestinationPath = "$($DestinationPath)\"
    }
    $DestinationPath = "$($DestinationPath)$($filename)"
  }

  $url = "http$(if($AuthToken.UseHttps) { 's' } else { '' })://$($AuthToken.Hostname):$($AuthToken.Port)/$($apiPath)?api=SYNO.FileStation.Download&method=download&version=2&_sid=$($AuthToken.Sid)"
  $url = "$($url)&path=$($Path)&mode=download"

  try {
    Invoke-WebRequest -Uri $url -Method GET -OutFile $DestinationPath
  } catch [System.Net.WebException] {
    Throw "HTTP Error $($_.Exception.Message)"
  }
}

<#
    .SYNOPSIS
    Upload a file to the NAS

    .DESCRIPTION
    Uploads a file to the specified file system path on the NAS

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER SourcePath
    Required. The path on the local computer of the file to be uploaded e.g. C:\Users\User\Documents\MyFile.txt or ~/Documents/MyFile.txt

    .PARAMETER DestinationPath
    Required. The root relative file system path in the format of /share/directory{/directory}

    .PARAMETER CreateParentFolders
    Default = $true. If a folder path beneath a legal share is specified that does not exist on the NAS, attempt to create it as part of the write

    .PARAMETER Overwrite
    Default = $false. If the file already exists, overwrite it.

    .PARAMETER LastModified
    Optional. Override the file/folders last modified date/time using a UNIX epoch timestamp

    .PARAMETER Created
    Optional. Override the file/folders creation date/time using a UNIX epoch timestamp

    .PARAMETER LastAccessed
    Optional. Override the file/folders last accessed date/time using a UNIX epoch timestamp

    .EXAMPLE
    PS> Synology-UploadFile -AuthToken $authToken -SourcePath "C:\Users\User\Desktop\MyFile.txt" -DestinationPath "/share/folder/folder"

#>
function Synology-UploadFile {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$SourcePath,
    [Parameter(Mandatory=$true)]
      [string]$DestinationPath,
    [Parameter(Mandatory=$false)]
      [boolean]$CreateParentFolders=$true,
    [Parameter(Mandatory=$false)]
      [boolean]$Overwrite=$false,
    [Parameter(Mandatory=$false)]
      [int]$LastModified=$null,
    [Parameter(Mandatory=$false)]
      [int]$Created=$null,
    [Parameter(Mandatory=$false)]
      [int]$LastAccessed=$null
  )
  if (-Not $AuthToken) {
    return
  }
  if (-Not $(Test-Path $SourcePath -PathType Leaf)) {
    return
  }

  $dictHeaders = @{ 
    "Content-Type" = "text/plain; charset=`"UTF-8`""
  }

  $parameters = @{}
  $parameters.Set_Item("api", "SYNO.FileStation.Upload")
  $parameters.Set_Item("version", 2)
  $parameters.Set_Item("method", "upload")
    #$parameters.Set_Item("_sid", $($AuthToken.Sid))
  $parameters.Set_Item("create_parents", $([string]$CreateParentFolders).toLower())
  if ($Overwrite) {
    $parameters.Set_Item("overwrite", 'true')       # true in v2, overwrite in v3
  } else {
    $parameters.Set_Item("overwrite", 'false')      # false in v2, skip in v3
  }
  $parameters.Set_Item("path", $(Synology-ParseFolderPath -Path $DestinationPath)) # DestinationPath must have a leading / and no trailing /
  if ($LastModified -is [int]) {
    $parameters.Set_Item("mtime", $LastModified)
  }
  if ($Created -is [int]) {
    $parameters.Set_Item("crtime", $Created)
  }
  if ($Created -is [int]) {
    $parameters.Set_Item("atime", $LastAccessed)
  }

  $file = Get-Item $SourcePath
  $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName);
  $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes);
  $boundary = [System.Guid]::NewGuid().ToString().Replace('-', '');
  $boundaryPrefix = '-----------------------'
  $LF = "`r`n";

  $parameters.Set_Item("size", $($file.length))
  $parameters

  $bodyLines = ''
  foreach ($parm in $parameters.keys) {
    $bodyLines = $bodyLines + "$boundaryPrefix--$boundary$LF"
    $bodyLines = $bodyLines + "Content-Disposition: form-data; name=`"$parm`"$LF$LF"
    $bodyLines = $bodyLines + "$($parameters[$parm])$LF"
  }
    
  $bodyLines = $bodyLines + "$boundaryPrefix--$boundary$LF"
  $bodyLines = $bodyLines + "Content-Disposition: form-data; name=`"file`"; filename=`"$($file.Name)`"$LF"
  $bodyLines = $bodyLines + "Content-Type: application/octet-stream$LF$LF"
  $bodyLines = $bodyLines + $fileEnc
  $bodyLines = $bodyLines + $LF
  $bodyLines = $bodyLines + "$boundaryPrefix--$boundary--$LF"

  $url = "http$(if($AuthToken.UseHttps) { 's' } else { '' })://$($AuthToken.Hostname):$($AuthToken.Port)/webapi/entry.cgi?api=SYNO.FileStation.Upload&method=upload&version=2&_sid=$($AuthToken.Sid)"

  # NOTE: Binary data > MUST < be the LAST part of the request body
  Invoke-RestMethod -Uri $Url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyLines -Headers $dictHeaders # NOTE: bouondary=$boundary has NO QUOTES
}

<#
    .SYNOPSIS
    Delete a file or folder/folder hierarchy

    .DESCRIPTION
    Deletes a file or folder/folder hierarchy on the NAS

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Path
    Required. The root relative file system path in the format of /share/directory{/directory/}{filename.ext}

    .PARAMETER Recursive
    Default = $false. If a folder is specified, whether to delete the folder and all sub-folders and items ($true) or to fial the operation unless it is empty ($false)

    .OUTPUTS
    Boolean. $true if no error occured, $false if it did. Will return $true even if the file did not exist

    .EXAMPLE
    PS> Synology-DeleteFile -AuthToken $authToken -Path '/share/folder' -Recursive $true

    .EXAMPLE
    PS> Synology-DeleteFile -AuthToken $authToken -Path '/share/folder/file.ext'

#>
function Synology-DeleteFile {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$Path,
    [Parameter(Mandatory=$false)]
      [boolean]$Recursive=$false
  )
  $Path = $(Synology-ParseFolderPath -Path $Path)

  $parameters = @{}
  $parameters.Set_Item("path", $Path)
  $parameters.Set_Item("recursive", $([string]$Recursive).ToLower())

  $return = Synology-InvokeMethod -AuthToken $authToken -API 'SYNO.FileStation.Delete' -Method 'delete' -Version 2 -Parameters $parameters -Return $true -OutputFormat HttpStatusCode
  if ($return) {
    return $true
  } else {
    return $false
  }
}

<#
    .SYNOPSIS
    Rename a file or folder

    .DESCRIPTION
    Renames a file or folder on the NAS

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Path
    Required. The root relative file system path in the format of /share/directory/directory/{filename.ext}

    .PARAMETER NewName
    Required. The name of the folder or file (excluding the path)

    .PARAMETER Additional
    Optional. Request additional data in the return response [real_path, size, owner, time,perm or type]

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> Synology-RenameFile -AuthToken $authToken -Path '/Shared/old-filename.txt' -NewName 'new-filename.txt'

#>
function Synology-RenameFile {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$Path,
    [Parameter(Mandatory=$true)]
      [string]$NewName,
    [Parameter(Mandatory=$false)]
    [ValidateSet('real_path', 'size', 'owner', 'time', 'perm', 'type', IgnoreCase = $false)]
      [string]$Additional
  )
  $Path = $(Synology-ParseFolderPath -Path $Path)

  $parameters = @{}
  $parameters.Set_Item("path", $Path)
  $parameters.Set_Item("name", $NewName)
  if ($Additional) {
    $parameters.Set_Item("additional", $Additional)
  }

  return Synology-InvokeMethod -AuthToken $authToken -API 'SYNO.FileStation.Rename' -Method 'rename' -Version 2 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Create a folder

    .DESCRIPTION
    Creates a folder or folder hierarchy on the NAS

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Path
    Required. The root relative file system path in the format of /share/directory/directory

    .PARAMETER Name
    Required. The name of the lowest level new folder (excluding the path)

    .PARAMETER ForceParent
    Default = $false. If the Path value specified to place the new folder in does not exist, create it

    .PARAMETER Additional
    Optional. Request additional data in the return response [real_path, size, owner, time,perm or type]

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> Synology-CreateFolder -AuthToken $authToken -Path '/Shared/myfolder' -Name 'my-data' -ForceParent $true

#>
function Synology-CreateFolder {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$Path,
    [Parameter(Mandatory=$true)]
      [string]$Name,
    [Parameter(Mandatory=$false)]
      [boolean]$ForceParent,
    [Parameter(Mandatory=$false)]
    [ValidateSet('real_path', 'size', 'owner', 'time', 'perm', 'type', IgnoreCase = $false)]
      [string]$Additional
  )
  $Path = $(Synology-ParseFolderPath -Path $Path)

  $parameters = @{}
  $parameters.Set_Item("folder_path", $Path)
  $parameters.Set_Item("name", $Name)
  $parameters.Set_Item("force_parent", $([string]$ForceParent).ToLower())
  if ($Additional) {
    $parameters.Set_Item("additional", $Additional)
  }

  return Synology-InvokeMethod -AuthToken $AuthToken -API 'SYNO.FileStation.CreateFolder' -Method 'create' -Version 2 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Initiates a S.M.A.R.T. test on a physical hard drive

    .DESCRIPTION
    Invokes a self diagnostic test on a physical drive in the NAS (non-blocking)

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Device
    Required. The POSIX device path for the drive e.g. /dev/sda

    .PARAMETER Type
    Default = quick. Whether a quick or an extended S.M.A.R.T. test are requied [quick, extend]

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> Synology-BeginSmartTest -AuthToken $authToken -Device '/dev/sda' -Type quick

#>
function Synology-BeginSmartTest {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$Device,
    [Parameter(Mandatory=$false)]
    [ValidateSet('quick', 'extend', IgnoreCase = $false)]
      [string]$Type='quick'
  )

  $parameters = @{}
  $parameters.Set_Item("device", $Device)
  $parameters.Set_Item("type", $Type)

  return Synology-InvokeMethod -AuthToken $AuthToken -Target Entry -API 'SYNO.Core.Storage.Disk' -Method 'do_smart_test' -Version 1 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Returns the S.M.A.R.T. test data for a drive

    .DESCRIPTION
    Returns the raw S.M.A.R.T. metric data from the drive

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Device
    Required. The POSIX device path for the drive e.g. /dev/sda

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> $smartdata = Synology-BeginSmartTest -AuthToken $authToken -Device '/dev/sda' -Type quick
    PS> $smartdata.healthInfo.overview

#>
function Synology-GetSmartResults {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$Device
  )

  $parameters = @{}
  $parameters.Set_Item("device", $Device)

  return Synology-InvokeMethod -AuthToken $AuthToken -Target Entry -API 'SYNO.Storage.CGI.Smart' -Method 'get_health_info' -Version 1 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Returns basic system information

    .DESCRIPTION
    Returns basic hardware specification, device firmware version and build, time Server data, uptime and system time, model and serial number

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> Synology-SystemInfo -AuthToken $authToken

#>
function Synology-SystemInfo {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken
  )

  return Synology-InvokeMethod -AuthToken $AuthToken -Target Entry -API 'SYNO.Core.System' -Method 'info' -Version 3 -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Returns a list of installed apps in Package Center

    .DESCRIPTION
    Returns a list of installed apps in Package Center

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .OUTPUTS
    JSON representation of the NAS response.

    .EXAMPLE
    PS> $packages = Synology-InstalledPackages -AuthToken $authToken
    PS> $packages.packages

#>
function Synology-InstalledPackages {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken
  )

  $parameters = @{}
  $parameters.Set_Item("additional", '["description","description_enu","dependent_packages","beta","distributor","distributor_url","maintainer","maintainer_url","dsm_apps","dsm_app_page","dsm_app_launch_name","report_beta_url","support_center","startable","installed_info","support_url","is_uninstall_pages","install_type","autoupdate","silent_upgrade","installing_progress","ctl_uninstall","updated_at"]')

  return Synology-InvokeMethod -AuthToken $AuthToken -Target Entry -API 'SYNO.Core.Package' -Method 'list' -Version 2 -Parameters $parameters -Return $true -OutputFormat Json
}

<#
    .SYNOPSIS
    Invokes a custom Synology API GET method call.

    .DESCRIPTION
    For more information on available methods see:
    https://cndl.synology.cn/download/Document/Software/DeveloperGuide/Package/FileStation/All/enu/Synology_File_Station_API_Guide.pdf

    .PARAMETER AuthToken
    Required. The credential structure used to pass the server address and authentication token to methods

    .PARAMETER Target
    Default = Entry. The API entrypoint (script path) used for the request. Valid entries are: Entry, Auth, Otp

    .PARAMETER API
    Required. The SYNO.xxx.xxx API namespace being called

    .PARAMETER Method
    Required. The name of the method being called within the namespace

    .PARAMETER Version
    Default = 1. The API level being invoked

    .PARAMETER Parameters
    Optional. Custom parameters passed to the QueryString of the method invocation in a HashTable

    .PARAMETER Return
    Optional. Whether to return a value or return void

    .PARAMETER OutputFormat
    Default = Json. The data type for the return (if requested). Options are Json, Raw (the raw response body), HttpStatusCode

    .PARAMETER PrintDebug
    Default = $false. Whether to print debugging information (URL called and the requested output object) to assist in troubleshooting

    .OUTPUTS
    Representation of the NAS response based upon the value of OutputFormat

    .EXAMPLE
    PS> Synology-InvokeMethod -AuthToken $authToken -API 'SYNO.API.Info' -Method 'query' -Parameters @{"query" = "all"} -Return $true -OutputFormat Json

#>
function Synology-InvokeMethod {
  Param (
    [Parameter(Mandatory=$true)]
      $AuthToken,
    [Parameter(Mandatory=$true)]
      [string]$API,
    [Parameter(Mandatory=$true)]
      [string]$Method,
    [Parameter(Mandatory=$false)]
      [int]$Version=1,
    [Parameter(Mandatory=$false)]
      $Parameters,
    [Parameter(Mandatory=$false)]
      [boolean]$Return=$false,
    [Parameter(Mandatory=$false)]
    [ValidateSet('Raw','Json','HttpStatusCode', 'ResponseObject', IgnoreCase = $false)]
      [string]$OutputFormat='Json',
    [Parameter(Mandatory=$false)]
    [ValidateSet('Auth','Entry', 'Otp', IgnoreCase = $false)]
      [string]$Target='Entry',
    [Parameter(Mandatory=$false)]
      [boolean]$PrintDebug=$false
  )
    if (-Not $AuthToken) {
    return
  }

  $apiPath = ''
  switch ($Target) {
    "Auth"  { $apiPath = 'webapi/auth.cgi'; continue }
    "Entry" { $apiPath = 'webapi/entry.cgi'; continue }
    "Otp"  { $apiPath = 'webapi/otp.cgi'; continue }
  }
  
  $url = "http$(if($AuthToken.UseHttps) { 's' } else { '' })://$($AuthToken.Hostname):$($AuthToken.Port)/$($apiPath)?api=$API&method=$($Method)&version=$($Version)&_sid=$($AuthToken.Sid)"

  if ($Parameters.length -gt 0) {
    foreach ($key in $Parameters.keys) {
      $url = $url + "&$($key)=$($Parameters[$key])"
    }
  }

  if ($PrintDebug) {
    Write-Host "Contacting: $url"
  }
#  $dictHeaders = @{ 
#    "Content-Type" = "application/x-www-form-urlencoded"
#  }

#  $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
#  #$cookie = [System.Net.Cookie]::new('sid', $AuthToken.Sid, $($AuthToken.Hostname))
#  $cookie = New-Object System.Net.Cookie
#    $cookie.Name   = 'id'
#    $cookie.Value  = $AuthToken.Sid
#    $cookie.Domain = $AuthToken.Hostname
#  $session.Cookies.Add($cookie);

  #$session.Cookies.Add($cookie) #"http$(if($AuthToken.UseHttps) { 's' } else { '' })://$($AuthToken.Hostname):$Port", 

  $response = Invoke-WebRequest -Uri $url -Method GET -Body $Parametes #-Headers $dictHeaders -SessionVariable $session

  if ($OutputFormat -eq 'Raw') {
    if ($PrintDebug) {
      Write-Host $response.Content
    }
    if ($Return) {
      return $response.Content
    }
  } elseif ($OutputFormat -eq 'Json') {
    $json = $response.Content | Out-String | ConvertFrom-Json
    if (-Not $json.success) {
      Write-Host "Error $($json.error.code): $(Synology-LookupError -ErrorCode $json.error.code)" -ForegroundColor Red
      if ($PrintDebug) {
        Write-Host $json
      }
      if ($Return) {
        return $json.error
      }
    } else {
      if ($PrintDebug) {
        Write-Host $json
      }
      if ($Return) {
        return $json.data
      }
    }
  } elseif ($OutputFormat -eq 'HttpStatusCode') {
    if ($PrintDebug) {
      Write-Host $response.StatusCode
    }
    if ($Return) {
      return $response.StatusCode
    }
  } elseif ($OutputFormat -eq 'ResponseObject') {
    if ($PrintDebug) {
      Write-Host $response
    }
    if ($Return) {
      return $response
    }
  }
}
