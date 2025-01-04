# Synology-PS
An API wrapper module for PowerShell 5.1 giving remote control of Synology Network Attached Storage (NAS) via the Synology WebAPI.

View full details and examples at:
https://www.c-amie.co.uk/technical/synology-nas-web-api-wrapper-for-powershell/

Synolgy-PS can:
- Wake the NAS via Wake-on-LAN
- Test for when the NAS has finished booting
- Log-in
- List all Shares
- List file/folder contents of a share/directory
- Download a file/compressed directory from the NAS
- Upload a file to the NAS
- Create a folder on the NAS
- Delete a file/directory on the NAS
- Rename a file/directory on the NAS
- List the available Web API methods for your device
- Call any Web API method not handled by a specific wrapper function
- Log-out
- Restart the NAS
- Shutdown (Power off) the NAS

## Functions List
- Synology-CreateFolder
- Synology-DeleteFile
- Synology-DownloadFile
- Synology-GenerateRandom
- Synology-InvokeMethod
- Synology-ListApi
- Synology-ListFiles
- Synology-ListShares
- Synology-Login
- Synology-Logout
- Synology-LookupError
- Synology-ParseFolderPath
- Synology-RenameFile
- Synology-Restart
- Synology-SetSessionTlsPolicy
- Synology-Shutdown
- Synology-TestConnection
- Synology-UploadFile
- Synology-WakeOnLan

## Basic Use

### Wake-on-LAN your NAS
```
Synology-WakeOnLan -MacAddress 'xx-xx-xx-xx-xx-xx'
```

### Sesson Creation and Teardown
```
# Import
. .\Synology-PS.ps1

# Set TLS 1.2 and 1.3 to enabled
Synology-SetSessionTlsPolicy

# Fetch an Authentication Token
$authToken = Synology-Login -Hostname "mynas.mydomain.local" -Port 5001 -UseHttps $true -Username "admin" -Password "secret"

if (-Not $authToken) {
  Write-Host "No authentication token was provided. Aborting."
  Exit 1
}

# Do something... 

Synology-Logout -AuthToken $authToken
```

### Restart the NAS
````
Synology-Restart -AuthToken $authToken
````

### Shutdown the NAS
````
Synology-Shutdown -AuthToken $authToken
````

### Download a File
```
Synology-DownloadFile -AuthToken $authToken -Path '/share/folder/MyFile.txt' -DestinationPath 'C:\Users\User\Documents'
```

### Upload a File
```
Synology-UploadFile -AuthToken $authToken -SourcePath "C:\Users\User\Desktop\MyFile.txt" -DestinationPath "/share/folder/folder"
```
