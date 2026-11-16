

$a2m_Environment = "local"          # local | AAHybrid | AAnoHybrid
$a2m_LogLevel = "INFO"              # DEBUG | INFO | WARNING | ERROR
$a2m_LogLocation = "Local"             # Local | Hybrid | Azure
$a2m_LogPath = "C:\_SCOworkingDir\TFS\au2mator-AssetManagement\LOGS\TASKS"
$a2m_LogFileName = "TASK_0011_SyncEntraAssets"
$a2m_DeleteAfterDays = 30
$global:a2m_AZKVResponse = $null
$a2m_AZKeyVaultEnvironment = "Hybrid"    # Hybrid | OnPrem | Azure
$a2m_AZKeyVaultEnvironmentHybrid = "AzureVM"
$a2m_AZKeyVaultName = "AA-Prod-au2matorInternal"

#endregion Environment


#region Functions

function Write-au2matorLog {
    [CmdletBinding()]
    param
    (
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Type,
        [string]$Text
    )

    if ($a2m_LogLevel -eq "DEBUG" -and ($Type -eq "DEBUG" -or $Type -eq "INFO" -or $Type -eq "WARNING" -or $Type -eq "ERROR")) {
        $Logging = $true
    }
    elseif ($a2m_LogLevel -eq "INFO" -and ($Type -eq "INFO" -or $Type -eq "WARNING" -or $Type -eq "ERROR")) {
        $Logging = $true
    }
    elseif ($a2m_LogLevel -eq "WARNING" -and ($Type -eq "WARNING" -or $Type -eq "ERROR")) {
        $Logging = $true
    }
    elseif ($a2m_LogLevel -eq "ERROR" -and $Type -eq "ERROR") {
        $Logging = $true
    }
    else {
        $Logging = $false
    }

    if ($Logging) {
        if (($a2m_Environment -eq "AAHybrid" -or $a2m_Environment -eq "local") -and ($a2m_LogLocation -eq "Local" -or $a2m_LogLocation -eq "Hybrid")) {
            if (!(Test-Path -Path $a2m_LogPath)) {
                try {
                    $null = New-Item -Path $a2m_LogPath -ItemType Directory
                    Write-Verbose ("Path: ""{0}"" was created." -f $a2m_LogPath)
                }
                catch {
                    Write-Verbose ("Path: ""{0}"" couldn't be created." -f $a2m_LogPath)
                }
            }
            else {
                Write-Verbose ("Path: ""{0}"" already exists." -f $a2m_LogPath)
            }
            [string]$logFile = '{0}\{1}_{2}.log' -f $a2m_LogPath, $(Get-Date -Format 'yyyyMMdd'), $a2m_LogFileName
            $logEntry = '{0}: <{1}> <{2}> <{3}> {4}' -f $(Get-Date -Format dd.MM.yyyy-HH:mm:ss), $Type, $RequestId, $Service, $Text
            Out-File -FilePath $logFile -Append -InputObject $logEntry -Encoding utf8
        }
        if (($a2m_Environment -eq "AAHybrid" -or $a2m_Environment -eq "AAnoHybrid") -and ($a2m_LogLocation -eq "Hybrid" -or $a2m_LogLocation -eq "Azure")) {
            $logEntry = '{0}: <{1}> {2}' -f $(Get-Date -Format yyyyMMdd_HHmmss), $Type, $Text

            switch ($Type) {
                INFO { Write-Debug $logEntry }
                WARNING { Write-Warning $logEntry }
                ERROR { Write-Error $logEntry }
                DEBUG { Write-Debug $logEntry }
                Default { Write-Debug $logEntry }
            }
        }
    }

}

function Get-GraphHeader {
    param (
        $ClientID,
        $TenantID,
        $Secret,
        $CertName
    )

   
    if ($CertName.length -gt 10) {

        #####################
        $Scope = "https://graph.microsoft.com/.default"
        $Certificate = Get-ChildItem -path Cert:\LocalMachine\My\* -Recurse | where { $_.Subject -eq "CN=$($CertName)" }

        # Create base64 hash of certificate
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        # Create JWT timestamp for expiration
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)

        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)

        # Create JWT header
        $JWTHeader = @{
            alg = "RS256"
            typ = "JWT"
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
        }

        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "https://login.microsoftonline.com/$TenantID/oauth2/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $ClientID

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $ClientID
        }

        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

        $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = $EncodedHeader + "." + $EncodedPayload

        # Get the private key object of your certificate
        $PrivateKey = $Certificate.PrivateKey

        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)
        ) -replace '\+', '-' -replace '/', '_' -replace '='

        # Join the signature to the JWT with "."
        $JWT = $JWT + "." + $Signature

        # Create a hash with body parameters
        $Body = @{
            client_id             = $ClientID
            client_assertion      = $JWT
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope                 = $Scope
            grant_type            = "client_credentials"

        }

        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

        # Use the self-generated JWT as Authorization
        $Header = @{
            Authorization = "Bearer $JWT"
        }

        # Splat the parameters for Invoke-Restmethod for cleaner code
        $PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded'
            Method      = 'POST'
            Body        = $Body
            Uri         = $Url
            Headers     = $Header
        }

        $Request = Invoke-RestMethod @PostSplat

        $header = @{
            "Authorization" = "Bearer $($Request.access_token)"
            "Content-type"  = "application/json"
        }
    }
    else {

        $tokenBody = @{
            Grant_Type    = "client_credentials"
            Scope         = "https://graph.microsoft.com/.default"
            Client_Id     = $ClientID
            Client_Secret = $Secret
        }
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody

        $header = @{
            "Authorization" = "Bearer $($tokenResponse.access_token)"
            "Content-type"  = "application/json"
        }
    }

    return $header
}

function Clear-Logs {
    if ($LogLocation -eq "Hybrid" -or $LogLocation -eq "Local") {
        Write-au2matorLog -Type INFO -Text "Clean Log Files"
        $limit = (Get-Date).AddDays(-$DeleteAfterDays)
        Get-ChildItem -Path $LogPath -Filter "*$LogfileName.log" | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $limit } | Remove-Item -Force
    }
}

function Get-AZKeyVaultSecret {
    param (
        [string]$KeyVaultName,
        [string]$SecretName
    )   

    $ResourceURL = "https://vault.azure.net/&api-version=2021-02-01"

    #Here we check if the global variable is set. If it is not, we authenticate and get the token from the endpoint
    if ($null -eq $global:a2m_AZKVResponse) {
        #write-au2matorLog -Type INFO -Text "Getting KeyVault Token"
        if ($a2m_AZKeyVaultEnvironment -eq "Hybrid") {
            if ($a2m_AZKeyVaultEnvironmentHybrid -eq "AzureArc") {
                $endpoint = "http://localhost:40342/metadata/identity/oauth2/token?resource=$ResourceURL" #Azure Arc
               
                try { Invoke-WebRequest -Method GET -Uri $endpoint -Headers @{Metadata = 'True' } -UseBasicParsing } 
                catch {                 
                    if ($psversiontable.PSVersion -lt [version]'6.0') {
                        $wwwAuthHeader = $_.Exception.Response.Headers["WWW-Authenticate"];
                    }
                    else
                    { $_.Exception.Response.Headers | where { $_.key -eq "WWW-Authenticate" } | ForEach-Object { $wwwAuthHeader = $_.Value } }

                }

                if ($wwwAuthHeader -match "Basic realm=.+") {         
                    $secretFile = ($wwwAuthHeader -split "Basic realm=")[1]     
                } 
                $secret = cat -Raw $secretFile 
                $global:a2m_AZKVResponse = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -Method GET -Uri $endpoint -Headers  @{Metadata = 'True'; Authorization = "Basic $secret" } -UseBasicParsing).RawContentStream.ToArray()) | ConvertFrom-Json
            }
            elseif ($a2m_AZKeyVaultEnvironmentHybrid -eq "AzureVM") {
                $endpoint = "http://169.254.169.254/metadata/identity/oauth2/token?resource=$ResourceURL" #AzureVM
                $global:a2m_AZKVResponse = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -Method GET -Uri $endpoint -Headers @{Metadata = 'True' } -UseBasicParsing).RawContentStream.ToArray()) | ConvertFrom-Json
            }
        }
        elseif ($a2m_AZKeyVaultEnvironment -eq "local") {
            
            #check if module is installed Az
            if (-not (Get-Module -ListAvailable -Name Az)) {
                Install-Module -Name Az -AllowClobber -Force -Scope CurrentUser
            }
            #Import Module
            Import-Module Az.Accounts
            #Connect to Azure to get Token
            $Out = Connect-AzAccount -SubscriptionId $a2m_AZKeyVaultLocalSubscription -TenantId $a2m_AZKeyVaultLocalTenant 
            $AZAccessToken = Get-AzAccessToken -ResourceTypeName KeyVault
            $token = $AZAccessToken.Token
            $tokenCredential = [PSCredential]::new("token", $token)
            $global:a2m_AZKVResponse = @{}
            $global:a2m_AZKVResponse.access_token = $($tokenCredential.GetNetworkCredential().Password)
        }
        else {
            $global:a2m_AZKVResponse = [System.Text.Encoding]::Default.GetString((Invoke-WebRequest -UseBasicParsing -Uri "$($env:IDENTITY_ENDPOINT)?resource=$resourceURL" -Method 'GET' -Headers @{'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER"; 'Metadata' = 'True' }).RawContentStream.ToArray()) | ConvertFrom-Json
        }
    }
    else {
        #Token is already set, do nothing        
    }

    $token = $global:a2m_AZKVResponse.access_token
    $Return = Invoke-RestMethod -Uri "https://$($KeyVaultName).vault.azure.net/secrets/$($SecretName)?api-version=7.4" -Method GET -Headers @{Authorization = "Bearer $($token)" }
    return $return.value
}




function Get-AzureResourcePaging {
    param (
        $URL,
        $AuthHeader
    )

    $Response = Invoke-RestMethod -Method GET -Uri $URL -Headers $AuthHeader
    $Resources = $Response.value

    $ResponseNextLink = $Response."@odata.nextLink"
    while ($null -ne $ResponseNextLink) {
        $Response = (Invoke-RestMethod -Uri $ResponseNextLink -Headers $AuthHeader -Method Get)
        $ResponseNextLink = $Response."@odata.nextLink"
        $Resources += $Response.value
    }
    return $Resources
}

function Get-au2matorAPIPaging {
    param (
        $URL,
        $Header
    )
    $PageSize = 100
    $Take = 100
    $Page = 1
    $Response = Invoke-RestMethod -Method GET -Uri "$($URL)?PageIndex=$($Page)&PageSize=$($PageSize)&Take=$($Take)" -Headers $Header
    $Items = $Response.items
    while ($Response.count -gt $items.Count) {
        if ($Response.count - $Items.Count -lt $PageSize) {
            $Take = $Response.count - $Items.Count
        }
        $Page++
        $Response = (Invoke-RestMethod -Uri "$($URL)?PageIndex=$($Page)&PageSize=$($PageSize)&Take=$($Take)" -Headers $Header -Method Get)
        $Items += $Response.items
    }
    return $Items
}



function Get-RemoteImageBase64 {
    <#
        Fetches an image from an official manufacturer site (image_url field from
        models.json - for models as well as manufacturers) and returns it as Base64.

        This repository does NOT host any manufacturer images or logos. It only
        follows a link - and only if the operator explicitly enables it. The images
        belong to the respective manufacturers.

        If the download fails, this is logged and $null is returned. A missing
        image must NEVER abort the import.
    #>
    param (
        [string]$ImageUrl,
        [string]$Subject,
        [string[]]$AllowedHosts,
        [int]$TimeoutSec = 15
    )

    if ([string]::IsNullOrWhiteSpace($ImageUrl)) { return $null }

    try {
        $Uri = [Uri]$ImageUrl
    }
    catch {
        Write-au2matorLog -Type WARNING -Text "Image URL is not a valid URI for $($Subject): $ImageUrl"
        return $null
    }

    if ($Uri.Scheme -ne 'https') {
        Write-au2matorLog -Type WARNING -Text "Image URL is not HTTPS for $($Subject): $ImageUrl"
        return $null
    }

    if ($AllowedHosts -notcontains $Uri.Host) {
        Write-au2matorLog -Type WARNING -Text "Image host '$($Uri.Host)' is not an approved manufacturer domain - skipping image for $Subject"
        return $null
    }

    try {
        $Response = Invoke-WebRequest -Uri $ImageUrl -UseBasicParsing -TimeoutSec $TimeoutSec -MaximumRedirection 3
        $Bytes = $Response.Content
        if ($Bytes -isnot [byte[]]) { $Bytes = $Response.RawContentStream.ToArray() }
        if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
            Write-au2matorLog -Type WARNING -Text "Image download was empty for $($Subject): $ImageUrl"
            return $null
        }
        Write-au2matorLog -Type INFO -Text "Downloaded image for $Subject ($([math]::Round($Bytes.Length / 1KB)) KB)"
        return [Convert]::ToBase64String($Bytes)
    }
    catch {
        Write-au2matorLog -Type WARNING -Text "Image download failed for $($Subject): $($_.Exception.Message)"
        return $null
    }
}

function Invoke-au2matorPatch {
    <#
        Sends a JSON Patch operation to the au2mator API.
        All update endpoints follow the same pattern:
          PATCH <BaseURL>/itam_AssetApi/<Endpoint>/<id>
          ContentType application/json-patch+json
          Body = array of @{ op = "replace"; path = "/field"; value = "..." }
        Confirmed by the OpenAPI spec for UpdateCategory, UpdateCompany,
        UpdateUser, UpdateHardwareAsset, UpdateConfigurationItem, UpdateCountry.
    #>
    param (
        [string]$BaseURL,
        [hashtable]$Header,
        [string]$Endpoint,
        [string]$Id,
        [array]$Operations,
        [string]$Subject
    )

    if ($null -eq $Operations -or $Operations.Count -eq 0) { return $null }

    $Body = ConvertTo-Json -InputObject @($Operations) -Depth 10
    $Uri = "$($BaseURL)/itam_AssetApi/$($Endpoint)/$($Id)"

    try {
        $Response = Invoke-RestMethod -Method PATCH -Uri $Uri -Headers $Header -Body $Body -ContentType "application/json-patch+json"
        Write-au2matorLog -Type INFO -Text "Updated $($Subject) - fields: $(($Operations | ForEach-Object { $_.path }) -join ', ')"
        return $Response
    }
    catch {
        Write-au2matorLog -Type ERROR -Text "Update failed for $($Subject) via $($Endpoint): $($_.Exception.Message)"
        return $null
    }
}

function Get-ITAMUserCompanyId {
    <#
        Returns the id of the company of an au2mator user, or $null if the user
        has none. GetAllUsers does not include the company, so GetUser is called
        once per user and the result is cached for the rest of the run.
    #>
    param (
        [string]$UserId
    )

    if ([string]::IsNullOrWhiteSpace($UserId)) { return $null }
    if ($ITAMUserCompanyCache.ContainsKey($UserId)) { return $ITAMUserCompanyCache[$UserId] }

    $CompanyId = $null
    try {
        $UserObject = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetUser?Id=$($UserId)" -Headers $au2mator_Header
        if ($null -ne $UserObject.company -and -not [string]::IsNullOrWhiteSpace("$($UserObject.company.id)")) {
            $CompanyId = "$($UserObject.company.id)"
        }
    }
    catch {
        Write-au2matorLog -Type WARNING -Text "Could not read the company of user $($UserId): $($_.Exception.Message)"
    }

    $ITAMUserCompanyCache[$UserId] = $CompanyId
    return $CompanyId
}

function Get-CategoryIconBase64 {
    <#
        Loads a category icon from the local icons folder as Base64.
        These icons come from au2mator's own icon set and ship with the
        repository - nothing is fetched from third-party servers.
    #>
    param (
        [string]$IconFileName,
        [string]$IconDirectory,
        [string]$CategoryName
    )

    if ([string]::IsNullOrWhiteSpace($IconFileName)) {
        Write-au2matorLog -Type WARNING -Text "No icon defined for category $CategoryName"
        return $null
    }

    $IconPath = Join-Path -Path $IconDirectory -ChildPath $IconFileName

    # Leaf check: without it an empty file name would point at the directory
    # itself, Test-Path would return true and ReadAllBytes would throw.
    if (-not (Test-Path -Path $IconPath -PathType Leaf)) {
        Write-au2matorLog -Type WARNING -Text "Icon not found for category $($CategoryName): $IconPath"
        return $null
    }

    try {
        return [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($IconPath))
    }
    catch {
        Write-au2matorLog -Type WARNING -Text "Icon could not be read for category $($CategoryName): $($_.Exception.Message)"
        return $null
    }
}

#endregion Functions





#region getSecrets
$Entra_AppReg_clientID = Get-AZKeyVaultSecret -KeyVaultName $a2m_AZKeyVaultName -SecretName "AppReg-PRODEntraID-clientID"
$Entra_AppReg_Clientsecret = Get-AZKeyVaultSecret -KeyVaultName $a2m_AZKeyVaultName -SecretName "AppReg-PRODEntraID-ClientSecret"
$Entra_AppReg_tenantID = Get-AZKeyVaultSecret -KeyVaultName $a2m_AZKeyVaultName -SecretName "AppReg-PRODEntraID-TenantID"


#App Reg to Read Intune Devices
# DeviceManagementManagedDevices.Read.All
$Intune_AppReg_ClientID = Get-AZKeyVaultSecret -KeyVaultName $a2m_AZKeyVaultName -SecretName "AppReg-PRODIntuneDeviceRead-clientID"
$Intune_AppReg_TenantID = Get-AZKeyVaultSecret -KeyVaultName $a2m_AZKeyVaultName -SecretName "AppReg-PRODIntuneDeviceRead-TenantID"
$Intune_AppReg_Secret = Get-AZKeyVaultSecret -KeyVaultName $a2m_AZKeyVaultName -SecretName "AppReg-PRODIntuneDeviceRead-secret"


$a2m_API_Key = Get-AZKeyVaultSecret  -SecretName "au2mator-API-Key-AssetImport-DEMO" -KeyVaultName $a2m_AZKeyVaultName
$au2mator_BaseURL = "https://avmsrv002.au2mator.local/api"
$au2mator_Header = @{
    'Content-Type' = "application/json"
    'X-Api-Key'    = "$a2m_API_Key"     
    'accept'       = "*/*"
}

$BAseDir = "C:\_SCOworkingDir\TFS\au2mator-AssetManagement"
#endregion getSecrets



#Sync Settings
$ImportUnknownDevices = $false
$LogFileForUnknownDevices = "C:\_au2mator\_SourceControl\au2mator\PS-Service\LOGS\TASKS\UnknownDevices.log"

$InternalCompanyShort="au2mator"

#region Import Settings - images and updates
#
#   Images
#     $ImportCategoryIcons       Include category icons from icons\
#     $DownloadModelImages       Download model images from the manufacturer
#     $DownloadCompanyLogos      Download manufacturer logos from the manufacturer
#     $ModelImageTimeoutSec      Timeout for these downloads
#
#   Compare existing objects against the JSON
#     $UpdateExistingCategories  Update categories
#     $UpdateExistingModels      Update models
#     $UpdateExistingCompanies   Update manufacturers
#
#   Assets
#     $AssignCompanyFromUserToAsset  Set the company of an asset to the company of its assigned user
#
#   Security
#     $AllowedImageHosts         Allowed manufacturer domains for image downloads
#

# Category icons come from au2mator's own icon set and ship as files
# in the repository. Uncritical, therefore enabled by default.
$ImportCategoryIcons = $true

# Model images are NOT part of this repository. models.json only contains
# a link to the image at the manufacturer (image_url field). If this switch
# is enabled, the import downloads the image from the manufacturer's server and
# stores it in THIS au2mator installation.
#
# This is deliberately the operator's decision and therefore OFF by default:
# the images belong to the respective manufacturers, not to au2mator. Whoever
# flips the switch must make sure they have the necessary rights.
$DownloadModelImages = $false
$ModelImageTimeoutSec = 15

# Manufacturer logos. models.json holds a link per manufacturer to the logo on
# the manufacturer's official site. Same reasoning as for the model images:
# the logo belongs to the manufacturer, we only link to it.
$DownloadCompanyLogos = $false

# Compare existing categories, models and manufacturers in ITAM against the
# JSON and update description or image when they differ.
# OFF by default: enabling this lets the JSON win and may overwrite changes
# someone made in au2mator.
# Writes happen only on an actual difference.
$UpdateExistingCategories = $false
$UpdateExistingModels = $false
$UpdateExistingCompanies = $false

# Assign the company of the assigned user to the asset.
# If the user an asset is assigned to has a company in au2mator, the asset gets
# that company: new assets when they are created, existing assets in a separate
# pass at the end of the asset sync (a write happens only if the company differs).
# Users without a company never change an asset - an existing company on the
# asset is not cleared. Assets without an assigned user are left alone.
# OFF by default, because it changes the company of existing assets.
$AssignCompanyFromUserToAsset = $false

# Images may only be downloaded from these hosts. Official manufacturer domains
# only - no resellers, no logo collections, no mirrors.
# If you add manufacturers to models.json, add their domain here.
$AllowedImageHosts = @(
    'cdsassets.apple.com', 'support.apple.com', 'www.apple.com',
    'images.samsung.com', 'www.samsung.com', 'resources.samsung.com',
    'i.dell.com', 'www.dell.com',
    'ssl-product-images.www8-hp.com', 'www.hp.com', 'www.hpe.com',
    'p1-ofp.static.pub', 'p3-ofp.static.pub', 'psref.lenovo.com', 'www.lenovo.com',
    'www.zebra.com', 'www.minix.com.hk', 'www.vmware.com', 'www.microsoft.com',
    'www.intel.com', 'www.honeywell.com', 'www.asus.com', 'www.acer.com',
    'images.acer.com', 'www.gigabyte.com', 'us.dynabook.com', 'emea.dynabook.com',
    'www.yealink.com', 'www.keyence.com', 'www.zotac.com', 'www.msi.com',
    'www.fujitsu.com', 'www.poly.com', 'www.alienware.com', 'step-solutions.de',
    'psrefstuff.lenovo.com', 'images.samsung.com', 'i02.appmifile.com',
    'www-file.honor.com', 'www.honor.com', 'www.gstatic.com'
)
# Cache for Get-ITAMUserCompanyId (user id -> company id)
$ITAMUserCompanyCache = @{}

#endregion Import Settings


#region Script
Write-au2matorLog -Type INFO -Text "Start Script"
try {


    #Region SyncUsers
    #Get All Users from Azure
    $Entra_header = Get-GraphHeader -ClientID $Entra_AppReg_clientID -TenantID $Entra_AppReg_tenantID -Secret $Entra_AppReg_Clientsecret 

    $Resource = "users"
    $uri = "https://graph.microsoft.com/v1.0/$($Resource)?`$select=displayName,givenName,postalCode,identities,surname,userPrincipalName,companyName,accountEnabled"
    $AllEntraUsers = Get-AzureResourcePaging -URL $uri -AuthHeader $Entra_header

    Write-au2matorLog -Type INFO -Text "Total Users in Entra: $($AllEntraUsers.count)"

    #Get all USers from ITAM API
    $AllITAMUsers = Get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllUsers" -Header $au2mator_Header
    write-au2matorLog -Type INFO -Text "Total Users in ITAM: $($AllITAMUsers.count)"


    #Build lookups by userPrincipalName
    $GraphLookup = @{}
    foreach ($obj in $AllEntraUsers) {
        $key = "$($obj.userPrincipalName)"
        $GraphLookup[$key] = $obj
    }
    $GRAPHKeys = $GraphLookup.Keys

    $ITAMLookup = @{}
    foreach ($obj in $AllITAMUsers) {
        $key = "$($obj.upn)"
        $ITAMLookup[$key] = $obj
    }

    $UserNotInITAM = $GRAPHKeys | Where-Object { -not $ITAMLookup.ContainsKey($_) } | ForEach-Object { $GraphLookup[$_] }
    $UserAlreadyInITAM = $GRAPHKeys | Where-Object { $ITAMLookup.ContainsKey($_) } | ForEach-Object { $GraphLookup[$_] }
    $USerNotInEntra = $ITAMLookup.Keys | Where-Object { -not $GRAPHKeys.Contains($_) } | ForEach-Object { $ITAMLookup[$_] }
    
    Write-au2matorLog -Type INFO -Text "Total Users not in ITAM: $($UserNotInITAM.count)"
    Write-au2matorLog -Type INFO -Text "Total Users already in ITAM: $($UserAlreadyInITAM.count)"
    Write-au2matorLog -Type INFO -Text "Total Users not in Entra: $($USerNotInEntra.count)"


    $AllITAMCompanies = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllCompanies" -Header $au2mator_Header
    $ITAMCompanyLookup = @{}
    foreach ($obj in $AllITAMCompanies) {
        $key = "$($obj.name)"
        $ITAMCompanyLookup[$key] = $obj
    }

    #Status
    $AllUSerStatus = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetAllUserStatus" -Headers $au2mator_Header

    #Import NeW User in ITAM
    $Post_URL = "$($au2mator_BaseURL)/itam_AssetApi/CreateUser"
    $ImportBody = @{}
    foreach ($User in $UserNotInITAM) {
        $ImportBody = @{
            upn          = $User.userPrincipalName
            name         = $User.displayName
            firstName    = $User.givenName
            lastName     = $User.surname
            companyId    = ($AllITAMCompanies | Where-Object { $_.shortName -eq "$InternalCompanyShort"}).id
            userStatusId = switch ($User.accountEnabled) {
                $true { ($AllUSerStatus.items | Where-Object { $_.name -eq "Active" }).id }
                $false { ($AllUSerStatus.items | Where-Object { $_.name -eq "Inactive" }).id }
            }
        }
        $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
        Write-au2matorLog -Type INFO -Text "Importing User: $($User.userPrincipalName) - $($User.displayName) - $($User.companyName)"
        $Response = Invoke-RestMethod -Method POST -Uri $Post_URL -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
        Write-au2matorLog -Type INFO -Text "Imported User: $($User.userPrincipalName) - Response: $($Response.message)"
    }




    #Update existing users in ITAM with new details from Entra
    Write-au2matorLog -Type INFO -Text "Updating existing users in ITAM with new details from Entra"
   
    foreach ($User in $UserAlreadyInITAM) {
        $UpdateBody = @()
        $Update = $false
      
        $ITAMUser = $ITAMLookup[$User.userPrincipalName]
        #Get User Object for Company 
        $ITAMUserObject = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetUser?Id=$($ITAMUser.id)" -Headers $au2mator_Header

        #Check if any property is different and build the update body accordingly
        #Name
        If ($User.displayName -ne $ITAMUser.name) {
            $Update = $true
          
        }
        #First Name
        If ($User.givenName -ne $ITAMUser.firstName) {
            $Update = $true
        }
        #Last Name
        If ($User.surname -ne $ITAMUser.lastName) {
            $Update = $true
        }
        #Company
        $UpdateCompany = $false
        If (($AllITAMCompanies | Where-Object { $_.shortName -eq $InternalCompanyShort }).name -ne $ITAMUserObject.company.name) {
            

            #checkl if we have a company with the shortName in ITAM
            If (($AllITAMCompanies | Where-Object { $_.shortName -eq $InternalCompanyShort }).id) {
                
                $UpdateCompany = $true
            }
            else {
                Write-au2matorLog -Type WARNING -Text "Company with shortName $($InternalCompanyShort) not found in ITAM for user $($User.userPrincipalName)"
            }

            
        }
        #>
        #User Status
        $UpdateBody = @()
        $UserStatusId = switch ($User.accountEnabled) {
            $true { ($AllUSerStatus.items | Where-Object { $_.name -eq "Active" }).id }
            $false { ($AllUSerStatus.items | Where-Object { $_.name -eq "Inactive" }).id }
        }
        If ($UserStatusId -ne $ITAMUser.userStatus.Id) {
            $Update = $true
        }


        #If there are any updates, send the update request
        if ($Update -or $UpdateCompany) {
            #"HALT"; Start-Sleep -Seconds 10
            $UpdateBody = @(
                @{
                    op    = "replace"
                    path  = "/name"
                    value = "$($User.displayName)"
                },
                @{
                    op    = "replace"
                    path  = "/firstName"
                    value = "$($User.givenName)"
                },
                @{
                    op    = "replace"
                    path  = "/lastName"
                    value = "$($User.surname)"
                },


                @{
                    op    = "replace"
                    path  = "/userStatusId"
                    value = "$UserStatusId"
                }

                if ($UpdateCompany) {
                    @{
                        op    = "replace"
                        path  = "/companyId"
                        value = ($AllITAMCompanies | Where-Object { $_.shortName -eq $InternalCompanyShort }).id
                    }
                }
            )




            $UpdateBodyJson = $UpdateBody | ConvertTo-Json -Depth 10
            $Update_URL = "$($au2mator_BaseURL)/itam_AssetApi/UpdateUser/$($ITAMUser.id)"
            Write-au2matorLog -Type DEBUG -Text "User update payload: $UpdateBodyJson"
            Write-au2matorLog -Type INFO -Text "Updating User: $($User.userPrincipalName) - $($User.displayName) - $($User.companyName)"
            $Response = Invoke-RestMethod -Method PATCH -Uri $Update_URL -Headers $au2mator_Header -Body $UpdateBodyJson  -ContentType "application/json; charset=utf-8"
            Write-au2matorLog -Type INFO -Text "Updated User: $($User.userPrincipalName) - Response: $($Response.message)"
        } 

        
    }



    #Disable Users in ITAM that are not in Entra
    write-au2matorLog -Type INFO -Text "Disabling Users in ITAM that are not in Entra"
    foreach ($User in $USerNotInEntra) {
        $UpdateBody = @(
            @{
                op    = "replace"
                path  = "/userStatusId"
                value = ($AllUSerStatus.items | Where-Object { $_.name -eq "Inactive" }).id
            }
        )
        $UpdateBodyJson = $UpdateBody | ConvertTo-Json -Depth 10
        $Update_URL = "$($au2mator_BaseURL)/itam_AssetApi/UpdateUser/$($User.id)"
        Write-au2matorLog -Type INFO -Text "Disabling User: $($User.upn) - $($User.name)"
        $Response = Invoke-RestMethod -Method PATCH -Uri $Update_URL -Headers $au2mator_Header -Body $UpdateBodyJson  -ContentType "application/json; charset=utf-8"
        Write-au2matorLog -Type INFO -Text "Disabled User: $($User.upn) - Response: $($Response.message)"
    }



    #endRegion SyncUsers




    #region SyncClientAssets
    $Intune_header = Get-GraphHeader -ClientID $Intune_AppReg_ClientID -TenantID $Intune_AppReg_TenantID -Secret $Intune_AppReg_Secret 

    #GetIntune Devices


    $Resource = "deviceManagement/managedDevices"
    $uri = "https://graph.microsoft.com/v1.0/$($Resource)"
    $AllIntuneDevices = Get-AzureResourcePaging -URL "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" -AuthHeader $Intune_header
    $IntuneDeviceLookup = @{}



    foreach ($obj in $AllIntuneDevices) {
        $key = "$($obj.serialNumber)"
        $IntuneDeviceLookup[$key] = $obj
    }
    $IntuneDeviceKeys = $IntuneDeviceLookup.Keys




    #Get Models from JSON
    $models_File = "$BaseDir\models.json"
    $manufacturers_File = "$BaseDir\models.json"
    $categories_File = "$BaseDir\categories.json"

    $JSONModels = Get-Content -Path $models_File | ConvertFrom-Json | Select-Object -ExpandProperty manufacturers | ForEach-Object {
        $manufacturer = $_.manufacturer
        $manufacturer_short = $_.short_name
        $_.categories | ForEach-Object {
            $category = $_.category
            $_.models | ForEach-Object {
                $model = $_.model_name
                [PSCustomObject]@{
                    manufacturer       = $manufacturer
                    manufacturer_short = $manufacturer_short
                    category           = $category
                    model_name         = $model
                    key_model_intune   = $_.key_model_intune
                    model_number       = $_.model_number
                    Description_EN     = $_.Description_EN
                    Description_DE     = $_.Description_DE
                    release_year       = $_.release_year
                    image_url          = $_.image_url
                    image_source       = $_.image_source
                }
            }
        }
    }
    Write-au2matorLog -Type INFO -Text "Models available in JSON: $($JSONModels.count)"


    #Get Details from au2mator

    $AllITAMUsers = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllUsers" -Header $au2mator_Header 
    $ITAMUserLookup = @{}
    foreach ($obj in $AllITAMUsers) {
        $key = "$($obj.upn)"
        $ITAMUserLookup[$key] = $obj
    }

    $AllITAMCompanies = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllCompanies" -Header $au2mator_Header

    $ITAMCompanyLookup_ShortName = @{}
    foreach ($obj in $AllITAMCompanies) {
        $key = "$($obj.shortname)"
        $ITAMCompanyLookup_ShortName[$key] = $obj
    }

    $AllITAMCategories = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllCategories" -Header $au2mator_Header
    $ITAMCategoryLookup = @{}
    foreach ($obj in $AllITAMCategories) {
        $key = "$($obj.name)"
        $ITAMCategoryLookup[$key] = $obj
    }

    # Endpoint name according to the OpenAPI spec: GetAllHardwareAssets
    $AllITAMAssets = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllHardwareAssets" -Header $au2mator_Header
    $ITAMDeviceLookup = @{}
    foreach ($obj in $AllITAMAssets) {
        $key = "$($obj.serialNumber)"
        $ITAMDeviceLookup[$key] = $obj
    }   

    $ITAMDeviceKeys = $ITAMDeviceLookup.Keys

    $AllITAMModels = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllModels" -Header $au2mator_Header
    $ITAMModelLookup = @{}
    foreach ($obj in $AllITAMModels) {
        $key = "$($obj.modelNumber)"
        $ITAMModelLookup[$key] = $obj
    }

        $ITAMModelLookup_keyModelIntune = @{}
    foreach ($obj in $AllITAMModels) {
        $key = "$($obj.keyModelIntune)"
        $ITAMModelLookup_keyModelIntune[$key] = $obj
    }






    $JSONManufacturers = Get-Content -Path $manufacturers_File | ConvertFrom-Json
    $JSONManufacturerLookup = @{}
    foreach ($obj in $JSONManufacturers.manufacturers) {
        $key = "$($obj.short_name)"
        $JSONManufacturerLookup[$key] = $obj
    }
    


    $JSONCategories = Get-Content -Path $categories_File | ConvertFrom-Json
    $JSONCategorieLookup = @{}
    foreach ($obj in $JSONCategories.categories) {
        $key = "$($obj.category)"
        $JSONCategorieLookup[$key] = $obj
    }



    #region UpdateExisting
    # Compare existing categories and models against the JSON.
    #
    # Deliberately SEPARATE loops before the device processing: the creation logic
    # further down sits inside "foreach ($Device in $DevicesNotInITAM)" and the
    # category branch additionally inside "if ($NewModel)". Hooked in there, an
    # update would practically never reach existing objects - they exist precisely
    # when the devices are already in ITAM as well.

    if ($UpdateExistingCategories) {
        Write-au2matorLog -Type INFO -Text "Checking existing categories against JSON"
        $CategoriesUpdated = 0
        $CategoriesChecked = 0

        foreach ($JSONCategory in $JSONCategories.categories) {
            $ITAMCategory = $ITAMCategoryLookup[$JSONCategory.category]
            if ($null -eq $ITAMCategory) { continue }   # new -> the creation logic adds it
            $CategoriesChecked++

            $Operations = @()

            $DesiredDescription = $JSONCategory."Description_$ImportLanguage"
            if (-not [string]::IsNullOrWhiteSpace($DesiredDescription) -and $DesiredDescription -ne $ITAMCategory.description) {
                $Operations += @{ op = "replace"; path = "/description"; value = "$DesiredDescription" }
            }

            if ($ImportCategoryIcons) {
                $DesiredIcon = Get-CategoryIconBase64 -IconFileName $JSONCategory.icon -IconDirectory (Join-Path $BaseDir 'icons') -CategoryName $JSONCategory.category
                if ($null -ne $DesiredIcon -and $DesiredIcon -ne $ITAMCategory.icon) {
                    $Operations += @{ op = "replace"; path = "/icon"; value = "$DesiredIcon" }
                }
            }

            if ($Operations.Count -gt 0) {
                $Result = Invoke-au2matorPatch -BaseURL $au2mator_BaseURL -Header $au2mator_Header -Endpoint "UpdateCategory" -Id $ITAMCategory.id -Operations $Operations -Subject "category $($JSONCategory.category)"
                if ($null -ne $Result) { $CategoriesUpdated++ }
            }
        }

        Write-au2matorLog -Type INFO -Text "Categories checked: $CategoriesChecked - updated: $CategoriesUpdated"
    }
    else {
        Write-au2matorLog -Type INFO -Text "Skipping category update - UpdateExistingCategories is disabled"
    }

    if ($ITAMModelLookup_keyModelIntune) {
        Write-au2matorLog -Type INFO -Text "Checking existing models against JSON"
        $ModelsUpdated = 0
        $ModelsChecked = 0

        foreach ($JSONModel in $JSONModels) {
            if ([string]::IsNullOrWhiteSpace($JSONModel.key_model_intune)) { continue }

            $ITAMModel = $ITAMModelLookup_keyModelIntune[$JSONModel.key_model_intune]
            if ($null -eq $ITAMModel) { continue }      # new -> the creation logic adds it
            $ModelsChecked++

            $Operations = @()

            $DesiredDescription = $JSONModel."Description_$ImportLanguage"
            if (-not [string]::IsNullOrWhiteSpace($DesiredDescription) -and $DesiredDescription -ne $ITAMModel.description) {
                $Operations += @{ op = "replace"; path = "/description"; value = "$DesiredDescription" }
            }

            # Only add the image if ITAM does not have one yet.
            # A comparison would mean downloading every model's image from the manufacturer
            # on EVERY run - hundreds of requests per run, only to do nothing most of the
            # time.
            if ($DownloadModelImages -and [string]::IsNullOrWhiteSpace($ITAMModel.icon) -and -not [string]::IsNullOrWhiteSpace($JSONModel.image_url)) {
                $DesiredImage = Get-RemoteImageBase64 -ImageUrl $JSONModel.image_url -Subject "model $($JSONModel.model_name)" -AllowedHosts $AllowedImageHosts -TimeoutSec $ModelImageTimeoutSec
                if ($null -ne $DesiredImage) {
                    $Operations += @{ op = "replace"; path = "/icon"; value = "$DesiredImage" }
                }
            }

            if ($Operations.Count -gt 0) {
                $Result = Invoke-au2matorPatch -BaseURL $au2mator_BaseURL -Header $au2mator_Header -Endpoint "UpdateModel" -Id $ITAMModel.id -Operations $Operations -Subject "model $($JSONModel.model_name)"
                if ($null -ne $Result) { $ModelsUpdated++ }
            }
        }

        Write-au2matorLog -Type INFO -Text "Models checked: $ModelsChecked - updated: $ModelsUpdated"
    }
    else {
        Write-au2matorLog -Type INFO -Text "Skipping model update - UpdateExistingModels is disabled"
    }

    if ($UpdateExistingCompanies) {
        Write-au2matorLog -Type INFO -Text "Checking existing manufacturers against JSON"
        $CompaniesUpdated = 0
        $CompaniesChecked = 0

        foreach ($JSONManufacturer in $JSONManufacturers.manufacturers) {
            $ITAMCompany = $ITAMCompanyLookup_ShortName[$JSONManufacturer.short_name]
            if ($null -eq $ITAMCompany) { continue }   # new -> the creation logic adds it
            $CompaniesChecked++

            $Operations = @()

            if (-not [string]::IsNullOrWhiteSpace($JSONManufacturer.manufacturer) -and $JSONManufacturer.manufacturer -ne $ITAMCompany.name) {
                $Operations += @{ op = "replace"; path = "/name"; value = "$($JSONManufacturer.manufacturer)" }
            }

            # Like for models, only add the logo if ITAM does not have one yet
            # - otherwise every run would re-download all logos.
            if ($DownloadCompanyLogos -and [string]::IsNullOrWhiteSpace($ITAMCompany.icon) -and -not [string]::IsNullOrWhiteSpace($JSONManufacturer.image_url)) {
                $DesiredLogo = Get-RemoteImageBase64 -ImageUrl $JSONManufacturer.image_url -Subject "company $($JSONManufacturer.short_name)" -AllowedHosts $AllowedImageHosts -TimeoutSec $ModelImageTimeoutSec
                if ($null -ne $DesiredLogo) {
                    $Operations += @{ op = "replace"; path = "/icon"; value = "$DesiredLogo" }
                }
            }

            if ($Operations.Count -gt 0) {
                $Result = Invoke-au2matorPatch -BaseURL $au2mator_BaseURL -Header $au2mator_Header -Endpoint "UpdateCompany" -Id $ITAMCompany.id -Operations $Operations -Subject "company $($JSONManufacturer.short_name)"
                if ($null -ne $Result) { $CompaniesUpdated++ }
            }
        }

        Write-au2matorLog -Type INFO -Text "Manufacturers checked: $CompaniesChecked - updated: $CompaniesUpdated"
    }
    else {
        Write-au2matorLog -Type INFO -Text "Skipping manufacturer update - UpdateExistingCompanies is disabled"
    }
    #endregion UpdateExisting


    $DevicesNotInITAM = $IntuneDeviceKeys | Where-Object { -not $ITAMDeviceLookup.ContainsKey($_) } | ForEach-Object { $IntuneDeviceLookup[$_] }
    Write-au2matorLog -Type INFO -Text "Devices in Intune but not in ITAM: $($DevicesNotInITAM.count)"


    $DevicesAlreadyInITAM = $IntuneDeviceKeys | Where-Object { $ITAMDeviceLookup.ContainsKey($_) } | ForEach-Object { $IntuneDeviceLookup[$_] }
    Write-au2matorLog -Type INFO -Text "Devices already in ITAM: $($DevicesAlreadyInITAM.count)"

    $DevicesNotInIntune = $ITAMDeviceKeys | Where-Object { -not $IntuneDeviceLookup.ContainsKey($_) } | ForEach-Object { $ITAMDeviceLookup[$_] }
    Write-au2matorLog -Type INFO -Text "Devices in ITAM but no longer in Intune: $($DevicesNotInIntune.count)"



    $AllItamStatus = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetAllStatus" -Headers $au2mator_Header
    $InUseStatusID = ($AllItamStatus.items | Where-Object { $_.name -eq "In Use" }).id
    $OfflineStatusID = ($AllItamStatus.items | Where-Object { $_.name -eq "Offline" }).id



    foreach ($Device in $DevicesNotInITAM) {
        $NewModel = $false
        #Start-Sleep -Seconds 10
        #Check Model and Manufacturer in au2mator
        $ModelMatchITAM = $null
        $ModelMatchITAM = $ITAMModelLookup[$Device.model]

        if ($null -eq $ModelMatchITAM) {
            #Model does not exist in a2uamtor, check Model JSON
            $ModelMatchJSON = $null
            # Select-Object -First 1 is intentional: models.json contains models that
            # share the same key_model_intune. Without it $ModelMatchJSON would be an
            # array, and so would every field in the request body.
            $ModelMatchJSON = $JSONModels | Where-Object { $_.key_model_intune -eq $Device.model } | Select-Object -First 1


            if ($null -ne $ModelMatchJSON) {
                #Model exists in JSON but not in ITAM, so we need to create it in ITAM before we can create the device. For that we also need to check if the Manufacturer exists in ITAM, because we need the ID for the Model creation. If the Manufacturer does not exist, we need to create it first.
                $NewModel = $true
                #"HALT Model"; Start-Sleep -Seconds 10

                $ManufacturerMatchITAM = $null
                $ManufacturerMatchITAM = $ITAMCompanyLookup_ShortName[$ModelMatchJSON.manufacturer_short]

                if ($null -eq $ManufacturerMatchITAM) {
                    #Manufacturer does not exist in ITAM, create it
                    #Get Details from JSON

                    $ManafacturerDetails = $JSONManufacturerLookup[$ModelMatchJSON.manufacturer_short]

                    # Manufacturer logo only if the operator wants it. models.json only provides
                    # the link to the official manufacturer site.
                    $CompanyLogoBase64 = $null
                    if ($DownloadCompanyLogos) {
                        $CompanyLogoBase64 = Get-RemoteImageBase64 -ImageUrl $ManafacturerDetails.image_url -Subject "company $($ManafacturerDetails.short_name)" -AllowedHosts $AllowedImageHosts -TimeoutSec $ModelImageTimeoutSec
                    }

                    $ImportBody = @{
                        name           = $ManafacturerDetails.manufacturer
                        shortname      = $ManafacturerDetails.short_name
                        isManufacturer = $true
                        icon           = $CompanyLogoBase64
                    }
                    $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
                    Write-au2matorLog -Type INFO -Text "Creating Manufacturer: $($ModelMatchJSON.manufacturer) for Model: $($ModelMatchJSON.model_name)"
                    $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateCompany" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
                    Write-au2matorLog -Type INFO -Text "Created Manufacturer: $($ModelMatchJSON.manufacturer)"
                
                    foreach ($obj in $Response) {
                        $key = "$($obj.shortName)"
                        $ITAMCompanyLookup_ShortName[$key] = $obj
                    }

                    $ManufacturerMatchITAM = $ITAMCompanyLookup_ShortName[$ModelMatchJSON.manufacturer_short]

             
                }

                if ($NewModel) {
                    $ManufacturerID = $ManufacturerMatchITAM.id
                    $CategoryMatchITAM = $ITAMCategoryLookup[$ModelMatchJSON.category]
                    if ($null -ne $CategoryMatchITAM) {
                        $CategoryID = $CategoryMatchITAM.id
                    }
                    else {
                        #New ITAM Category
                        $CategoryDetails = $JSONCategorieLookup[$ModelMatchJSON.category]

                        # models.json may use a category that categories.json does not know
                        # (currently: none). Without this guard the category would be created below
                        # with name = $null and the icon handling would point at the directory instead
                        # of a file - Test-Path then reports true and
                        # ReadAllBytes throws an exception.
                        if ($null -eq $CategoryDetails) {
                            Write-au2matorLog -Type WARNING -Text "Category '$($ModelMatchJSON.category)' is used in models.json but not defined in categories.json - skipping model $($ModelMatchJSON.model_name)"
                            continue
                        }

                        # Deliberately a separate variable, NOT written back to
                        # $CategoryDetails.icon: the object lives in the lookup and would otherwise
                        # permanently carry the Base64 string instead of the file name.
                        $CategoryIconBase64 = $null
                        if ($ImportCategoryIcons) {
                            $CategoryIconBase64 = Get-CategoryIconBase64 -IconFileName $CategoryDetails.icon -IconDirectory (Join-Path $BaseDir 'icons') -CategoryName $CategoryDetails.category
                        }

                        $ImportBody = @{
        
                            name        = $CategoryDetails.category
                            description = $CategoryDetails."Description_$ImportLanguage"
                            icon        = $CategoryIconBase64
                        }
                        $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
                        Write-au2matorLog -Type INFO -Text "Creating Category: $($CategoryDetails.category) for Model: $($ModelMatchJSON.model_name)"
                        $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateCategory" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
                        Write-au2matorLog -Type INFO -Text "Created Category: $($CategoryDetails.category)"
                        foreach ($obj in $Response) {
                            $key = "$($obj.name)"
                            $ITAMCategoryLookup[$key] = $obj
                        }
                        $CategoryMatchITAM = $ITAMCategoryLookup[$ModelMatchJSON.category]
                    }
                    
                    # Model image: only if the operator explicitly wants it.
                    # models.json only provides the link to the manufacturer.
                    $ModelImageBase64 = $null
                    if ($DownloadModelImages) {
                        $ModelImageBase64 = Get-RemoteImageBase64 -ImageUrl $ModelMatchJSON.image_url -Subject "model $($ModelMatchJSON.model_name)" -AllowedHosts $AllowedImageHosts -TimeoutSec $ModelImageTimeoutSec
                    }

                    $ImportBody = @{
                        name           = $ModelMatchJSON.model_name
                        description    = $($ModelMatchJSON."Description_$ImportLanguage")
                        icon           = $ModelImageBase64
                        modelNumber    = $ModelMatchJSON.key_model_intune
                        manufacturerId = $ManufacturerID
                        categoryId     = $CategoryMatchITAM.id
                        keymodelintune = $ModelMatchJSON.key_model_intune
                    }
                    $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
                    Write-au2matorLog -Type INFO -Text "Creating Model: $($ModelMatchJSON.model_name)"
                    $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateModel" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"

                    Write-au2matorLog -Type INFO -Text "Created Model: $($ModelMatchJSON.model_name)"
                    foreach ($obj in $Response) {
                        $key = "$($obj.modelNumber)"
                        $ITAMModelLookup[$key] = $obj
                    }
                    # The model is created with modelNumber = key_model_intune, so the lookup must
                    # use it as well. With model_number the lookup came back empty for every model
                    # whose part number differs from the Intune name (Apple, ASUS, Acer, ...) -
                    # the device was silently skipped and only created on the next run.
                    $ModelMatchITAM = $ITAMModelLookup[$ModelMatchJSON.key_model_intune]
                    if ($null -eq $ModelMatchITAM) {
                        Write-au2matorLog -Type WARNING -Text "Model $($ModelMatchJSON.model_name) was created but could not be read back - device will be picked up on the next run"
                    }
                    #Start-Sleep -Seconds 5
                }
                #
            }
            else {
                Write-au2matorLog -Type WARNING -Text "Model: $($Device.model) not found in JSON for Device: $($Device.deviceName) - Serial: $($Device.serialNumber)"
            
                #Log all details to LogFileForUnknownDevices

                $LogEntry = "Device: $($Device.deviceName) - Serial: $($Device.serialNumber) - Model: $($Device.model) - Manufacturer: $($Device.manufacturer) - UserPrincipalName: $($Device.userPrincipalName)"
                Add-Content -Path $LogFileForUnknownDevices -Value $LogEntry

            }

        }


        if ($null -ne $ModelMatchITAM) {
            $AssignedUser = ""
            $AssignedUserCompany = ""
            if ($Device.userPrincipalName -ne $null) {
                $AssignedUser = $ITAMUserLookup[$Device.userPrincipalName]
            }
    

            #Check to see if we can update Icon of Model


            #Now we have the Model and Manufacturer in ITAM, we can create the Device in ITAM
            $ImportBody = @{
                modelId        = $ModelMatchITAM.id
                serialNumber   = $Device.serialNumber
                assignedToId   = $AssignedUser.id
                uniqueName     = $Device.serialNumber
                name           = $Device.deviceName
                manufacturerId = $ModelMatchITAM.manufacturer.id
                statusId       = $InUseStatusID
                        }

            # Company of the assigned user (switch $AssignCompanyFromUserToAsset)
            if ($AssignCompanyFromUserToAsset -and $AssignedUser) {
                $AssignedUserCompany = Get-ITAMUserCompanyId -UserId "$($AssignedUser.id)"
                if ($AssignedUserCompany) {
                    $ImportBody.companyId = $AssignedUserCompany
                }
            }
            $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3

            Write-au2matorLog -Type DEBUG -Text "Hardware asset payload: $ImportBodyJson"


            Write-au2matorLog -Type INFO -Text "Creating Device: $($Device.deviceName)" 
            #Start-Sleep -Seconds 10
            $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateHardwareAsset" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
            #Start-Sleep -Seconds 5
            Write-au2matorLog -Type INFO -Text "Created Device: $($Device.deviceName)"
        }

    }


    foreach ($Device in $DevicesAlreadyInITAM) {
        #Check adssigned to and set in ITAM/au2mator
      
    }




    foreach ($Device in $DevicesNotInIntune) {
        #Check if Device is In Use or Offline in ITAM, if In Use, we need to set it to Offline, because it is not in Intune anymore
        if ($Device.status.id -eq $InUseStatusID) {
            Write-au2matorLog -Type INFO -Text "Device: $($Device.name) - Serial: $($Device.serialNumber) is In Use in ITAM but not in Intune anymore, setting to Offline"

        
            $UpdateBody = @(
                @{
                    op    = "replace"
                    path  = "/statusId"
                    value = "$($OfflineStatusID)"
                }
            )

            $UpdateBodyJson = ConvertTo-Json -InputObject $UpdateBody -Depth 10



            Write-au2matorLog -Type INFO -Text "Setting Device: $($Device.name) - Serial: $($Device.serialNumber) to Offline"
            $Response = Invoke-RestMethod -Method PATCH -Uri "$($au2mator_BaseURL)/itam_AssetApi/UpdateHardwareAsset/$($Device.id)" -Headers $au2mator_Header -Body $UpdateBodyJson -ContentType "application/json; charset=utf-8"
            Write-au2matorLog -Type INFO -Text "Set Device: $($Device.name) - Serial: $($Device.serialNumber) to Offline"
        }
    }

    #region AssignCompanyToAssets
    # Existing assets: take over the company of the assigned user.
    # GetAllHardwareAssets does not return the asset company, so the asset is read
    # individually and updated only if its company differs from the user's.
    # Assets that were just created above already carry the company in their payload.
    if ($AssignCompanyFromUserToAsset) {
        Write-au2matorLog -Type INFO -Text "Assigning the company of the assigned user to existing assets"
        $AssetsChecked = 0
        $AssetsUpdated = 0

        foreach ($Asset in $AllITAMAssets) {
            if ($null -eq $Asset.assignedTo -or [string]::IsNullOrWhiteSpace("$($Asset.assignedTo.id)")) { continue }

            # User without a company: leave the asset alone
            $UserCompanyId = Get-ITAMUserCompanyId -UserId "$($Asset.assignedTo.id)"
            if ([string]::IsNullOrWhiteSpace("$UserCompanyId")) { continue }

            $AssetsChecked++
            try {
                $AssetDetails = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetHardwareAsset?Id=$($Asset.id)" -Headers $au2mator_Header
                if ("$($AssetDetails.company.id)" -eq "$UserCompanyId") { continue }

                $CompanyOperations = @(@{ op = "replace"; path = "/companyId"; value = "$UserCompanyId" })
                $Result = Invoke-au2matorPatch -BaseURL $au2mator_BaseURL -Header $au2mator_Header -Endpoint "UpdateHardwareAsset" -Id $Asset.id -Operations $CompanyOperations -Subject "asset $($Asset.name) - Serial: $($Asset.serialNumber)"
                if ($null -ne $Result) { $AssetsUpdated++ }
            }
            catch {
                Write-au2matorLog -Type ERROR -Text "Could not check the company of asset $($Asset.name) - Serial: $($Asset.serialNumber): $($_.Exception.Message)"
            }
        }

        Write-au2matorLog -Type INFO -Text "Company from user: $AssetsChecked assets checked, $AssetsUpdated updated"
    }
    #endregion AssignCompanyToAssets

    #endregion SyncClientAssets



































    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $IntuneScripts_clientID
        Client_Secret = $IntuneScripts_secret
    }
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
    $header = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }

    Write-au2matorLog -Type INFO -Text "Getting script results"
    $ScriptResults = Get-AzureResourcePaging -URL "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/3ae6833f-37b7-4175-a11f-72e38490ec8d/deviceRunStates?`$filter=detectionState eq 'success'&`$select=id,lastStateUpdateDateTime,preRemediationDetectionScriptOutput" -AuthHeader $header

    $monitors = $ScriptResults | ForEach-Object {
        $item = $_
        $output = $item.preRemediationDetectionScriptOutput | ConvertFrom-Json
        $output | Select-Object *,
        @{Name = 'id'; Expression = { $item.id } },
        @{Name = 'lastStateUpdateDateTime'; Expression = { $item.lastStateUpdateDateTime } } |
        Where-Object { $_.Status -eq $null }
    }

    Write-au2matorLog -Type INFO -Text "Getting saved data"
    $query = "SELECT * FROM [au2mator-help].dbo.MonitorDeviceCollection"
    $SavedData = ExecuteSqlQuery -sqlquery $query
    
    Write-au2matorLog -Type INFO -Text "Creating lookup tables"
    $monitorLookup = @{}
    foreach ($monitor in $monitors) {
        if ($monitor.SerialNumber) {
            $monitorLookup[$monitor.SerialNumber] = $monitor
        }
    }

    $savedLookup = @{}
    foreach ($saved in $SavedData) {
        if ($saved.SerialNumber) {
            $savedLookup[$saved.SerialNumber] = $saved
        }
    }

    Write-au2matorLog -Type INFO -Text "Inserting Monitors"
    foreach ($monitor in $monitors) {
        if ($monitor.SerialNumber -and $savedLookup.ContainsKey($monitor.SerialNumber)) {
            if ($savedLookup[$monitor.SerialNumber].ComputerSerialNumber -eq $monitor.ComputerSN -and [DateTime]$savedLookup[$monitor.SerialNumber].LastUpdate -ne ([datetimeoffset]$monitor.lastStateUpdateDateTime).UtcDateTime) {
                $query = "UPDATE [au2mator-help].dbo.MonitorDeviceCollection set LastUpdate = '$($monitor.lastStateUpdateDateTime)' where ComputerSerialNumber = '$($monitor.ComputerSN)' and SerialNumber = '$($monitor.SerialNumber)'"
                ExecuteSqlQuery -sqlquery $query
            }
        }
        if ($monitor.SerialNumber -and -not $savedLookup.ContainsKey($monitor.SerialNumber)) {
            $query = "INSERT INTO [au2mator-help].dbo.MonitorDeviceCollection (ComputerName, ComputerSerialNumber, ManufacturerCode, Model, SerialNumber, PNPDeviceID, ScriptID, LastUpdate) values ('$($monitor.ComputerName)','$($monitor.ComputerSN)','$($monitor.ManufacturerCode)','$($monitor.Model)','$($monitor.SerialNumber)','$($monitor.PNPDeviceID)','$($monitor.id)','$($monitor.lastStateUpdateDateTime)')"
            ExecuteSqlQuery -sqlquery $query
        }
    }
}
catch {
    Write-au2matorLog -Type ERROR -Text "Error: $Error"
}
#endregion Script

#region Return
Write-au2matorLog -Type INFO -Text "Service finished"
Clear-Logs 





# Note: This used to hold a one-off, commented-out DEV->PROD migration block.
# Removed because it contained hard-coded customer URLs, a local file path and
# an API key in plain text. One-off migrations belong in a separate, non-public
# script.

