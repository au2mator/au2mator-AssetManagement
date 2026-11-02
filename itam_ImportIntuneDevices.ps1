

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
        Holt ein Bild von einer offiziellen Herstellerseite (Feld image_url aus
        models.json - fuer Modelle wie fuer Hersteller) und gibt es als Base64
        zurueck.

        Dieses Repository hostet KEINE Hersteller-Bilder oder -Logos. Hier wird
        nur ein Link verfolgt - und auch das nur, wenn der Betreiber es
        ausdruecklich aktiviert. Die Bilder gehoeren den jeweiligen Herstellern.

        Faehrt der Download gegen die Wand, wird das protokolliert und $null
        zurueckgegeben. Ein fehlendes Bild darf den Import NIE abbrechen.
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
        Schickt eine JSON-Patch-Operation an die au2mator-API.
        Alle Update-Endpunkte folgen demselben Muster:
          PATCH <BaseURL>/itam_AssetApi/<Endpoint>/<id>
          ContentType application/json-patch+json
          Body = Array aus @{ op = "replace"; path = "/feld"; value = "..." }
        Belegt durch die OpenAPI-Spec fuer UpdateCategory, UpdateCompany,
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

function Get-CategoryIconBase64 {
    <#
        Laedt ein Kategorie-Icon aus dem lokalen icons-Ordner als Base64.
        Diese Icons stammen aus au2mators eigenem Icon-Set und liegen im
        Repository - hier wird nichts von fremden Servern geholt.
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

    # Leaf-Pruefung: ohne sie wuerde ein leerer Dateiname auf das Verzeichnis
    # selbst zeigen, Test-Path true liefern und ReadAllBytes eine Exception werfen.
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

#region Image Settings
# Kategorie-Icons stammen aus au2mators eigenem Icon-Set und liegen als Dateien
# im Repository. Unkritisch, daher standardmaessig aktiv.
$ImportCategoryIcons = $true

# Modellbilder sind NICHT Teil dieses Repositories. models.json enthaelt nur
# einen Link auf das Bild beim Hersteller (Feld image_url). Wird dieser Schalter
# aktiviert, laedt der Import das Bild vom Server des Herstellers und legt es in
# DIESER au2mator-Installation ab.
#
# Das ist bewusst eine Entscheidung des Betreibers und deshalb standardmaessig
# AUS: die Bilder gehoeren den jeweiligen Herstellern, nicht au2mator. Wer den
# Schalter umlegt, muss sich selbst vergewissern, die noetigen Rechte zu haben.
$DownloadModelImages = $false
$ModelImageTimeoutSec = 15

# Herstellerlogos. models.json hinterlegt pro Hersteller einen Link auf das
# Logo auf der offiziellen Herstellerseite. Gleiche Ueberlegung wie bei den
# Modellbildern: das Logo gehoert dem Hersteller, wir verlinken nur.
$DownloadCompanyLogos = $true

# Bestehende Kategorien, Modelle und Hersteller in ITAM gegen die JSON
# abgleichen und Beschreibung bzw. Bild nachziehen, wenn sie abweichen.
# Standardmaessig AUS: wer das aktiviert, laesst die JSON gewinnen und
# ueberschreibt damit ggf. Aenderungen, die jemand in au2mator gemacht hat.
# Es wird ausschliesslich bei echter Abweichung geschrieben.
$UpdateExistingCategories = $true
$UpdateExistingModels = $true
$UpdateExistingCompanies = $true

# Von diesen Hosts darf ein Bild geladen werden. Ausschliesslich offizielle
# Herstellerdomains - keine Haendler, keine Logo-Sammlungen, keine Spiegel.
# Wer models.json um weitere Hersteller ergaenzt, traegt deren Domain hier ein.
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
    'www.fujitsu.com', 'www.poly.com', 'www.alienware.com', 'step-solutions.de'
)
#endregion Image Settings


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


    #Baumit Company Details
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

    # Endpunktname laut OpenAPI-Spec: GetAllHardwareAssets
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
    # Bestehende Kategorien und Modelle gegen die JSON abgleichen.
    #
    # Bewusst EIGENE Schleifen vor der Geraeteverarbeitung: die Anlage-Logik
    # weiter unten haengt in "foreach ($Device in $DevicesNotInITAM)" und der
    # Kategorie-Zweig zusaetzlich in "if ($NewModel)". Dort eingehaengt wuerde
    # ein Update bestehende Objekte praktisch nie erreichen - die existieren ja
    # gerade dann, wenn auch die Geraete schon in ITAM sind.

    if ($UpdateExistingCategories) {
        Write-au2matorLog -Type INFO -Text "Checking existing categories against JSON"
        $CategoriesUpdated = 0
        $CategoriesChecked = 0

        foreach ($JSONCategory in $JSONCategories.categories) {
            $ITAMCategory = $ITAMCategoryLookup[$JSONCategory.category]
            if ($null -eq $ITAMCategory) { continue }   # neu -> legt die Anlage-Logik an
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
            if ($null -eq $ITAMModel) { continue }      # neu -> legt die Anlage-Logik an
            $ModelsChecked++

            $Operations = @()

            $DesiredDescription = $JSONModel."Description_$ImportLanguage"
            if (-not [string]::IsNullOrWhiteSpace($DesiredDescription) -and $DesiredDescription -ne $ITAMModel.description) {
                $Operations += @{ op = "replace"; path = "/description"; value = "$DesiredDescription" }
            }

            # Bild nur nachtragen, wenn in ITAM noch keines hinterlegt ist.
            # Ein Vergleich wuerde bedeuten, bei JEDEM Lauf fuer JEDES Modell
            # das Bild beim Hersteller zu laden - das waeren hunderte Abrufe
            # pro Durchlauf, nur um dann meist nichts zu tun.
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
            if ($null -eq $ITAMCompany) { continue }   # neu -> legt die Anlage-Logik an
            $CompaniesChecked++

            $Operations = @()

            if (-not [string]::IsNullOrWhiteSpace($JSONManufacturer.manufacturer) -and $JSONManufacturer.manufacturer -ne $ITAMCompany.name) {
                $Operations += @{ op = "replace"; path = "/name"; value = "$($JSONManufacturer.manufacturer)" }
            }

            # Logo wie beim Modell nur nachtragen, wenn in ITAM noch keines
            # hinterlegt ist - sonst laedt jeder Lauf alle Logos neu.
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
            # Select-Object -First 1 ist Absicht: in models.json gibt es Modelle,
            # die sich denselben key_model_intune teilen. Ohne das waere
            # $ModelMatchJSON ein Array und jedes Feld im Request-Body ebenfalls.
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

                    # Herstellerlogo nur, wenn der Betreiber es will. models.json
                    # liefert lediglich den Link auf die offizielle Herstellerseite.
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

                        # models.json kann eine Kategorie verwenden, die
                        # categories.json nicht kennt (aktuell: Server). Ohne
                        # diesen Guard wuerde unten mit name = $null angelegt und
                        # das Icon-Handling auf das Verzeichnis statt auf eine
                        # Datei zeigen - Test-Path meldet dann true und
                        # ReadAllBytes wirft eine Exception.
                        if ($null -eq $CategoryDetails) {
                            Write-au2matorLog -Type WARNING -Text "Category '$($ModelMatchJSON.category)' is used in models.json but not defined in categories.json - skipping model $($ModelMatchJSON.model_name)"
                            continue
                        }

                        # Bewusst in eine eigene Variable, NICHT zurueck nach
                        # $CategoryDetails.icon: das Objekt liegt im Lookup und
                        # wuerde sonst dauerhaft den Base64-String statt des
                        # Dateinamens tragen.
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
                    
                    # Modellbild: nur wenn der Betreiber es ausdruecklich will.
                    # models.json liefert lediglich den Link zum Hersteller.
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
                    # Angelegt wird mit modelNumber = key_model_intune, also muss
                    # auch damit nachgeschlagen werden. Mit model_number lief der
                    # Lookup bei jedem Modell ins Leere, dessen Artikelnummer von
                    # der Intune-Bezeichnung abweicht (Apple, ASUS, Acer, ...) -
                    # das Geraet wurde dann stillschweigend uebersprungen und erst
                    # im naechsten Lauf angelegt.
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
            
                #Logging to LogFileForUnknownDevices with alle Infos

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





<#

#Temp Migrations

#CompanyName from DEV to PROD via API

$a2m_API_Key = Get-AZKeyVaultSecret  -SecretName "au2mator-API-Key-AssetImport"
$au2mator_BaseURL = "https://automation.baumit.app/api"
$au2mator_Header = @{
    'Content-Type' = "application/json"
    'X-Api-Key'    = "$a2m_API_Key"     
    'accept'       = "*/*"
}


$a2m_DEV_API_Key = "REMOVED-ROTATED-CREDENTIAL"
$au2mator_DEV_BaseURL = "https://automationdev.baumit.app/api"
$au2mator_DEV_Header = @{
    'Content-Type' = "application/json"
    'X-Api-Key'    = "$a2m_DEV_API_Key"
    'accept'       = "*/*"
}


$DEV_Companies = get-au2matorAPIPaging -URL "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetAllCompanies" -Header $au2mator_DEV_Header
$PROD_Companies = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllCompanies" -Header $au2mator_Header

$PROD_Countries = Get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllCountries" -Header $au2mator_Header


foreach ($company in $DEV_Companies) {
    if ($company.shortName -like "B*") {
        #"HALT"; Start-Sleep -Seconds 10
        #GetCompany from DEV for Country Info
        $DEV_Company = Invoke-RestMethod -Method GET -Uri "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetCompany?Id=$($company.id)" -Headers $au2mator_DEV_Header
        Write-au2matorLog -Type DEBUG -Text "Company country: $($DEV_Company.country)"

        #Get Country from Prod
        $PROD_Country = $PROD_Countries | Where-Object { $_.name -eq $DEV_Company.country.name }

        $LogoURL = "C:\Temp\baumit-logo-png_seeklogo-17175.png"
        $IconBytes = [System.IO.File]::ReadAllBytes($LogoURL)
        $IconBase64 = [Convert]::ToBase64String($IconBytes)
        $CategoryDetails = $IconBase64

        #Now Create Company in PROD
        $Post_URL = "$($au2mator_BaseURL)/itam_AssetApi/CreateCompany"
        $ImportBody = @{
            name      = $DEV_Company.name
            shortName = $DEV_Company.shortName
            countryId = $PROD_Country.id
            logoURL   = $CategoryDetails

        }
        $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
        Write-au2matorLog -Type INFO -Text "Importing Company: $($DEV_Company.name) - $($DEV_Company.shortName) - $($PROD_Country.name)"
        $Response = Invoke-RestMethod -Method POST -Uri $Post_URL -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
        Write-au2matorLog -Type INFO -Text "Imported Company: $($DEV_Company.name) - Response: $($Response.message)"


    }
}



#Locations

$DEV_Locations = get-au2matorAPIPaging -URL "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetAllLocations" -Header $au2mator_DEV_Header


foreach ($location in $DEV_Locations) {

    #build Body

    #{
    #  "name": "string",
    #  "description": "string",
    #  "address": "string",
    #  "city": "string",
    #  "state": "string",
    #  "postalCode": "string",
    #  "companyIds": [
    #    "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    #  ],
    #  "countryId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    #
    #}
    


    #Get Location for Details
    $TargetLocation = Invoke-RestMethod -Method GET -Uri "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetLocation?Id=$($location.id)" -Headers $au2mator_DEV_Header

    #New Location with related Country and Companies
    $PROD_Country = $PROD_Countries | Where-Object { $_.name -eq $location.country.name }
    $PROD_CompanyIDs = @()
    foreach ($Entry in $location.companies.name) {
        $PROD_Company = $PROD_Companies | Where-Object { $_.name -eq $Entry }
        if ($PROD_Company) {
            $PROD_CompanyIDs += $PROD_Company.id
        }
    }

    $Post_URL = "$($au2mator_BaseURL)/itam_AssetApi/CreateLocation"
    $ImportBody = @{
        name        = $TargetLocation.name
        description = $TargetLocation.description
        address     = $TargetLocation.address
        city        = $TargetLocation.city
        state       = $TargetLocation.state
        postalCode  = $TargetLocation.postalCode
        companyIds  = $PROD_CompanyIDs
        countryId   = $PROD_Country.id

    }
    $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
    Write-au2matorLog -Type INFO -Text "Importing Location: $($TargetLocation.name) - $($PROD_Country.name)"
    $Response = Invoke-RestMethod -Method POST -Uri $Post_URL -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
    Write-au2matorLog -Type INFO -Text "Imported Location: $($TargetLocation.name) - Response: $($Response.message)"







    
}



#Sync User Location from dEV to PROD
$DEV_Users = get-au2matorAPIPaging -URL "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetAllUsers" -Header $au2mator_DEV_Header
$PROD_Users = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllUsers" -Header $au2mator_Header

$DEV_LOCATIONS = get-au2matorAPIPaging -URL "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetAllLocations" -Header $au2mator_DEV_Header
$PROD_LOCATIONS = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetApi/GetAllLocations" -Header $au2mator_Header


$Dev_Users_lookup = @{}
foreach ($User in $DEV_Users) {
    $Dev_Users_lookup[$User.upn] = $User
}

foreach ($User in $PROD_Users) {

    $DevUserObject = $Dev_Users_lookup[$User.upn]

    if ($DevUserObject) {
        $DevUserGetObject = Invoke-RestMethod -Method GET -Uri "$($au2mator_DEV_BaseURL)/itam_AssetApi/GetUser?Id=$($DevUserObject.id)" -Headers $au2mator_DEV_Header


        if ($DevUserGetObject.location) {
            "Location"; Start-Sleep -Seconds 10

            #$PRODUserGetObjekt = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetUser?Id=$($User.id)" -Headers $au2mator_Header

            $PROD_Location = $PROD_LOCATIONS | Where-Object { $_.name -eq $DevUserGetObject.location.name }

            #Update user in PROD
            $Update_URL = "$($au2mator_BaseURL)/itam_AssetApi/UpdateUser/$($User.id)"



            $UpdateBody = @(
                @{
                    op    = "replace"
                    path  = "/LocationID"
                    value = "$($PROD_Location.id)"
                },
                @{
                    op    = "replace"
                    path  = "/locationId"
                    value = "$($PROD_Location.id)"
                }            
            ) 



            $UpdateBodyJson = $UpdateBody | ConvertTo-Json -Depth 10
            $Response = Invoke-RestMethod -Method PATCH -Uri $Update_URL -Headers $au2mator_Header -Body $UpdateBodyJson -ContentType "application/json; charset=utf-8"
            Write-au2matorLog -Type INFO -Text "Updated User: $($User.upn) - Response: $($Response.message)"




        }



    }
}







#>
