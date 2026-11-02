

$a2m_Environment = "local"          # local | AAHybrid | AAnoHybrid
$a2m_LogLevel = "INFO"              # DEBUG | INFO | WARNING | ERROR
$a2m_LogLocation = "Local"             # Local | Hybrid | Azure
$a2m_LogPath = "C:\_au2mator\_SourceControl\au2mator\PS-Service\LOGS\TASKS"
$a2m_LogFileName = "TASK_0011_SyncEntraAssets"
$a2m_DeleteAfterDays = 30
$global:a2m_AZKVResponse = $null
$a2m_AZKeyVaultEnvironment = "Hybrid"    # Hybrid | OnPrem | Azure
$a2m_AZKeyVaultEnvironmentHybrid = "AzureVM"
$a2m_AZKeyVaultName = "AA-Prod-au2matorInternal"

#endregion Environment


#region Functions

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


#region Script
Write-au2matorLog -Type INFO -Text "Start Script"
try {


    #Region SyncUsers
    #Get All Users from Azure
    $Entra_header = Get-GraphHeader -ClientID $Entra_AppReg_clientID -TenantID $Entra_AppReg_tenantID -Secret $Entra_AppReg_Clientsecret 

    $Resource = "users"
    $uri = "https://graph.microsoft.com/v1.0/$($Resource)?`$select=displayName,givenName,postalCode,identities,surname,userPrincipalName,companyName,accountEnabled,onPremisesExtensionAttributes"
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
            companyId    = ($AllITAMCompanies | Where-Object { $_.shortName -eq $User.onPremisesExtensionAttributes.extensionAttribute15 }).id
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
        If (($AllITAMCompanies | Where-Object { $_.shortName -eq $User.onPremisesExtensionAttributes.extensionAttribute15 }).name -ne $ITAMUserObject.company.name) {
            #$UpdateBody.companyId = ($AllITAMCompanies | Where-Object { $_.shortName -eq $User.onPremisesExtensionAttributes.extensionAttribute15 }).id

            #checkl if we have a company with the shortName in ITAM
            If (($AllITAMCompanies | Where-Object { $_.shortName -eq $User.onPremisesExtensionAttributes.extensionAttribute15 }).id) {
                
                $UpdateCompany = $true
            }
            else {
                Write-au2matorLog -Type WARNING -Text "Company with shortName $($User.onPremisesExtensionAttributes.extensionAttribute15) not found in ITAM for user $($User.userPrincipalName)"
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
                        value = ($AllITAMCompanies | Where-Object { $_.shortName -eq $User.onPremisesExtensionAttributes.extensionAttribute15 }).id
                    }
                }
            )




            $UpdateBodyJson = $UpdateBody | ConvertTo-Json -Depth 10
            $Update_URL = "$($au2mator_BaseURL)/itam_AssetApi/UpdateUser/$($ITAMUser.id)"
            $UpdateBodyJson
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


    $IntuneScopeTageLookup = @{}

    $Scopes = Invoke-RestMethod -Uri  "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" -Headers $Intune_header -Method Get

    foreach ($Scope in $Scopes.value) {
        $key = "$($Scope.id)"
        $IntuneScopeTageLookup[$key] = $Scope
    }



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
                    release_year       = $_.release_year
                    icon               = $_.icon
                }
            }
        }
    }
    $JSONModels.count


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

    $AllITAMAssets = get-au2matorAPIPaging -URL "$($au2mator_BaseURL)/itam_AssetAPI/GetAllHArdwareAssets" -Header $au2mator_Header
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



    $DevicesNotInITAM = $IntuneDeviceKeys | Where-Object { -not $ITAMDeviceLookup.ContainsKey($_) } | ForEach-Object { $IntuneDeviceLookup[$_] }
    $DevicesNotInITAM.count


    $DevicesAlreadyInITAM = $IntuneDeviceKeys | Where-Object { $ITAMDeviceLookup.ContainsKey($_) } | ForEach-Object { $IntuneDeviceLookup[$_] }
    $DevicesAlreadyInITAM.count

    $DevicesNotInIntune = $ITAMDeviceKeys | Where-Object { -not $IntuneDeviceLookup.ContainsKey($_) } | ForEach-Object { $ITAMDeviceLookup[$_] }
    $DevicesNotInIntune.count



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
            $ModelMatchJSON = $JSONModels | Where-Object { $_.key_model_intune -eq $Device.model }


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

                    $ImportBody = @{
                        name           = $ManafacturerDetails.manufacturer
                        shortname      = $ManafacturerDetails.short_name
                        isManufacturer = $true
                    }
                    $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
                    Write-Host "Creating Manufacturer: $($ModelMatchJSON.manufacturer) for Model: $($ModelMatchJSON.model_name)"
                    $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateCompany" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
                    Write-Host "Created Manufacturer: $($ModelMatchJSON.manufacturer)"
                
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


                        #Icon to BAse64
                        $IconPath = "$BaseDir\Icons\$($CategoryDetails.icon)"
                        if (Test-Path -Path $IconPath) {
                            $IconBytes = [System.IO.File]::ReadAllBytes($IconPath)
                            $IconBase64 = [Convert]::ToBase64String($IconBytes)
                            $CategoryDetails.icon = $IconBase64
                        }
                        else {
                            Write-Host "Icon not found for Category: $($CategoryDetails.category) - Path: $IconPath"
                            $CategoryDetails.icon = $null
                        }



                        $ImportBody = @{
        
                            name        = $CategoryDetails.category
                            description = $CategoryDetails."Description_$ImportLanguage"
                            icon        = $CategoryDetails.icon
                        }
                        $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
                        Write-Host "Creating Category: $($CategoryDetails.category) for Model: $($ModelMatchJSON.model_name)"
                        $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateCategory" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
                        Write-Host "Created Category: $($CategoryDetails.category)"
                        foreach ($obj in $Response) {
                            $key = "$($obj.name)"
                            $ITAMCategoryLookup[$key] = $obj
                        }
                        $CategoryMatchITAM = $ITAMCategoryLookup[$ModelMatchJSON.category]
                    }
                    
                    #Icon to BAse64
                    $IconPath = "$BaseDir\icons\$($ModelMatchJSON.icon)"
                    try {
                        if ((Test-Path -Path $IconPath) -and $ModelMatchJSON.icon -like "*.png") {
           
                            $IconBytes = [System.IO.File]::ReadAllBytes($IconPath)
                            $IconBase64 = [Convert]::ToBase64String($IconBytes)
                            $ModelMatchJSON.icon = $IconBase64
                        }
                        else {
                            Write-Host "Icon not found for Model: $($ModelMatchJSON.model_name) - Path: $IconPath"
                            $ModelMatchJSON.icon = $null
                        }
                    }
                    catch {
                        Write-Host "Icon not found for Model: $($ModelMatchJSON.model_name) - Path: $IconPath"
                        $ModelMatchJSON.icon = $null
                    }    

                    $ImportBody = @{
                        name           = $ModelMatchJSON.model_name
                        description    = $($ModelMatchJSON."Description_$ImportLanguage")
                        icon           = $ModelMatchJSON.icon
                        modelNumber    = $ModelMatchJSON.key_model_intune
                        manufacturerId = $ManufacturerID
                        categoryId     = $CategoryMatchITAM.id
                        keymodelintune = $ModelMatchJSON.key_model_intune
                    }
                    $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3
                    Write-Host "Creating Model: $($ModelMatchJSON.model_name)"
                    $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateModel" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"

                    Write-Host "Created Model: $($ModelMatchJSON.model_name)"
                    foreach ($obj in $Response) {
                        $key = "$($obj.modelNumber)"
                        $ITAMModelLookup[$key] = $obj
                    }
                    $ModelMatchITAM = $ITAMModelLookup[$ModelMatchJSON.model_number]
                    #Start-Sleep -Seconds 5
                }
                #
            }
            else {
                Write-au2matorLog -Type WARNING -Text "Model: $($Device.model) not found in JSON for Device: $($Device.deviceName) - Serial: $($Device.serialNumber)"
            
                #Logging to LogFileForUnknownDevices with alle Infos

                $LogEntry = "Device: $($Device.deviceName) - Serial: $($Device.serialNumber) - Model: $($Device.model) - Manufacturer: $($Device.manufacturer) - UserPrincipalName: $($Device.userPrincipalName) - Company: $($GraphLookup[$Device.userPrincipalName].onPremisesExtensionAttributes.extensionAttribute15)"
                Add-Content -Path $LogFileForUnknownDevices -Value $LogEntry

            }

        }


        if ($null -ne $ModelMatchITAM) {
            $AssignedUser = ""
            $AssignedUserCompany = ""
            if ($Device.userPrincipalName -ne $null) {
                $AssignedUser = $ITAMUserLookup[$Device.userPrincipalName]
                $AssignedUserCompany = $GraphLookup[$Device.userPrincipalName].onPremisesExtensionAttributes.extensionAttribute15
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
                companyId      = ($AllITAMCompanies | Where-Object { $_.shortName -eq $AssignedUserCompany }).id
            }
            $ImportBodyJson = $ImportBody | ConvertTo-Json -Depth 3

            $ImportBodyJson


            Write-Host "Creating Device: $($Device.deviceName)" 
            #Start-Sleep -Seconds 10
            $Response = Invoke-RestMethod -Method POST -Uri "$($au2mator_BaseURL)/itam_AssetApi/CreateHardwareAsset" -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
            #Start-Sleep -Seconds 5
            Write-Host "Created Device: $($Device.deviceName)"
        }

    }


    foreach ($Device in $DevicesAlreadyInITAM) {
        #Check adssigned to and set in ITAM/au2mator
        $ITAMDevice = $ITAMDeviceLookup[$Device.serialNumber]
        #$Device.userPrincipalName

        #$ITAMDevice.assignedTo.upn
        $ItamObjectDetails = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetHardwareAsset?id=$($ITAMDevice.id)" -Headers $au2mator_Header
        #$ItamObjectDetails.serialNumber
        if ($Device.userPrincipalName.Length -eq 0) {
            #Assigned to is empty in both, so set company to Intune ScopeTag and clear Location in ITAM
            #"LEER";
            #Asset Location leeren

            #Get ScopeDtag from Entra
            $DeviceDetails = Invoke-RestMethod -Uri  "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($Device.id)?`$select=roleScopeTagIds" -Headers $Intune_header -Method Get
            $ScopeTagIDs = $DeviceDetails.roleScopeTagIds

            #Get ScopeTag Names from Entra
            $IntuneScopeTageLookup[$ScopeTagIDs[0]].displayName
            $ItamCompanyObject = $ITAMCompanyLookup_ShortName[$IntuneScopeTageLookup[$ScopeTagIDs[0]].displayName]


            if ($ItamObjectDetails.company.id -ne $ItamCompanyObject.id -or $ItamObjectDetails.location.id -ne $null) {
                #Update Company in ITAM
                Write-Host "Updating Company in ITAM for Device: $($Device.deviceName) - Serial: $($Device.serialNumber)"
                #Start-Sleep -Seconds 10
                $ImportBody = @(
                    @{
                        op    = "replace"
                        path  = "/companyId"
                        value = "$($ItamCompanyObject.id)"
                    },
                    @{
                        op    = "replace"
                        path  = "/locationId"
                        value = ""
                    }, @{
                        op    = "replace"
                        path  = "/assignedToId"
                        value = ""
                    }
                ) 

                $ImportBodyJson = ConvertTo-Json -InputObject $ImportBody -Depth 10

                $Response = Invoke-RestMethod -Method PATCH -Uri "$($au2mator_BaseURL)/itam_AssetApi/UpdateHardwareAsset/$($ITAMDevice.id)" `
                    -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json-patch+json" 
            }

    
        }
        else {
            #Update AssignedTo in ITAM
            #Write-Host "Passt nicht: $($Device.userPrincipalName)"
            #Write-Host "ITAM ist: $($ITAMDevice.assignedTo.upn)"
            #Write-Host "Intune ist: $($Device.userPrincipalName)"

            $ITAMUser = $ITAMUserLookup[$Device.userPrincipalName]
            try {
                $ItamUserObjectDetails = Invoke-RestMethod -Method GET -Uri "$($au2mator_BaseURL)/itam_AssetApi/GetUser?id=$($ITAMUser.id)" -Headers $au2mator_Header
                $Update = $false
                $ImportBody = @()

                if ($ItamUserObjectDetails.company.id -ne $ItamObjectDetails.company.id -or $ItamUserObjectDetails.location.id -ne $ItamObjectDetails.location.id) {
                    $Update = $true
                    Write-Host "Updating Company and Location in ITAM for Device: $($Device.deviceName) - Serial: $($Device.serialNumber)"
                    #Start-Sleep -Seconds 10
                    $ImportBody += @(
           
                        @{
                            op    = "replace"
                            path  = "/companyId"
                            value = "$($ItamUserObjectDetails.company.id)"
                        },
                        @{
                            op    = "replace"
                            path  = "/locationId"
                            value = "$($ItamUserObjectDetails.location.id)"
                        }
                    )               
                }

                #Check AssignedTo in ITAM and Intune, if not the same, update in ITAM
                if ($ITAMDevice.assignedTo.upn -ne $Device.userPrincipalName) {
                    $Update = $true
                    Write-Host "Updating AssignedTo in ITAM for Device: $($Device.deviceName) - Serial: $($Device.serialNumber)"
                    $ImportBody += @(
                        @{
                            op    = "replace"
                            path  = "/assignedToId"
                            value = "$($ITAMUser.id)"
                        }
                    )
                }

                if ($Update) {
                    Write-Host "Updating Device: $($Device.deviceName) - Serial: $($Device.serialNumber) in ITAM"
                    $ImportBodyJson = ConvertTo-Json -InputObject $ImportBody -Depth 10

                    $Response = Invoke-RestMethod -Method PATCH -Uri "$($au2mator_BaseURL)/itam_AssetApi/UpdateHardwareAsset/$($ITAMDevice.id)" `
                        -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json-patch+json" 

                }
                else {
                    #Write-Host "No Update needed for Device: $($Device.deviceName) - Serial: $($Device.serialNumber) in ITAM"
                }  
            }
            catch {
                Write-Host "Error getting ITAM User Details for Device: $($Device.deviceName) - Serial: $($Device.serialNumber) - User: $($Device.userPrincipalName) - Error: $($_.Exception.Message)"
            }
       
        }
    }




    foreach ($Device in $DevicesNotInIntune) {
        #Check if Device is In Use or Offline in ITAM, if In Use, we need to set it to Offline, because it is not in Intune anymore
        if ($Device.status.id -eq $InUseStatusID) {
            Write-Host "Device: $($Device.name) - Serial: $($Device.serialNumber) is In Use in ITAM but not in Intune anymore, setting to Offline"

        
            $UpdateBody = @(
                @{
                    op    = "replace"
                    path  = "/statusId"
                    value = "$($OfflineStatusID)"
                }
            )

            $UpdateBodyJson = ConvertTo-Json -InputObject $UpdateBody -Depth 10



            Write-Host "Setting Device: $($Device.name) - Serial: $($Device.serialNumber) to Offline"
            $Response = Invoke-RestMethod -Method PATCH -Uri "$($au2mator_BaseURL)/itam_AssetApi/UpdateHardwareAsset/$($Device.id)" -Headers $au2mator_Header -Body $UpdateBodyJson -ContentType "application/json; charset=utf-8"
            Write-Host "Set Device: $($Device.name) - Serial: $($Device.serialNumber) to Offline"
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
        $DEV_Company.country

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
        Write-Host "Importing Company: $($DEV_Company.name) - $($DEV_Company.shortName) - $($PROD_Country.name)"
        $Response = Invoke-RestMethod -Method POST -Uri $Post_URL -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
        Write-Host "Imported Company: $($DEV_Company.name) - Response: $($Response.message)"


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
    Write-Host "Importing Location: $($TargetLocation.name) - $($PROD_Country.name)"
    $Response = Invoke-RestMethod -Method POST -Uri $Post_URL -Headers $au2mator_Header -Body $ImportBodyJson -ContentType "application/json; charset=utf-8"
    Write-Host "Imported Location: $($TargetLocation.name) - Response: $($Response.message)"







    
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
            Write-Host "Updated User: $($User.upn) - Response: $($Response.message)"




        }



    }
}







#>
