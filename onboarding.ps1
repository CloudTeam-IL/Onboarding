param(
    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $tenantId,

    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $readersPrincipalId,

    [string]
    [Parameter()]
    $proactivePrincipalId = 'Disabled'
)
#Requires -Modules Az, Microsoft.Graph

## Access Token
function Get-AccessToken {
    param (
        [string]
        [Parameter()]
        $ResourceTypeName = 'MSGraph'
    )
    $token = Get-AzAccessToken -ResourceTypeName $ResourceTypeName
    return $token
}
function Connect-AAD {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $AccessToken
    )
    $MSGraphConnection = Connect-MgGraph -AccessToken $AccessToken
    return $MSGraphConnection
}
## Get User's object id - Input UserId - $ARM.Context.Account.Id
function Get-ObjectId {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $UserId
    )
    $user = Get-MgUser -All | Where-Object { $_.DisplayName -eq $UserId -or $_.UserPrincipalName -like $UserId }
    return $user
}
function Get-UserPemissions {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $UserId
    )
    $response = $null
    $uri = "https://graph.microsoft.com/beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=principalId eq '$UserId'"
    $method = 'GET'
    $headers = @{'ConsistencyLevel' = 'eventual' }
    $response = (Invoke-MgGraphRequest -Uri $uri -Headers $headers -Method $method -Body $null).value
    return $response
}
function checkRole {
    param (
        [Parameter()]
        $roles,
        [string]
        [Parameter()]
        $roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'
    )
    if (roleDefinitionId -in $roles.roleDefinitionId) {
        return $true
    }
    else {
        return $false
    }
}
## Elevate access
function elevateAccess {
    $req = Invoke-AzRestMethod -Path "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01" -Method POST
    return $req.StatusCode
}
## RBAC - Owner -> MG
# $ARMConnection.Context.Account.Id => signinname
# "/" => scope
# "Owner" => roledefinitionname
function roleAssignment {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $RoleDefinitionName,
        [Parameter(Mandatory = $true)]
        [string] $ObjectId,
        [Parameter(Mandatory = $true)]
        [string] $Scope
    )
    $role = New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -WarningAction SilentlyContinue
    return $role
}
function MGMenu {
    param (
        [Parameter()]
        $MGs
    )
    Write-Host "Enter the option number for the management group onboarding:"
    $switchBlock = ""
    for ($i = 1; $i -le $MGs.length; $i++) {
        $switchBlock += "`n`t$i) '$($MGs.DisplayName)'"
    }
    return $switchBlock
}
function Switch-MG {
    param (
        [Parameter()]
        $Option
    )
    $switch = 'switch($Option){'
    for ($i = 1; $i -le $MGs.length; $i++) {
        $switch += "`n`t$i { '$($MGs.DisplayName)' }"
    }
    $switch += "`n}"
    $MGOption = Invoke-Expression $switch
    return $MGOption
}
function onboardingObjects {
    Param
    (
        [Parameter(Mandatory = $true)]
        $MGExpandedObject
    )
    $SubsOnboard = @()
    $MGsOnboard = @()
    Write-Host "Detecting subscriptions...`n"
    foreach ($child in $MGExpandedObject.Children) {
        if ($child.Type -eq "/subscriptions") {
            $SubsOnboard += $child.Id.Split("/subscriptions/")[1]
        }
        elseif ($child.Type -eq "/managementGroup") {
            if ($child.Children.Count -gt 0) {
                $childSubs = @()
                foreach ($children in $child.Children) {
                    if ($children.Type -eq "/subscriptions") {
                        $childSubs += @($children.Id.Split("/subscriptions/")[1])
                    }
                    elseif ($children.Type -eq "/managementGroup") {
                        $grandChildMG = $children
                        do {
                            foreach ($grandChild in $grandChildMG.Children) {
                                $grandchildSubs = @()
                                $grandChildMGId = $grandChildMG.Id
                                if ($grandChild.Type -eq "/subscriptions") {
                                    $grandchildSubs += @($grandChild.Id.Split("/subscriptions/")[1])
                                }
                                elseif ($grandChild.Children.Type -eq "/managementGroup") {
                                    $grandChildMG = $grandChild
                                }
                            }
                            if ($grandchildSubs) {
                                $MGsOnboard += @{'id' = $grandChildMGId ; 'subsList' = $grandchildSubs }
                            }
                        } until ($grandChildMG.Children.Count -gt 0)
                    }
                }
                if ($childSubs) {
                    $MGsOnboard += @{'id' = $child.Id ; 'subsList' = $childSubs }
                }
            }
        }
    }
    return $onboardObjects, $SubsOnboard
}
Write-Host "Connecting to the customer's tenant...`n"
$ARMConnection = Connect-AzAccount -TenantId $tenantId -WarningAction SilentlyContinue
if ($ARMConnection) {
    Write-Host "Connected to '$($ARMConnection.Context.Tenant.Id)' Tenant." -ForegroundColor green
    Write-Host "`nListing Management Groups...`n"
    $MGs = Get-AzManagementGroup -WarningAction SilentlyContinue
    if ($MGs) {
        $MGMenuOutput = MGMenu -MGs $MGs
        Write-Host "$MGMenuOutput`n" -ForegroundColor Blue
        $Option = Read-Host Option
        $ChoosenMG = Switch-MG -Option $Option
        Write-Host "`n'$ChoosenMG' Management Group selected.`n" -ForegroundColor Green
        $MGObject = $MGs | Where-Object { $_.DisplayName -eq $ChoosenMG }
        $MGExpandedObject = Get-AzManagementGroup -GroupName $MGObject.Name -Expand -Recurse -WarningAction SilentlyContinue
        $onboardObjects, $SubsList = onboardingObjects -MGExpandedObject $MGExpandedObject
        $paramObject = @{
            'gitURI'               = "https://raw.githubusercontent.com/CloudTeam-IL/Onboarding/main"
            'proactivePrincipalID' = $proactivePrincipalId
            'readersPrincipalID'   = $readersPrincipalId
            'subsList'             = $SubsList
        }
        if ($onboardObjects.Length -gt 0) {
            $paramObject += @{'childMG' = $onboardObjects }
        }
        $parameters = @{
            'Name'                    = 'CloudTeamOnboarding'
            'Location'                = 'westeurope'
            'TemplateUri'             = "$($paramObject.gitURI)/main.json"
            'TemplateParameterObject' = $paramObject
        }
        $ARMDeployment = New-AzManagementGroupDeployment @parameters
    }
}