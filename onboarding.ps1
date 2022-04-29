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
    [Parameter(Mandatory = $true)]
    $proactivePrincipalId = ''
)
#Requires -Modules Az, Microsoft.Graph

## Access Token
function accessToken {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $ResourceTypeName
    )
    $token = Get-AzAccessToken -ResourceTypeName $ResourceTypeName
    return $token
}
## Get User's object id - Input UserId - $ARM.Context.Account.Id
function objectId {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $accessToken,

        [string]
        [Parameter(Mandatory = $true)]
        $UserId
    )
    Connect-MgGraph -AccessToken $accessToken | Out-Null
    $user = Get-MgUser -All | Where-Object { $_.DisplayName -eq $UserId -or $_.UserPrincipalName -like $UserId }
    return $user
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
        [string] $SignInName,
        [Parameter(Mandatory = $true)]
        [string] $Scope
    )
    $role = New-AzRoleAssignment -SignInName $SignInName -RoleDefinitionName $RoleDefinitionName -Scope $Scope -WarningAction SilentlyContinue
    return $role
}
function onboardingObjects {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string] $MGExpandedObject
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
    return $MGsOnboard, $SubsOnboard
}
Write-Host "Connecting to the customer's tenant...`n"
$ARMConnection = Connect-AzAccount -TenantId $tenantId -WarningAction SilentlyContinue
if ($ARMConnection) {
    Write-Host "Connected to '$($ARMConnection.Context.Tenant.Id)' Tenant." -ForegroundColor green
    Write-Host "`nListing Management Groups...`n"
    $MGs = Get-AzManagementGroup -WarningAction SilentlyContinue
    if ($MGs) {
        Write-Host "Enter the option number for the management group onboarding:"
        $switchBlock = ""
        $switch = 'switch($option){'
        for ($i = 1; $i -le $MGs.length; $i++) {
            $switchBlock += "`n`t$i) '$($MGs.DisplayName)'"
            $switch += "`n`t$i { '$($MGs.DisplayName)' }"
        }
        Write-Host "$switchBlock`n" -ForegroundColor Blue
        $option = Read-Host Option
        $switch += "`n}"
        $MGOption = Invoke-Expression $switch
        Write-Host "`n'$MGOption' Management Group selected.`n" -ForegroundColor Green
        $MGObject = $MGs | Where-Object { $_.DisplayName -eq $MGOption }
        $MGExpandedObject = Get-AzManagementGroup -GroupName $MGObject.Name -Expand -Recurse -WarningAction SilentlyContinue
        $onboardObjects, $SubsList = onboardingObjects -MGExpandedObject $MGExpandedObject
        # for child MG, need to add bool parameter that will determine if the finalize phase needs to be deployed.
        # It needs to deploy lighthouse resources only.
        # for child MG foreach loop, it needs to create a new SubsOnboard var and iterate over it !
        $paramObject = @{
            'gitURI'               = "https://raw.githubusercontent.com/CloudTeam-IL/Onboarding/main"
            'proactivePrincipalID' = $proactivePrincipalId
            'readersPrincipalID'   = $readersPrincipalId
            'subsList'             = $SubsList
        }
        if ($MGsOnboard.Length -gt 0) {
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