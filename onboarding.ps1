<#
  .SYNOPSIS
  CloudTeam & CloudHiro onboarding script for clients

  .DESCRIPTION
  Pre-requisites:
  - User that has an Owner permission to the desired management group to be onboarded.
  OR
  - User that is a Global Administrator on the tenant.
  The onboarding.ps1 script logs in to a customer's tenant and do the following:
  - Lists all management groups in which the logged in user has permissions to.
  - Then, the customer should choose the desired management group in which CloudTeam will have access to it's subscriptions.
  - If the user has no permissions on any management group, the script will check if the user is a Global Administrator on the tenant, and will elevate access to the root of the tenant ("/") and then it will reload the management groups.
  - After the listing of management groups, the user will get a prompt and choose the desired management group to be onboarded.
  - After selecting the management group, an ARM Template which contains all onboarding resources will be deployed at the selected management group.
  - When everything is completed or failed, a cleanup function will be executed and will cleanup any temporary configurations, permissions and connections.

  .PARAMETER TenantId
  Tenant ID of the tenant to be onboarded.

  .PARAMETER ReadersPrincipalId
  Readers Group of users from CloudTeam.AI Experts.

  .PARAMETER ProactivePrincipalId
  Proactive Group of users from CloudTeam.AI Experts.

  .EXAMPLE
  PS> ./Onboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ReadersPrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ProactivePrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

  .EXAMPLE
  PS> ./Onboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ReadersPrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

#>

######################################################################################################################

#  Copyright 2022 CloudTeam & CloudHiro Inc. or its affiliates. All Rights Re`ed.                                 #

#  You may not use this file except in compliance with the License.                                                  #

#  https://www.cloudhiro.com/AWS/TermsOfUse.php                                                                      #

#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES                                                  #

#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #

#  and limitations under the License.                                                                                #

######################################################################################################################

param(
    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $TenantId,

    [string]
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $ReadersPrincipalId,

    [string]
    [Parameter()]
    $ProactivePrincipalId = 'Disabled'
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
        $ObjectId
    )
    $response = $null
    $uri = "https://graph.microsoft.com/beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=principalId eq '$ObjectId'"
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
    [string]
    [Parameter()]
    $APIVersion = '2016-07-01'

    $req = Invoke-AzRestMethod -Path "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01" -Method POST
    return $req.StatusCode
}
## RBAC - Owner -> MG
# $ARMConnection.Context.Account.Id => signinname
# "/" => scope
# "Owner" => roledefinitionname
function New-RoleAssignment {
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
function Remove-RoleAssignment {
    param (
        [Parameter(Mandatory = $true)]
        [string] $RoleDefinitionName,
        [Parameter(Mandatory = $true)]
        [string] $ObjectId,
        [Parameter(Mandatory = $true)]
        [string] $Scope
    )
    $role = Remove-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -WarningAction SilentlyContinue
    return $role
}
function TempRoot {
    param (
        [Parameter()]
        [string] $AccessTokenResourceTypeName = 'MSGraph',
        [Parameter()]
        [string] $RoleDefinitionName = 'Owner',
        [Parameter(Mandatory = $true)]
        [string] $UserId
    )
    $GlobalAdministrator = '62e90394-69f5-4237-9190-012177145e10'
    Write-Host "Listing Management Groups operation failed." -ForegroundColor Red
    Write-Host "Checking if '$($UserId)' has Global Administrator privileges..."
    $token = Get-AccessToken -ResourceTypeName $AccessTokenResourceTypeName
    $MGConnection = Connect-AAD -AccessToken $token.Token
    if ($MGConnection) {
        $ObjectId = Get-ObjectId -UserId $UserId
        $UserPermissions = Get-UserPemissions -ObjectId $ObjectId
        if ((checkRole -roles $UserPermissions -roleDefinitionId $GlobalAdministrator)) {
            Write-Host "'$($UserId)' has Global Administrator privileges." -ForegroundColor Green
            Write-Host "`nElevating root access..."
            $ea = elevateAccess -APIVersion "2016-07-01"
            if ($ea = 200) {
                $Scope = "/"
                Write-Host "`nRoot access has successfully elevated." -ForegroundColor
                $rbacAssignment = New-RoleAssignment -RoleDefinitionName $RoleDefinitionName -ObjectId $ObjectId -Scope $Scope
                Write-Host "`nAssigning '$($RoleDefinitionName)' permission for '$($UserId)' on '$($Scope)' scope..."
                if ($rbacAssignment) {
                    Write-Host "'$($RoleDefinitionName)' Permission were given temporary for '$($UserId)' on Root Management Group sucessfully." -ForegroundColor Green
                }
            }
        }
        else {
            Write-Error "Global Administrator privileges not found for '$($UserId)'."
        }
    }
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
function Select-MG {
    param (
        [Parameter()]
        $MGs
    )
    $MGMenuOutput = MGMenu -MGs $MGs
    Write-Host "$MGMenuOutput`n" -ForegroundColor Blue
    $Option = Read-Host Option
    $ChoosenMG = Switch-MG -Option $Option
    Write-Host "`n'$ChoosenMG' Management Group selected.`n" -ForegroundColor Green
    return $ChoosenMG
}
function Get-MGExpandedObject {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $ManagementGroup
    )
    $MGObject = $MGs | Where-Object { $_.DisplayName -eq $ManagementGroup }
    $MGExpandedObject = Get-AzManagementGroup -GroupName $MGObject.Name -Expand -Recurse -WarningAction SilentlyContinue
    return $MGExpandedObject
}
function GenerateARMTemplateParameters {
    param (
        [Parameter()]
        $ParamObject
    )
    $parameters = @{
        'Name'                    = 'CloudTeamOnboarding'
        'Location'                = 'westeurope'
        'TemplateUri'             = "$($paramObject.gitURI)/main.json"
        'TemplateParameterObject' = $paramObject
    }
    return $parameters
}
function Cleanup {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ObjectId
    )
    $RoleDefinitionName = "Owner"
    $Scope = "/"
    # Remove Root access.
    $removeAssignment = Remove-RoleAssignment -RoleDefinitionName $RoleDefinitionName -ObjectId $ObjectId -Scope $Scope
    if (!$removeAssignment) {
        Write-Error "Cannot remove role assignment."
    }
    Disconnect-AzAccount | Out-Null
}
Write-Host "Connecting to the customer's tenant...`n"
$ARMConnection = Connect-AzAccount -TenantId $TenantId -WarningAction SilentlyContinue
if ($ARMConnection) {
    Write-Host "Connected to '$($ARMConnection.Context.Tenant.Id)' Tenant." -ForegroundColor green
    Write-Host "`nListing Management Groups...`n"
    $MGs = Get-AzManagementGroup -WarningAction SilentlyContinue
    if (!$MGs) {
        TempRoot -UserId $ARMConnection.Context.Account.Id
    }
    Write-Host "`nListing Management Groups...`n"
    $MGs = Get-AzManagementGroup -WarningAction SilentlyContinue
    if ($MGs) {
        $ChoosenMG = Select-MG -MGs $MGs
        $MGExpandedObject = Get-MGExpandedObject -ManagementGroup $ChoosenMG
        $onboardObjects, $SubsList = onboardingObjects -MGExpandedObject $MGExpandedObject
        $ParamObject = @{
            'gitURI'               = "https://raw.githubusercontent.com/CloudTeam-IL/Onboarding/main"
            'proactivePrincipalID' = $ProactivePrincipalId
            'readersPrincipalID'   = $ReadersPrincipalId
            'subsList'             = $SubsList
        }
        if ($onboardObjects.Length -gt 0) {
            $ParamObject += @{'childMG' = $onboardObjects }
        }
        $parameters = GenerateARMTemplateParameters -paramObject $paramObject
        $ARMDeployment = New-AzManagementGroupDeployment $parameters
        if ($ARMDeployment -and $ARMDeployment.ProvisioningState -eq "Succeeded") {
            Write-Host "'$($ARMConnection.Context.Account.Id)',Thank you for joining CloudTeam.AI FinOps Services." -ForegroundColor Green
        }
        else {
            Write-Error "Onboarding failed."
        }
    }
    else {
        Write-Error "Failed."
    }
}