<#
  .SYNOPSIS
  CloudTeam & CloudHiro onboarding script for clients

  .DESCRIPTION
  Pre-requisites:
  - User that has an Owner permission to the desired management group to be onboarded.
  OR
  - User that is a Global Administrator on the tenant.
  ********************************************************************************************
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

  .PARAMETER gitURI
  Git URI for all ARM templates. Don't change the default value !

  .EXAMPLE
  PS> ./Onboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ReadersPrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ProactivePrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

  .EXAMPLE
  PS> ./Onboarding.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -ReadersPrincipalId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

#>

######################################################################################################################

#  Copyright 2022 CloudTeam & CloudHiro Inc. or its affiliates. All Rights Re`ed.                                    #

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
    [Parameter(Mandatory = $true)]
    $ProactivePrincipalId = 'Disabled',

    [string]
    [Parameter()]
    $gitURI = 'https://raw.githubusercontent.com/CloudTeam-IL/Onboarding/dev'
)
#Requires -Modules Az

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
## Connect Microsoft Graph API
function Connect-AAD {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $AccessToken
    )
    $MSGraphConnection = Connect-MgGraph -AccessToken $AccessToken
    return $MSGraphConnection
}
## Get the security principal's object id
function Get-ObjectId {
    param (
        [string]
        [Parameter(Mandatory = $true)]
        $UserId
    )
    $user = Get-MgUser -All | Where-Object { $_.UserPrincipalName -eq $UserId -or $_.Mail -eq $UserId }
    return $user.Id
}
## List Security principal's permissions
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
## Check if a security principal has specific role.
function checkRole {
    param (
        [Parameter()]
        $roles,
        [string]
        [Parameter()]
        $roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'
    )
    if ($roleDefinitionId -in $roles.roleDefinitionId) {
        return $true
    }
    else {
        return $false
    }
}
## Elevate access for root access
function elevateAccess {
    [string]
    [Parameter()]
    $APIVersion = '2016-07-01'

    $req = Invoke-AzRestMethod -Path "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01" -Method POST
    return $req.StatusCode
}
## Get Role assignments
function Get-RoleAssignment {
    $role = Get-AzRoleAssignment -WarningAction SilentlyContinue
    return $role
}
## Create a role assignment
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
## Remove a role assignment
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
## Delegates root access to the specified security principal
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
        if (checkRole -roles $UserPermissions -roleDefinitionId $GlobalAdministrator) {
            Write-Host "'$($UserId)' has Global Administrator privileges." -ForegroundColor Green
            Write-Host "`nElevating root access..."
            $ea = elevateAccess -APIVersion "2016-07-01"
            if ($ea = 200) {
                $Scope = "/"
                Write-Host "`nRoot access has successfully elevated." -ForegroundColor Green
                $chkRole = Get-RoleAssignment | Where-Object { ($_.ObjectId -eq $ObjectId -and $_.Scope -eq $Scope -and $_.RoleDefinitionName -eq $RoleDefinitionName) }
                if (!$chkRole) {
                    $rbacAssignment = New-RoleAssignment -RoleDefinitionName $RoleDefinitionName -ObjectId $ObjectId -Scope $Scope
                    Write-Host "`nAssigning '$($RoleDefinitionName)' permission for '$($UserId)' on '$($Scope)' scope..."
                    if ($rbacAssignment) {
                        Write-Host "'$($RoleDefinitionName)' Permission were given temporary for '$($UserId)' on Root Management Group sucessfully." -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "'$($UserId)' has already '$($RoleDefinitionName)' permission on '$($Scope)'."
                }
            }
        }
        else {
            Write-Error "Global Administrator privileges not found for '$($UserId)'."
        }
    }
}
## Returns Management groups list.
function MGMenu {
    param (
        [Parameter()]
        $MGs
    )
    Write-Host "Enter the option number for the management group onboarding:"
    $switchBlock = @()
    for ($i = 1; $i -le $MGs.length; $i++) {
        $MG = $MGs[$i - 1]
        $switchBlock += "`n`t$i) '$($MG.DisplayName)'"
    }
    return $switchBlock
}
## Switch (Select) the desired management group to be onboarded.
function Switch-MG {
    param (
        [Parameter()]
        $Option
    )
    $switch = 'switch($Option){'
    for ($i = 1; $i -le $MGs.length; $i++) {
        $MG = $MGs[$i - 1]
        $switch += "`n`t$i { '$($MG.DisplayName)' }"
    }
    $switch += "`n}"
    $MGOption = Invoke-Expression $switch
    return $MGOption
}
## Discovering the objects to be onboarded.
function onboardingObjects {
    Param
    (
        [Parameter(Mandatory = $true)]
        $MGExpandedObject
    )
    $SubsOnboard = @()
    [hashtable[]]$MGsOnboard = @()
    Write-Host "Detecting subscriptions...`n"
    foreach ($child in $MGExpandedObject.Children) {
        if ($child.Type -eq "/subscriptions") {
            $SubsOnboard += $child.Id.Split("/subscriptions/")[1]
        }
        elseif ($child.Type -eq "/providers/Microsoft.Management/managementGroups") {
            if ($child.Children.Count -gt 0) {
                $childSubs = @()
                foreach ($children in $child.Children) {
                    if ($children.Type -eq "/subscriptions") {
                        $childSubs += @($children.Id.Split("/subscriptions/")[1])
                    }
                    elseif ($children.Type -eq "/providers/Microsoft.Management/managementGroups") {
                        $grandChildMG = $children
                        do {
                            foreach ($grandChild in $grandChildMG.Children) {
                                $grandchildSubs = @()
                                $grandChildMGId = $grandChildMG.Id
                                if ($grandChild.Type -eq "/subscriptions") {
                                    $grandchildSubs += @($grandChild.Id.Split("/subscriptions/")[1])
                                }
                                elseif ($grandChild.Children.Type -eq "/providers/Microsoft.Management/managementGroups") {
                                    $grandChildMG = $grandChild
                                }
                            }
                            if ($grandchildSubs) {
                                $grandChildName = $grandChild.DisplayName
                                $MGsOnboard += @{id = $grandChildMGId ; subsList = @($grandchildSubs) }
                            }
                        } until ($grandChildMG.Children.Count -gt 0)
                    }
                }
                if ($childSubs) {
                    $MGsOnboard += @{ id = $child.Id ; subsList = @($childSubs) }
                }
            }
        }
    }
    return $MGsOnboard, $SubsOnboard
}
## Expected User's input for a management group to be onboarded.
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
## Get the selected management group with more descriptive information.
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
## Generate ARM Template parameters object
function GenerateARMTemplateParameters {
    param (
        [Parameter(Mandatory = $true)]
        $ParamObject,
        [Parameter(Mandatory = $true)]
        [string] $ManagementGroupId
    )
    $parameters = @{
        'Name'                    = 'CloudTeamOnboarding'
        'Location'                = 'westeurope'
        'TemplateUri'             = "$($paramObject.gitURI)/main.json"
        'TemplateParameterObject' = $paramObject
        'ManagementGroupId'       = $ManagementGroupId
    }
    return $parameters
}
## Cleanup function which remove any temporary configurations/permissions that were given in this process.
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
try {
    $ARMConnection = Connect-AzAccount -TenantId $TenantId -WarningAction SilentlyContinue
}
catch {
    Write-Error $Error[0]
}
if ($ARMConnection) {
    Write-Host "Connected to '$($ARMConnection.Context.Tenant.Id)' Tenant." -ForegroundColor green
    Write-Host "`nListing Management Groups...`n"
    $MGs = Get-AzManagementGroup -WarningAction SilentlyContinue
    if (!$MGs) {
        Write-Host "Cannot list management groups." -ForegroundColor Red
        Write-Host "`nTriggering temporary root permissions..."
        TempRoot -UserId $ARMConnection.Context.Account.Id
        $temproot = $true
    }
    else {
        $temproot = $false
    }
    $MGs = Get-AzManagementGroup -WarningAction SilentlyContinue
    if ($MGs) {
        $ChoosenMG = Select-MG -MGs $MGs
        $MGExpandedObject = Get-MGExpandedObject -ManagementGroup $ChoosenMG
        $onboardObjects, $SubsList = onboardingObjects -MGExpandedObject $MGExpandedObject
        $parameters = @{
            'Name'                 = 'CloudTeamOnboarding'
            'Location'             = 'westeurope'
            'TemplateUri'          = "$($gitURI)/main.json"
            'Verbose'              = $true
            'gitURI'               = $gitURI
            'ManagementGroupId'    = $MGExpandedObject.Name
            'proactivePrincipalID' = $ProactivePrincipalId
            'readersPrincipalID'   = $ReadersPrincipalId
            'subsList'             = $SubsList
        }
        if ($onboardObjects.Length -gt 0) {
            $object = @{ 'MGs' = $onboardObjects }
            $parameters = $parameters + @{'childs' = $object }
        }
        try {
            Write-Host "Starting onboarding deployment...`n"
            $ARMDeployment = New-AzManagementGroupDeployment @parameters
        }
        catch {
            Write-Error $Error[0]
        }
        finally {
            if ($ARMDeployment) {
                Write-Host "`Onboarding successfully completed." -ForegroundColor Green
            }
            if ($temproot) {
                $token = Get-AccessToken -ResourceTypeName 'MSGraph'
                $MGConnection = Connect-AAD -AccessToken $token.Token
                if ($MGConnection) {
                    $ObjectId = Get-ObjectId -UserId $ARMConnection.Context.Account.Id
                    Cleanup -ObjectId $(Get-ObjectId -UserId $ARMConnection.Context.Account.Id)
                }
            }
        }
    }
    else {
        Write-Error "Failed."
    }
}