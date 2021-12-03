<#       
  	THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SCRIPT OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

    .SYNOPSIS
        This PowerShell script exports Scheduled Analytic Rules

    .DESCRIPTION
        Exports Scheduled Analytic Rules from the selected Microsoft Sentinel Workspace
    
    .PARAMETER TenantID
        Enter the TenantID (required)
    
    .NOTES
        AUTHOR: Sreedhar Ande
        LASTEDIT: 12-2-2021

    .EXAMPLE
        .\ExportRules.ps1 -TenantID xxxx 
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] $TenantID
)

#region Helper Functions
enum Kind {
    Scheduled
    Fusion
    MLBehaviorAnalytics
    MicrosoftSecurityIncidentCreation
}
function Write-Log {
    <#
    .DESCRIPTION 
    Write-Log is used to write information to a log file and to the console.
    
    .PARAMETER Severity
    parameter specifies the severity of the log message. Values can be: Information, Warning, or Error. 
    #>

    [CmdletBinding()]
    param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$LogFileName,
 
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information'
    )
    # Write the message out to the correct channel											  
    switch ($Severity) {
        "Information" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
    } 											  
    try {
        [PSCustomObject]@{
            Time     = (Get-Date -f g)
            Message  = $Message
            Severity = $Severity
        } | Export-Csv -Path "$PSScriptRoot\$LogFileName" -Append -NoTypeInformation -Force
    }
    catch {
        Write-Error "An error occurred in Write-Log() method" -ErrorAction SilentlyContinue		
    }    
}

function Get-RequiredModules {
    <#
    .DESCRIPTION 
    Get-Required is used to install and then import a specified PowerShell module.
    
    .PARAMETER Module
    parameter specifices the PowerShell module to install. 
    #>

    [CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $Module        
    )
    
    try {
        $installedModule = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue
        if ($null -eq $installedModule) {
            Write-Log -Message "The $Module PowerShell module was not found" -LogFileName $LogFileName -Severity Warning
            #check for Admin Privleges
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                #Not an Admin, install to current user            
                Write-Log -Message "Can not install the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                Write-Log -Message "Installing $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning
                
                Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
            else {
                #Admin, install to all users																		   
                Write-Log -Message "Installing the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                Install-Module -Name $Module -Force -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
        }
        # Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
        # Import-Module will bring the module and its functions into your current powershell session, if the module is installed.  
    }
    catch {
        Write-Log -Message "An error occurred in Get-RequiredModules() method" -LogFileName $LogFileName -Severity Error																			
        exit
    }
}

Function Get-FolderName { 
    param($initialDirectory) 
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null

    $folderDiag = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDiag.Description = "Select a folder to Export to"
    $folderDiag.rootfolder = "MyComputer"
    $folderDiag.SelectedPath = $initialDirectory

    if($folderDiag.ShowDialog() -eq "OK")
    {
        $SelectedFolder += $folderDiag.SelectedPath
    }
    return $SelectedFolder 
} #end function Get-FolderName

Function Clear-FileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $cleanName = [RegEx]::Replace($Name, "[$invalidChars]", [string]::Empty)
    return $cleanName
}

#endregion

#region MainFunctions

Function Save-MicrosoftSentinelRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $Rule,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Json", "Yaml")]
        [string]
        $Format,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Analytics", "Hunting", "LiveStream", "Automation")]
        [string]
        $Kind,
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    if($null -ne $Rule) {
        $Name = $Rule.DisplayName
        if([string]::IsNullOrEmpty($Name)) {
            $Name = $Rule.Id
        }
        $Name = Clear-FileName -Name $Name
        $OutputPathFileName = Join-Path -Path $Path -ChildPath "$($Name).$($Kind.ToLowerInvariant()).rule.$($Format.ToLowerInvariant())"
        switch ($Format) {
            "Yaml" { 
                $Rule | ConvertTo-Yaml -OutFile $OutputPathFileName -Force
                }
            "Json" { 
                $Rule | ConvertTo-Json -Depth 10 -EnumsAsStrings | Out-File -FilePath $OutputPathFileName -Force 
            }
            Default {}
        }
    }
    else {
        Write-Log "Rule is null or invalid" -LogFileName $LogFileName -Severity Error
        throw
    }
}

Function Get-MicrosoftSentinelAlertRuleAction {
    <#
      .SYNOPSIS
      Get Microsoft Sentinel Alert rule Action
      .DESCRIPTION
      This function can be used to see if an action is attached to the alert rule, if so then the configuration will be returned
      .PARAMETER SubscriptionId
      Enter the subscription ID, if no subscription ID is provided then current AZContext subscription will be used
      .PARAMETER WorkspaceName
      Enter the Workspace name
      .PARAMETER RuleName
      Enter the name of the Alert rule
      .PARAMETER RuleId
      Enter the Rule Id to skip Get-MicrosoftSentinelAlertRule step
      .EXAMPLE
      Get-MicrosoftSentinelAlertRuleAction -WorkspaceName "" -RuleName "testrule01"
      This example will get the Workspace ands return the full data object
      .NOTES
      NAME: Get-MicrosoftSentinelAlertRuleAction
    #>
    param (
        [Parameter(Mandatory)]        
        [string]$BaseUri,
        
        [Parameter(Mandatory = $false)]        
        [string]$RuleName,

        [Parameter(Mandatory = $false)]        
        [string]$RuleId
    )
    
    if ($RuleName) {
        try {
            $alertId = (Get-MicrosoftSentinelAlertRule -BaseUri $BaseUri -RuleName $RuleName -ErrorAction Stop).name
        }
        catch {
            Write-Log $_.Exception.Message -LogFileName $LogFileName -Severity Error            
            break
        }
    }
    elseif ($RuleId) {
        $alertId = $RuleId
    }
    else {
        Write-Log "No Alert Name or ID is provided" -LogFileName $LogFileName -Severity Error        
    }

    if ($alertId) {
        $uri = "https://management.azure.com$BaseUri/providers/Microsoft.SecurityInsights/alertRules/$($alertId)/actions?api-version=2019-01-01-preview"
        try {
            $return = (Invoke-RestMethod -Uri $uri -Method Get -Headers $APIHeaders).value
            return $return
        }
        catch {
            Write-Log $_.Exception.Message -LogFileName $LogFileName -Severity Error
            return $_.Exception.Message            
        }
    }
    else {
        $return = "No Alert found with provided: $($alertId)"
        return $return
    }    
}

Function Get-MicrosoftSentinelAlertRule {
    <#
      .SYNOPSIS
      Get Microsoft Sentinel Alert Rules
      .DESCRIPTION
      With this function you can get the configuration of the Azure Sentinel Alert rule from Azure Sentinel
      .PARAMETER SubscriptionId
      Enter the subscription ID, if no subscription ID is provided then current AZContext subscription will be used
      .PARAMETER WorkspaceName
      Enter the Workspace name
      .PARAMETER RuleName
      Enter the name of the Alert rule
      .PARAMETER Kind
      The alert rule kind
      .PARAMETER LastModified
      Filter for rules modified after this date/time
      .PARAMETER SkipPlaybook
      Use SkipPlaybook switch to only return the rule properties, this skips the Playbook resolve step.
      .EXAMPLE
      Get-MicrosoftSentinelAlertRule -WorkspaceName "" -RuleName "",""
      In this example you can get configuration of multiple alert rules in once
      .EXAMPLE
      Get-MicrosoftSentinelAlertRule -SubscriptionId "" -WorkspaceName "" -LastModified 2020-09-21
      In this example you can get configuration of multiple alert rules only if modified after the 21st September 2020. The datetime must be in ISO8601 format.
    #>

    [cmdletbinding()]
    param (        
        [Parameter(Mandatory)]        
        [string]$BaseUri,
        
        [Parameter(Mandatory = $false)]        
        [string[]]$RuleName,

        [Parameter(Mandatory = $false)]        
        [Kind[]]$Kind,

        [Parameter(Mandatory = $false)]        
        [DateTime]$LastModified,

        [Parameter(Mandatory = $false)]        
        [switch]$SkipPlaybook
    )
      
    
    $uri = "https://management.azure.com$BaseUri/providers/Microsoft.SecurityInsights/alertRules?api-version=2019-01-01-preview"
    Write-Log "End point $uri" -LogFileName $LogFileName -Severity Information
    

    try {
        $alertRules = Invoke-RestMethod -Uri $uri -Method Get -Headers $APIHeaders
    }
    catch {
        Write-Log $_ -LogFileName $LogFileName -Severity Error            
        Write-Log "Unable to get alert rules with error code: $($_.Exception.Message)" -LogFileName $LogFileName -Severity Error
    }

    $return = @()
    if ($alertRules.value -and $LastModified) {
        Write-Log "Filtering for rules modified after $LastModified" -LogFileName $LogFileName -Severity Error        
        $alertRules.value = $alertRules.value | Where-Object { $_.properties.lastModifiedUtc -gt $LastModified }
    }
    if ($alertRules.value) {
        Write-Log "Found $($alertRules.value.count) Alert rules" -LogFileName $LogFileName -Severity Information
        Write-Verbose "Found $($alertRules.value.count) Alert rules"

        if ($RuleName.Count -ge 1) {
            foreach ($rule in $RuleName) {
                $alertRules.value | Where-Object { $_.properties.displayName -eq $rule } | ForEach-Object {

                    $_.properties | Add-Member -NotePropertyName name -NotePropertyValue $_.name -Force
                    $_.properties | Add-Member -NotePropertyName etag -NotePropertyValue $_.etag -Force
                    $_.properties | Add-Member -NotePropertyName id -NotePropertyValue $_.id -Force
                    $_.properties | Add-Member -NotePropertyName kind -NotePropertyValue $_.kind -Force

                    # Updating incidentConfiguration output to match JSON input
                    if ($_.properties.kind -eq 'Scheduled'){
                        $_.properties | Add-Member -NotePropertyName createIncident -NotePropertyValue $_.properties.incidentConfiguration.createIncident -Force
                        $_.properties | Add-Member -NotePropertyName groupingConfiguration -NotePropertyValue $_.properties.incidentConfiguration.groupingConfiguration -Force
                        $_.properties.PSObject.Properties.Remove('incidentConfiguration')
                    }

                    if (! $SkipPlaybook) {

                        $playbook = Get-AzSentinelAlertRuleAction @arguments -RuleId $_.name

                        if ($playbook) {
                            $playbookName = ($playbook.properties.logicAppResourceId).Split('/')[-1]
                        }
                        else {
                            $playbookName = ""
                        }

                        $_.properties | Add-Member -NotePropertyName playbookName -NotePropertyValue $playbookName -Force
                    }

                    $return += $_.properties
                }
            }
            return $return
        }
        elseif ($Kind.Count -ge 1) {
            foreach ($rule in $Kind) {
                $alertRules.value | Where-Object { $_.Kind -eq $rule } | ForEach-Object {

                    $_.properties | Add-Member -NotePropertyName name -NotePropertyValue $_.name -Force
                    $_.properties | Add-Member -NotePropertyName etag -NotePropertyValue $_.etag -Force
                    $_.properties | Add-Member -NotePropertyName id -NotePropertyValue $_.id -Force
                    $_.properties | Add-Member -NotePropertyName kind -NotePropertyValue $_.kind -Force

                    # Updating incidentConfiguration output to match JSON input
                    if ($_.properties.kind -eq 'Scheduled'){
                        $_.properties | Add-Member -NotePropertyName createIncident -NotePropertyValue $_.properties.incidentConfiguration.createIncident -Force
                        $_.properties | Add-Member -NotePropertyName groupingConfiguration -NotePropertyValue $_.properties.incidentConfiguration.groupingConfiguration -Force
                        $_.properties.PSObject.Properties.Remove('incidentConfiguration')
                    }

                    if (! $SkipPlaybook) {

                        $playbook = Get-MicrosoftSentinelAlertRuleAction -BaseUri $BaseUri -RuleId $_.name

                        if ($playbook) {
                            $playbookName = ($playbook.properties.logicAppResourceId).Split('/')[-1]
                        }
                        else {
                            $playbookName = ""
                        }

                        $_.properties | Add-Member -NotePropertyName playbookName -NotePropertyValue $playbookName -Force
                    }

                    $return += $_.properties
                }
            }
            return $return
        }
        else {
            $alertRules.value | ForEach-Object {

                $_.properties | Add-Member -NotePropertyName name -NotePropertyValue $_.name -Force
                $_.properties | Add-Member -NotePropertyName id -NotePropertyValue $_.id -Force
                $_.properties | Add-Member -NotePropertyName kind -NotePropertyValue $_.kind -Force

                # Updating incidentConfiguration output to match JSON input
                if ($_.properties.kind -eq 'Scheduled'){
                    $_.properties | Add-Member -NotePropertyName createIncident -NotePropertyValue $_.properties.incidentConfiguration.createIncident -Force
                    $_.properties | Add-Member -NotePropertyName groupingConfiguration -NotePropertyValue $_.properties.incidentConfiguration.groupingConfiguration -Force
                    $_.properties.PSObject.Properties.Remove('incidentConfiguration')
                }

                if (! $SkipPlaybook) {
                    $playbook = Get-MicrosoftSentinelAlertRuleAction -BaseUri $BaseUri -RuleId $_.name

                    if ($playbook) {
                        $playbookName = ($playbook.properties.logicAppResourceId).Split('/')[-1]
                    }
                    else {
                        $playbookName = ""
                    }

                    $_.properties | Add-Member -NotePropertyName playbookName -NotePropertyValue $playbookName -Force
                }

                $return += $_.properties
            }
            return $return
        }
    }
    else {
        Write-Log "No Rules found on $BaseUri" -LogFileName $LogFileName -Severity Information
    }
    
}

#endregion MainFunctions

#region DriverProgram
Get-RequiredModules("Az")
Get-RequiredModules("Az.SecurityInsights")

$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss 
$LogFileName = '{0}_{1}.csv' -f "ExportRules", $TimeStamp

# Check Powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log "Supported PowerShell version for this script is 5 or above" -LogFileName $LogFileName -Severity Error    
    exit
}

#disconnect exiting connections and clearing contexts.
Write-Log "Clearing existing Azure connection" -LogFileName $LogFileName -Severity Information
    
$null = Disconnect-AzAccount -ContextName 'MyAzContext' -ErrorAction SilentlyContinue
    
Write-Log "Clearing existing Azure context `n" -LogFileName $LogFileName -Severity Information
    
get-azcontext -ListAvailable | ForEach-Object{$_ | remove-azcontext -Force -Verbose | Out-Null} #remove all connected content
    
Write-Log "Clearing of existing connection and context completed." -LogFileName $LogFileName -Severity Information
Try {
    #Connect to tenant with context name and save it to variable
    Connect-AzAccount -Tenant $TenantID -ContextName 'MyAzContext' -Force -ErrorAction Stop
        
    #Select subscription to build
    $GetSubscriptions = Get-AzSubscription -TenantId $TenantID | Where-Object {($_.state -eq 'enabled') } | Out-GridView -Title "Select Subscription to Use" -PassThru       
}
catch {    
    Write-Log "Error When trying to connect to tenant : $($_)" -LogFileName $LogFileName -Severity Error
    exit    
}

#loop through each selected subscription.. 
foreach($CurrentSubscription in $GetSubscriptions)
{
    Try 
    {
        #Set context for subscription being built
        $null = Set-AzContext -Subscription $CurrentSubscription.id

        Write-Log "Working in Subscription: $($CurrentSubscription.Name)" -LogFileName $LogFileName -Severity Information

        $LAWs = Get-AzOperationalInsightsWorkspace | Where-Object { $_.ProvisioningState -eq "Succeeded" } | Out-GridView -Title "Select Log Analytics workspace" -PassThru 
        if($null -eq $LAWs) {
            Write-Log "No Log Analytics workspace found..." -LogFileName $LogFileName -Severity Error 
        }
        else {
            Write-Log "Listing Log Analytics workspace" -LogFileName $LogFileName -Severity Information
            
            Write-Log "Exporting Azure Sentinel Rules" -LogFileName $LogFileName -Severity Information
            $FolderName = Get-FolderName -initialDirectory $CurrentLoation.Drive.Root
            foreach($LAW in $LAWs) { 
                $AzureAccessToken = (Get-AzAccessToken).Token            
                $APIHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $APIHeaders.Add("Content-Type", "application/json")
                $APIHeaders.Add("Authorization", "Bearer $AzureAccessToken")    

                if (Test-Path $FolderName) {
                    Write-Log "$FolderName Path Exists" -LogFileName $LogFileName -Severity Information
                }
                else {
                    try {
                        $null = New-Item -Path $FolderName -Force -ItemType Directory -ErrorAction Stop
                    }
                    catch {
                        $ErrorMessage = $_.Exception.Message
                        Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
                        Write-Log $_ -LogFileName $LogFileName -Severity Error                        
                        Break
                    }
                }
                #Initial Version - Analytical Rules 
                $RuleType = "Alert"

                if (($RuleType -like 'Alert') -or ($RuleType -like 'All')) {
                    try {
                        $rules = Get-MicrosoftSentinelAlertRule -BaseUri $LAW.ResourceId.ToString()
                    }
                    catch {
                        $ErrorMessage = $_.Exception.Message
                        Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
                        Write-Log $_ -LogFileName $LogFileName -Severity Error                         
                    }
        
                    if ($rules) {
                        foreach ($rule in $rules) {
                            if (Test-Path "$FolderName/$($LAW.Name)") {
                                $WorkspaceDirectory = "$FolderName/$($LAW.Name)"
                            }
                            else {
                                $WorkspaceDirectory = New-Item -Path $FolderName -Name $LAW.Name -ItemType "directory"
                            }                                                           
                            

                            switch ($rule.kind) {
                                "Fusion" {
                                    if(($rule.name) -ne "BuiltInFusion") {
                                        if (Test-Path "$WorkspaceDirectory/Fusion") {
                                            $ScheduledRulesDirectory = "$WorkspaceDirectory/Fusion"
                                        }
                                        else {
                                            $ScheduledRulesDirectory = New-Item -Path $WorkspaceDirectory -Name "Fusion" -ItemType "directory"
                                        }                        							
                                        Save-MicrosoftSentinelRule -Rule $rule -Format "Json" -Kind Analytics -Path $ScheduledRulesDirectory
                                    }
                                }
                                "Scheduled" {
                                    if (Test-Path "$WorkspaceDirectory/Scheduled") {
                                        $ScheduledRulesDirectory = "$WorkspaceDirectory/Scheduled"
                                    }
                                    else {
                                        $ScheduledRulesDirectory = New-Item -Path $WorkspaceDirectory -Name "Scheduled" -ItemType "directory"
                                    }                        							
                                    Save-MicrosoftSentinelRule -Rule $rule -Format "Json" -Kind Analytics -Path $ScheduledRulesDirectory
                                }
                                "MLBehaviorAnalytics" {
                                    if (Test-Path "$WorkspaceDirectory/MLBehaviorAnalytics") {
                                        $ScheduledRulesDirectory = "$WorkspaceDirectory/MLBehaviorAnalytics"
                                    }
                                    else {
                                        $ScheduledRulesDirectory = New-Item -Path $WorkspaceDirectory -Name "MLBehaviorAnalytics" -ItemType "directory"
                                    }                        							
                                    Save-MicrosoftSentinelRule -Rule $rule -Format "Json" -Kind Analytics -Path $ScheduledRulesDirectory
                                }
                                "MicrosoftSecurityIncidentCreation" {
                                    if (Test-Path "$WorkspaceDirectory/MicrosoftSecurityIncidentCreation") {
                                        $ScheduledRulesDirectory = "$WorkspaceDirectory/MicrosoftSecurityIncidentCreation"
                                    }
                                    else {
                                        $ScheduledRulesDirectory = New-Item -Path $WorkspaceDirectory -Name "MicrosoftSecurityIncidentCreation" -ItemType "directory"
                                    }                        							
                                    Save-MicrosoftSentinelRule -Rule $rule -Format "Json" -Kind Analytics -Path $ScheduledRulesDirectory
                                }
                                "Anomaly" {
                                    if (Test-Path "$WorkspaceDirectory/Anomaly") {
                                        $ScheduledRulesDirectory = "$WorkspaceDirectory/Anomaly"
                                    }
                                    else {
                                        $ScheduledRulesDirectory = New-Item -Path $WorkspaceDirectory -Name "Anomaly" -ItemType "directory"
                                    }                        							
                                    Save-MicrosoftSentinelRule -Rule $rule -Format "Json" -Kind Analytics -Path $ScheduledRulesDirectory
                                }
                                "NRT" {
                                    if (Test-Path "$WorkspaceDirectory/NRT") {
                                        $ScheduledRulesDirectory = "$WorkspaceDirectory/NRT"
                                    }
                                    else {
                                        $ScheduledRulesDirectory = New-Item -Path $WorkspaceDirectory -Name "NRT" -ItemType "directory"
                                    }                        							
                                    Save-MicrosoftSentinelRule -Rule $rule -Format "Json" -Kind Analytics -Path $ScheduledRulesDirectory
                                }
                                Default {
                                    throw "Not Supported Rule"
                                }
                            }
                        }
                    }
                }
            }                  

        } 	
    }
    catch [Exception]
    { 
        Write-Log $_ -LogFileName $LogFileName -Severity Error                         		
    }		 
}
#endregion DriverProgram  