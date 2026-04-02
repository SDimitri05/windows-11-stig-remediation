<#
.SYNOPSIS
  Remediates WN11-00-000135 by enabling Windows Firewall on all profiles.

.DESCRIPTION
  Windows Firewall provides a line of defense against unauthorized inbound and
  outbound connections. On Windows 11, DISA STIG requires the host-based firewall
  to be installed and enabled on the system.

  This script supports three execution modes:
    - Verify   : Capture and report the current firewall profile state only
    - Apply    : Enable Windows Firewall on Domain, Private, and Public profiles
    - Rollback : Restore the firewall profiles to a disabled baseline

  This script:
    - Ensures it is run as Administrator
    - Captures the firewall profile state before and after any change
    - Tests compliance against the STIG requirement
    - Prompts for mode selection when no -Mode argument is supplied
    - Uses the supplied mode directly when -Mode is specified
    - Displays CURRENT STATE in Verify mode
    - Displays DESIRED STATE in Verify and Apply modes
    - Displays ROLLBACK TARGET STATE in Rollback mode
    - Uses change tracking and reboot classification for smarter reboot prompting
    - Detects the active network category and corrects Public-to-Private during Apply when appropriate
    - Enables common management firewall rule groups to preserve authenticated scanning in lab environments

.VERSIONING
  This script follows a simple semantic versioning approach:

    - Major (X.0)     : Breaking changes to usage, parameters, or script flow
    - Minor (X.Y)     : New behavior, new logic, or meaningful feature additions
    - Patch (X.Y.Z)   : Bug fixes, wording cleanup, comment-only improvements, or non-breaking reliability fixes

.NOTES
    - Requires administrative privileges
    - Tested for compatibility with Windows PowerShell 5.1 (no ternary operator)
    - Author        : Sun Dimitri NFANDA
    - Date Created  : 2026-03-28
    - Last Modified : 2026-03-31
    - Version       : 1.9
    - Version 1.9   : Added active network category detection, Public-to-Private correction, and management firewall rule enablement to preserve authenticated scanning
    - Version 1.8.3 : Fixed firewall profile Apply and Rollback operations by passing string-based Enabled values accepted by Set-NetFirewallProfile
    - Version 1.8.2 : Aligned SUMMARY output fields while preserving the colored Result line and mode-specific compliance display
    - Version 1.8.1 : Removed "Compliant After Change" from Verify mode and replaced it with a single "Compliant" field for clarity and accuracy
    - Version 1.8   : Standardized the single-STIG script structure to match the final reusable framework
    - Version 1.7.1 : Removed AFTER STATE section in Verify mode to eliminate redundant output
    - Version 1.7   : Added CURRENT STATE, DESIRED STATE, and ROLLBACK TARGET STATE display model with mode-aware section labeling
    - Version 1.6   : Added change tracking and context-aware reboot handling using reboot classification
    - Version 1.5   : Improved Verify mode by avoiding redundant state re-evaluation and clarifying AFTER STATE behavior
    - Version 1.4   : Removed the separate -Interactive requirement and now prompts for execution mode whenever no -Mode argument is supplied
    - Version 1.3   : Added mode-aware Next Steps behavior and aligned version-history notation
    - Version 1.2   : Added support for safe automation default and optional interactive mode selection
    - Version 1.1   : Added comments throughout, stronger error handling, and clearer summary output
    - Version 1.0   : Initial release with verify/apply/rollback logic

.TESTED ON
    Date(s) Tested  : 2026-03-31
    Tested By       : Sun Dimitri NFANDA
    Systems Tested  : Windows 11 VM
    PowerShell Ver. : 5.1.x (Verify your version using `$PSVersionTable`)

.USAGE
  Supported execution patterns:

    - No parameters   : Prompt for mode selection
    - -Mode Verify    : Explicit verify mode
    - -Mode Apply     : Explicit apply mode
    - -Mode Rollback  : Explicit rollback mode

  Examples:
    PS C:\> .\Invoke-STIG-WindowsFirewall.ps1
    PS C:\> .\Invoke-STIG-WindowsFirewall.ps1 -Mode Verify
    PS C:\> .\Invoke-STIG-WindowsFirewall.ps1 -Mode Apply
    PS C:\> .\Invoke-STIG-WindowsFirewall.ps1 -Mode Rollback
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Verify','Apply','Rollback')]
    [string]$Mode
)

# Tracks whether Apply or Rollback actually changed anything.
$script:ChangesMade = $false

# Valid values:
#   NotRequired
#   Recommended
#   Required
$script:RebootPreference = 'NotRequired'

function Test-IsAdministrator {
    # Confirm the current PowerShell session is elevated.
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Section {
    param([string]$Title)

    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host $Title
    Write-Host ('=' * 72)
}

function Read-YesNo {
    param([string]$Prompt)

    $response = Read-Host ($Prompt + ' [y/N]')

    if ([string]::IsNullOrWhiteSpace($response)) {
        return $false
    }

    switch ($response.Trim().ToLower()) {
        'y'   { return $true }
        'yes' { return $true }
        default { return $false }
    }
}

function Resolve-ExecutionMode {
    param([string]$RequestedMode)

    # If the user explicitly supplied a mode, honor it.
    if (-not [string]::IsNullOrWhiteSpace($RequestedMode)) {
        return $RequestedMode
    }

    # If no mode was supplied, prompt the user interactively.
    Write-Host ''
    Write-Host 'No mode was supplied. Choose an execution mode:' -ForegroundColor Cyan
    Write-Host '  1. Verify   - Check current configuration only'
    Write-Host '  2. Apply    - Apply the remediation'
    Write-Host '  3. Rollback - Revert the remediation'
    Write-Host '  Press Enter with no selection to use the safe default: Verify'

    $selection = Read-Host 'Enter 1, 2, or 3'

    switch ($selection) {
        '1' { return 'Verify' }
        '2' { return 'Apply' }
        '3' { return 'Rollback' }
        ''  { return 'Verify' }
        default {
            Write-Host 'Unrecognized selection. Defaulting to Verify.' -ForegroundColor Yellow
            return 'Verify'
        }
    }
}

function Set-ChangeFlag {
    param([bool]$Value = $true)
    $script:ChangesMade = $Value
}

function Set-RebootPreference {
    param(
        [ValidateSet('NotRequired','Recommended','Required')]
        [string]$Level
    )

    $script:RebootPreference = $Level
}

function Show-RebootPrompt {
    if (-not $script:ChangesMade) {
        Write-Host 'No changes were made. Reboot is not necessary.' -ForegroundColor DarkGray
        return
    }

    Write-Section 'REBOOT GUIDANCE'

    switch ($script:RebootPreference) {
        'NotRequired' {
            Write-Host 'Reboot is not required for this change, but you may reboot now if desired.' -ForegroundColor Cyan
        }
        'Recommended' {
            Write-Host 'Reboot is recommended for this change to fully take effect.' -ForegroundColor Yellow
        }
        'Required' {
            Write-Host 'Reboot is required for this change to fully take effect.' -ForegroundColor Red
        }
    }

    Write-Section 'REBOOT PROMPT'
    $restart = Read-YesNo -Prompt 'Do you want to reboot the system now?'

    if ($restart) {
        Write-Host 'Restarting the system...' -ForegroundColor Yellow
        Restart-Computer -Force
    }
    else {
        switch ($script:RebootPreference) {
            'NotRequired' {
                Write-Host 'No reboot was performed. That is acceptable for this change.' -ForegroundColor Yellow
            }
            'Recommended' {
                Write-Host 'No reboot was performed. Consider rebooting later so the change fully takes effect.' -ForegroundColor Yellow
            }
            'Required' {
                Write-Host 'No reboot was performed. Please reboot later because this change requires a restart to fully apply.' -ForegroundColor Yellow
            }
        }
    }
}

function Show-StateComparison {
    param(
        [pscustomobject]$Current,
        [pscustomobject]$Expected
    )

    $rows = @()

    foreach ($prop in $Expected.PSObject.Properties.Name) {
        $currentValue = $Current.$prop
        $expectedValue = $Expected.$prop

        $rows += [pscustomobject]@{
            Setting  = $prop
            Current  = $currentValue
            Expected = $expectedValue
        }
    }

    $rows | Format-Table -AutoSize
}

function Show-StateComparisonWithTarget {
    param(
        [pscustomobject]$Current,
        [pscustomobject]$Target
    )

    $rows = @()

    foreach ($prop in $Target.PSObject.Properties.Name) {
        $currentValue = $Current.$prop
        $targetValue = $Target.$prop

        $rows += [pscustomobject]@{
            Setting = $prop
            Current = $currentValue
            Target  = $targetValue
        }
    }

    $rows | Format-Table -AutoSize
}

function Get-FirewallProfileEnabledValue {
    param([string]$ProfileName)

    try {
        $profile = Get-NetFirewallProfile -Name $ProfileName -ErrorAction Stop
        return [bool]$profile.Enabled
    }
    catch {
        return $null
    }
}

function Get-ActiveNetworkCategory {
    try {
        $profile = Get-NetConnectionProfile -ErrorAction Stop |
            Sort-Object -Property IPv4Connectivity -Descending |
            Select-Object -First 1

        if ($null -eq $profile) {
            return $null
        }

        return [string]$profile.NetworkCategory
    }
    catch {
        return $null
    }
}

function Set-NetworkCategoryIfDifferent {
    param(
        [string]$DesiredCategory
    )

    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue

    if ($null -eq $profiles) {
        Write-Warning 'Unable to enumerate network connection profiles.'
        return
    }

    foreach ($profile in $profiles) {
        if ([string]$profile.NetworkCategory -eq $DesiredCategory) {
            Write-Host ("Network profile '{0}' is already set to {1}. No change is needed." -f $profile.Name, $DesiredCategory) -ForegroundColor Green
            continue
        }

        Write-Host ("Setting network profile '{0}' category to {1}..." -f $profile.Name, $DesiredCategory)
        Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory $DesiredCategory -ErrorAction Stop
        Set-ChangeFlag
    }
}

function Enable-ManagementRuleGroupIfNeeded {
    param(
        [string]$DisplayGroup
    )

    try {
        $rules = Get-NetFirewallRule -DisplayGroup $DisplayGroup -ErrorAction Stop
    }
    catch {
        Write-Warning ("Firewall rule group '{0}' was not found on this system." -f $DisplayGroup)
        return
    }

    $disabledRules = $rules | Where-Object { $_.Enabled -ne 'True' }

    if (-not $disabledRules) {
        Write-Host ("Firewall rule group '{0}' is already enabled." -f $DisplayGroup) -ForegroundColor Green
        return
    }

    Write-Host ("Enabling firewall rule group '{0}'..." -f $DisplayGroup)
    Enable-NetFirewallRule -DisplayGroup $DisplayGroup -ErrorAction Stop | Out-Null
    Set-ChangeFlag
}

function Get-CurrentState {
    # Gather the current state of the firewall profiles and active network category
    # for comparison and reporting.
    return [pscustomobject]@{
        DomainProfileEnabled  = Get-FirewallProfileEnabledValue -ProfileName 'Domain'
        PrivateProfileEnabled = Get-FirewallProfileEnabledValue -ProfileName 'Private'
        PublicProfileEnabled  = Get-FirewallProfileEnabledValue -ProfileName 'Public'
        ActiveNetworkCategory = Get-ActiveNetworkCategory
    }
}

function Get-DesiredState {
    return [pscustomobject]@{
        DomainProfileEnabled  = $true
        PrivateProfileEnabled = $true
        PublicProfileEnabled  = $true
        ActiveNetworkCategory = 'Private'
    }
}

function Get-RollbackTargetState {
    return [pscustomobject]@{
        DomainProfileEnabled  = $false
        PrivateProfileEnabled = $false
        PublicProfileEnabled  = $false
        ActiveNetworkCategory = 'Public'
    }
}

function Test-Compliance {
    param([pscustomobject]$State)

    # The STIG itself is satisfied when all firewall profiles are enabled.
    $domainCompliant  = ($State.DomainProfileEnabled -eq $true)
    $privateCompliant = ($State.PrivateProfileEnabled -eq $true)
    $publicCompliant  = ($State.PublicProfileEnabled -eq $true)

    return ($domainCompliant -and $privateCompliant -and $publicCompliant)
}

function Set-FirewallProfileIfDifferent {
    param(
        [string]$ProfileName,
        [bool]$DesiredValue
    )

    $currentValue = Get-FirewallProfileEnabledValue -ProfileName $ProfileName

    if ($currentValue -eq $DesiredValue) {
        Write-Host ("{0} firewall profile is already set to {1}. No change is needed." -f $ProfileName, $DesiredValue) -ForegroundColor Green
        return
    }

    $enabledValue = if ($DesiredValue) { 'True' } else { 'False' }

    Write-Host ("Setting {0} firewall profile to {1}..." -f $ProfileName, $DesiredValue)
    Set-NetFirewallProfile -Name $ProfileName -Enabled $enabledValue -ErrorAction Stop
    Set-ChangeFlag
}

function Invoke-Apply {
    # Enabling Windows Firewall profiles generally does not require a reboot.
    # However, switching from Public to Private network category and enabling
    # management rule groups helps preserve authenticated scanning behavior.
    Set-RebootPreference -Level 'NotRequired'

    Write-Host 'Evaluating Domain firewall profile...'
    Set-FirewallProfileIfDifferent -ProfileName 'Domain' -DesiredValue $true

    Write-Host 'Evaluating Private firewall profile...'
    Set-FirewallProfileIfDifferent -ProfileName 'Private' -DesiredValue $true

    Write-Host 'Evaluating Public firewall profile...'
    Set-FirewallProfileIfDifferent -ProfileName 'Public' -DesiredValue $true

    $activeCategory = Get-ActiveNetworkCategory
    if ($activeCategory -eq 'Public') {
        Write-Host 'Active network category is Public. Switching to Private to better support authenticated scanning...' -ForegroundColor Yellow
        Set-NetworkCategoryIfDifferent -DesiredCategory 'Private'
    }
    elseif ($activeCategory -eq 'Private') {
        Write-Host 'Active network category is already Private.' -ForegroundColor Green
    }
    elseif ($activeCategory) {
        Write-Host ("Active network category is '{0}'. No category change is being forced." -f $activeCategory) -ForegroundColor Yellow
    }
    else {
        Write-Warning 'Unable to determine the active network category.'
    }

    # Enable common management rule groups used by authenticated scanning.
    Enable-ManagementRuleGroupIfNeeded -DisplayGroup 'Windows Management Instrumentation (WMI)'
    Enable-ManagementRuleGroupIfNeeded -DisplayGroup 'File and Printer Sharing'
    Enable-ManagementRuleGroupIfNeeded -DisplayGroup 'Remote Event Log Management'
}

function Invoke-Rollback {
    # Rollback restores a simple non-compliant lab baseline.
    Set-RebootPreference -Level 'NotRequired'

    Write-Host 'Evaluating rollback for Domain firewall profile...'
    Set-FirewallProfileIfDifferent -ProfileName 'Domain' -DesiredValue $false

    Write-Host 'Evaluating rollback for Private firewall profile...'
    Set-FirewallProfileIfDifferent -ProfileName 'Private' -DesiredValue $false

    Write-Host 'Evaluating rollback for Public firewall profile...'
    Set-FirewallProfileIfDifferent -ProfileName 'Public' -DesiredValue $false

    Write-Host 'Restoring network category to Public for rollback baseline...'
    Set-NetworkCategoryIfDifferent -DesiredCategory 'Public'
}

# Resolve the execution mode before doing anything else.
$Mode = Resolve-ExecutionMode -RequestedMode $Mode

if (-not (Test-IsAdministrator)) {
    Write-Error 'This script must be run as Administrator.'
    exit 1
}

# Reset runtime state for this execution.
$script:ChangesMade = $false
$script:RebootPreference = 'NotRequired'

$currentState = Get-CurrentState

if ($Mode -eq 'Verify') {
    Write-Section 'CURRENT STATE'
}
else {
    Write-Section 'BEFORE STATE'
}

$currentState | Format-List
$beforeState = $currentState
$beforeCompliant = Test-Compliance -State $beforeState
Write-Host ('Compliant Before Change: {0}' -f $beforeCompliant)

if ($Mode -in @('Verify','Apply')) {
    Write-Section 'DESIRED STATE'
    $desiredState = Get-DesiredState
    $desiredState | Format-List

    Write-Section 'CURRENT VS DESIRED'
    Show-StateComparison -Current $beforeState -Expected $desiredState
}

if ($Mode -eq 'Rollback') {
    Write-Section 'ROLLBACK TARGET STATE'
    $rollbackTargetState = Get-RollbackTargetState
    $rollbackTargetState | Format-List

    Write-Section 'CURRENT VS ROLLBACK TARGET'
    Show-StateComparisonWithTarget -Current $beforeState -Target $rollbackTargetState
}

try {
    switch ($Mode) {
        'Verify' {
            Write-Section 'VERIFY MODE'
            Write-Host 'No changes were made. Review the current configuration and desired state above.' -ForegroundColor Cyan
        }
        'Apply' {
            Write-Section 'APPLY MODE'
            Invoke-Apply
        }
        'Rollback' {
            Write-Section 'ROLLBACK MODE'
            Invoke-Rollback
        }
    }
}
catch {
    Write-Error ('An error occurred while executing mode ''{0}'': {1}' -f $Mode, $_.Exception.Message)
    exit 1
}

if ($Mode -ne 'Verify') {
    Write-Section 'AFTER STATE'

    # Re-query the system only after Apply or Rollback.
    $afterState = Get-CurrentState
    $afterCompliant = Test-Compliance -State $afterState

    $afterState | Format-List
    Write-Host ('Compliant After Change: {0}' -f $afterCompliant)
}
else {
    # In Verify mode, AFTER STATE is intentionally omitted to avoid redundant output.
    $afterState = $beforeState
    $afterCompliant = $beforeCompliant
}

Write-Section 'SUMMARY'

if ($Mode -eq 'Verify') {
    Write-Host ("{0,-24}: {1}" -f 'Mode Executed', $Mode)
    Write-Host ("{0,-24}: {1}" -f 'Compliant', $beforeCompliant)
}
else {
    Write-Host ("{0,-24}: {1}" -f 'Mode Executed', $Mode)
    Write-Host ("{0,-24}: {1}" -f 'Compliant Before Change', $beforeCompliant)
    Write-Host ("{0,-24}: {1}" -f 'Compliant After Change', $afterCompliant)
}

Write-Host ("{0,-24}: {1}" -f 'Changes Made', $script:ChangesMade)

if ($Mode -in @('Apply','Rollback')) {
    Write-Host ("{0,-24}: {1}" -f 'Reboot Preference', $script:RebootPreference)
}

if ($Mode -eq 'Verify') {
    Write-Host ("{0,-24}: {1}" -f 'Result', 'Verification completed. No changes were made.') -ForegroundColor Cyan
}
elseif ($Mode -eq 'Apply' -and $afterCompliant) {
    if ($script:ChangesMade) {
        Write-Host ("{0,-24}: {1}" -f 'Result', 'STIG remediation applied successfully.') -ForegroundColor Green
    }
    else {
        Write-Host ("{0,-24}: {1}" -f 'Result', 'System was already compliant. No changes were required.') -ForegroundColor Green
    }
}
elseif ($Mode -eq 'Rollback') {
    if ($script:ChangesMade) {
        Write-Host ("{0,-24}: {1}" -f 'Result', 'Rollback completed.') -ForegroundColor Yellow
    }
    else {
        Write-Host ("{0,-24}: {1}" -f 'Result', 'No rollback changes were required.') -ForegroundColor Yellow
    }
}
else {
    Write-Host ("{0,-24}: {1}" -f 'Result', 'Review the AFTER STATE section for details.') -ForegroundColor Yellow
}

Write-Section 'NEXT STEPS'
if ($Mode -eq 'Verify') {
    Write-Host '1. Review CURRENT STATE against DESIRED STATE.'
    Write-Host '2. If the firewall profiles are non-compliant, re-run this script with -Mode Apply.'
    Write-Host '3. Re-run your DISA STIG or Tenable compliance scan if you need independent validation.'
}
elseif ($Mode -eq 'Apply') {
    Write-Host '1. Review BEFORE STATE, DESIRED STATE, and AFTER STATE.'
    Write-Host '2. Re-run this script with -Mode Verify to confirm the final state.'
    Write-Host '3. Re-run your DISA STIG or Tenable compliance scan to validate the finding is remediated.'
    Write-Host '4. Capture before/after screenshots or terminal output for project evidence.'
    Write-Host '5. This script also corrects a Public network category and enables common management rule groups to help preserve authenticated Tenable scanning.'
}
elseif ($Mode -eq 'Rollback') {
    Write-Host '1. Review BEFORE STATE, ROLLBACK TARGET STATE, and AFTER STATE.'
    Write-Host '2. Re-run this script with -Mode Verify if you want to confirm the new state.'
    Write-Host '3. Document that rollback restores the defined rollback target, not necessarily the exact original pre-change state.'
    Write-Host '4. Capture before/after screenshots or terminal output for project evidence.'
}

if ($Mode -in @('Apply','Rollback')) {
    Show-RebootPrompt
}