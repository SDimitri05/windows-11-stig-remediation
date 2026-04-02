<#
.SYNOPSIS
  Remediates account lockout-related Windows 11 STIG settings.

.DESCRIPTION
  This grouped script addresses the following controls:
    - WN11-AC-000005: Windows 11 account lockout duration must be configured to 15 minutes or greater
    - WN11-AC-000010: The number of allowed bad logon attempts must be configured to three or less
    - WN11-AC-000015: The period of time before the bad logon counter is reset must be configured to 15 minutes

  This script supports three execution modes:
    - Verify   : Capture and report the current account lockout policy state only
    - Apply    : Enforce the required account lockout policy settings
    - Rollback : Restore the account lockout policy settings to a simple non-enforced baseline

  This script:
    - Ensures it is run as Administrator
    - Captures the account lockout policy state before and after any change
    - Tests compliance against the STIG requirements
    - Prompts for mode selection when no -Mode argument is supplied
    - Uses the supplied mode directly when -Mode is specified
    - Displays CURRENT STATE in Verify mode
    - Displays DESIRED STATE in Verify and Apply modes
    - Displays ROLLBACK TARGET STATE in Rollback mode
    - Uses change tracking and reboot classification for smarter reboot prompting
    - Uses STIG-specific comment headers inside grouped remediation sections

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
    - Version       : 1.8.2
    - Version 1.8.2 : Aligned SUMMARY output fields while preserving the colored Result line and refined account lockout compliance logic to match STIG ranges
    - Version 1.8.1 : Removed "Compliant After Change" from Verify mode and replaced it with a single "Compliant" field for clarity and accuracy
    - Version 1.8   : Added STIG-specific comment headers inside grouped remediation sections for auditability and traceability
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
    PS C:\> .\Invoke-STIG-AccountLockout.ps1
    PS C:\> .\Invoke-STIG-AccountLockout.ps1 -Mode Verify
    PS C:\> .\Invoke-STIG-AccountLockout.ps1 -Mode Apply
    PS C:\> .\Invoke-STIG-AccountLockout.ps1 -Mode Rollback
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

    if (-not [string]::IsNullOrWhiteSpace($RequestedMode)) {
        return $RequestedMode
    }

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

function Get-NetAccountsValue {
    param([string]$Label)

    $output = net accounts 2>$null
    if (-not $output) {
        return $null
    }

    foreach ($line in $output) {
        if ($line -match "^\s*$([regex]::Escape($Label))\s+(.+?)\s*$") {
            return $matches[1].Trim()
        }
    }

    return $null
}

function Convert-ToIntegerOrNull {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $match = [regex]::Match($Value, '\d+')
    if (-not $match.Success) {
        return $null
    }

    return [int]$match.Value
}

function Get-CurrentState {
    # Gather current account lockout settings from 'net accounts'.
    $lockoutDurationRaw = Get-NetAccountsValue -Label 'Lockout duration (minutes):'
    $lockoutThresholdRaw = Get-NetAccountsValue -Label 'Lockout threshold:'
    $lockoutResetRaw = Get-NetAccountsValue -Label 'Lockout observation window (minutes):'

    return [pscustomobject]@{
        LockoutDurationMinutes        = Convert-ToIntegerOrNull -Value $lockoutDurationRaw
        LockoutThreshold              = Convert-ToIntegerOrNull -Value $lockoutThresholdRaw
        LockoutObservationWindowMins  = Convert-ToIntegerOrNull -Value $lockoutResetRaw
    }
}

function Get-DesiredState {
    return [pscustomobject]@{
        # ================================================================
        # STIG: WN11-AC-000005
        # Title: Account lockout duration must be configured to 15 minutes or greater
        # Requirement: 15 or greater, or 0
        # ================================================================
        LockoutDurationMinutes        = 15

        # ================================================================
        # STIG: WN11-AC-000010
        # Title: The number of allowed bad logon attempts must be configured to three or less
        # Requirement: 1 to 3, excluding 0
        # ================================================================
        LockoutThreshold              = 3

        # ================================================================
        # STIG: WN11-AC-000015
        # Title: The period of time before the bad logon counter is reset must be configured to 15 minutes
        # Requirement: 15 or greater
        # ================================================================
        LockoutObservationWindowMins  = 15
    }
}

function Get-RollbackTargetState {
    return [pscustomobject]@{
        # ================================================================
        # STIG: WN11-AC-000005
        # Rollback Target: Disable account lockout by setting duration to 0
        # ================================================================
        LockoutDurationMinutes        = 0

        # ================================================================
        # STIG: WN11-AC-000010
        # Rollback Target: Disable account lockout by setting threshold to 0
        # ================================================================
        LockoutThreshold              = 0

        # ================================================================
        # STIG: WN11-AC-000015
        # Rollback Target: Reset window to 0
        # ================================================================
        LockoutObservationWindowMins  = 0
    }
}

function Test-Compliance {
    param([pscustomobject]$State)

    $durationCompliant  = ($State.LockoutDurationMinutes -ge 15 -or $State.LockoutDurationMinutes -eq 0)
    $thresholdCompliant = ($State.LockoutThreshold -ge 1 -and $State.LockoutThreshold -le 3)
    $windowCompliant    = ($State.LockoutObservationWindowMins -ge 15)

    return ($durationCompliant -and $thresholdCompliant -and $windowCompliant)
}

function Invoke-Apply {
    # Account lockout policy updates generally do not require reboot, but a sign-out
    # or policy refresh/retest may be useful before rescanning.
    Set-RebootPreference -Level 'NotRequired'

    $currentState = Get-CurrentState

    # ================================================================
    # STIG: WN11-AC-000010
    # Set lockout threshold first because Windows ties the three settings together.
    # ================================================================
    if ($currentState.LockoutThreshold -lt 1 -or $currentState.LockoutThreshold -gt 3) {
        Write-Host 'Setting account lockout threshold to 3...'
        net accounts /lockoutthreshold:3 | Out-Null
        Set-ChangeFlag
    }
    else {
        Write-Host ("Account lockout threshold is already within the compliant range ({0}). No change is needed." -f $currentState.LockoutThreshold) -ForegroundColor Green
    }

    # ================================================================
    # STIG: WN11-AC-000005
    # ================================================================
    $currentState = Get-CurrentState
    if ($currentState.LockoutDurationMinutes -lt 15 -and $currentState.LockoutDurationMinutes -ne 0) {
        Write-Host 'Setting account lockout duration to 15 minutes...'
        net accounts /lockoutduration:15 | Out-Null
        Set-ChangeFlag
    }
    elseif ($currentState.LockoutDurationMinutes -eq 15 -or $currentState.LockoutDurationMinutes -eq 0) {
        Write-Host ("Account lockout duration is already set to an acceptable value ({0}). No change is needed." -f $currentState.LockoutDurationMinutes) -ForegroundColor Green
    }
    else {
        Write-Host ("Account lockout duration is already greater than the minimum required ({0}). No change is needed." -f $currentState.LockoutDurationMinutes) -ForegroundColor Green
    }

    # ================================================================
    # STIG: WN11-AC-000015
    # ================================================================
    $currentState = Get-CurrentState
    if ($currentState.LockoutObservationWindowMins -lt 15) {
        Write-Host 'Setting account lockout observation window to 15 minutes...'
        net accounts /lockoutwindow:15 | Out-Null
        Set-ChangeFlag
    }
    elseif ($currentState.LockoutObservationWindowMins -eq 15) {
        Write-Host 'Account lockout observation window is already set to 15. No change is needed.' -ForegroundColor Green
    }
    else {
        Write-Host ("Account lockout observation window is already greater than the minimum required ({0}). No change is needed." -f $currentState.LockoutObservationWindowMins) -ForegroundColor Green
    }
}

function Invoke-Rollback {
    # Rollback restores a simple non-enforced lab baseline.
    Set-RebootPreference -Level 'NotRequired'

    $currentState = Get-CurrentState

    if ($currentState.LockoutThreshold -ne 0) {
        Write-Host 'Setting account lockout threshold to 0 for rollback baseline...'
        net accounts /lockoutthreshold:0 | Out-Null
        Set-ChangeFlag
    }
    else {
        Write-Host 'Account lockout threshold is already 0. No rollback change is needed.' -ForegroundColor Green
    }

    if ($currentState.LockoutDurationMinutes -ne 0) {
        Write-Host 'Setting account lockout duration to 0 for rollback baseline...'
        net accounts /lockoutduration:0 | Out-Null
        Set-ChangeFlag
    }
    else {
        Write-Host 'Account lockout duration is already 0. No rollback change is needed.' -ForegroundColor Green
    }

    if ($currentState.LockoutObservationWindowMins -ne 0) {
        Write-Host 'Setting account lockout observation window to 0 for rollback baseline...'
        net accounts /lockoutwindow:0 | Out-Null
        Set-ChangeFlag
    }
    else {
        Write-Host 'Account lockout observation window is already 0. No rollback change is needed.' -ForegroundColor Green
    }
}

$Mode = Resolve-ExecutionMode -RequestedMode $Mode

if (-not (Test-IsAdministrator)) {
    Write-Error 'This script must be run as Administrator.'
    exit 1
}

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

    $afterState = Get-CurrentState
    $afterCompliant = Test-Compliance -State $afterState

    $afterState | Format-List
    Write-Host ('Compliant After Change: {0}' -f $afterCompliant)
}
else {
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
    Write-Host '2. If the account lockout settings are non-compliant, re-run this script with -Mode Apply.'
    Write-Host '3. Re-run your DISA STIG or Tenable compliance scan if you need independent validation.'
}
elseif ($Mode -eq 'Apply') {
    Write-Host '1. Review BEFORE STATE, DESIRED STATE, and AFTER STATE.'
    Write-Host '2. Re-run this script with -Mode Verify to confirm the final state.'
    Write-Host '3. Re-run your DISA STIG or Tenable compliance scan to validate the account lockout findings.'
    Write-Host '4. Capture before/after screenshots or terminal output for project evidence.'
    Write-Host '5. If needed, sign out and sign back in before rescanning to ensure policy reporting is refreshed.'
}
elseif ($Mode -eq 'Rollback') {
    Write-Host '1. Review BEFORE STATE, ROLLBACK TARGET STATE, and AFTER STATE.'
    Write-Host '2. Re-run this script with -Mode Verify if you want to confirm the new state.'
    Write-Host '3. Document that rollback restores a simple non-enforced baseline for this lab scenario.'
    Write-Host '4. Capture before/after screenshots or terminal output for project evidence.'
}

if ($Mode -in @('Apply','Rollback')) {
    Show-RebootPrompt
}