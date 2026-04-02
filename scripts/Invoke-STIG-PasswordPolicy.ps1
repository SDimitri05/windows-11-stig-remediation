<#
.SYNOPSIS
  Remediates password policy-related Windows 11 STIG settings.

.DESCRIPTION
  This grouped script addresses the following controls:
    - WN11-AC-000020: The password history must be configured to 24 passwords remembered
    - WN11-AC-000030: The minimum password age must be configured to at least 1 day
    - WN11-AC-000035: Passwords must, at a minimum, be 14 characters
    - WN11-AC-000040: The built-in Microsoft password complexity filter must be enabled

  This script supports three execution modes:
    - Verify   : Capture and report the current password policy state only
    - Apply    : Enforce the required password policy settings
    - Rollback : Restore the password policy settings to a simple non-enforced baseline

  This script:
    - Ensures it is run as Administrator
    - Captures the password policy state before and after any change
    - Tests compliance against the STIG requirements
    - Prompts for mode selection when no -Mode argument is supplied
    - Uses the supplied mode directly when -Mode is specified
    - Displays CURRENT STATE in Verify mode
    - Displays DESIRED STATE in Verify and Apply modes
    - Displays ROLLBACK TARGET STATE in Rollback mode
    - Uses change tracking and reboot classification for smarter reboot prompting
    - Uses STIG-specific comment headers inside grouped remediation sections
    - Uses secedit export/import to read and enforce local password policy consistently

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
    - Version 1.8.2 : Aligned SUMMARY output fields while preserving the colored Result line and refined password policy parsing and compliance logic
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
    PS C:\> .\Invoke-STIG-PasswordPolicy.ps1
    PS C:\> .\Invoke-STIG-PasswordPolicy.ps1 -Mode Verify
    PS C:\> .\Invoke-STIG-PasswordPolicy.ps1 -Mode Apply
    PS C:\> .\Invoke-STIG-PasswordPolicy.ps1 -Mode Rollback
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

function Get-TemporaryPath {
    param([string]$FileName)
    return Join-Path -Path $env:TEMP -ChildPath $FileName
}

function Export-SecurityPolicy {
    param([string]$OutputPath)

    if (Test-Path $OutputPath) {
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
    }

    secedit /export /cfg $OutputPath /areas SECURITYPOLICY | Out-Null

    if (-not (Test-Path $OutputPath)) {
        throw "Security policy export failed. File was not created: $OutputPath"
    }
}

function Get-InfValue {
    param(
        [string[]]$Lines,
        [string]$KeyName
    )

    foreach ($line in $Lines) {
        if ($line -match "^\s*{0}\s*=\s*(.+?)\s*$" -f [regex]::Escape($KeyName)) {
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

    $match = [regex]::Match($Value, '^-?\d+$')
    if (-not $match.Success) {
        return $null
    }

    return [int]$match.Value
}

function Convert-ToBooleanEnabledState {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    switch ($Value.Trim()) {
        '1' { return $true }
        '0' { return $false }
        default { return $null }
    }
}

function Get-CurrentState {
    $exportPath = Get-TemporaryPath -FileName 'PasswordPolicy_Current.inf'
    Export-SecurityPolicy -OutputPath $exportPath
    $lines = Get-Content -Path $exportPath -ErrorAction Stop

    return [pscustomobject]@{
        PasswordHistorySize = Convert-ToIntegerOrNull -Value (Get-InfValue -Lines $lines -KeyName 'PasswordHistorySize')
        MinimumPasswordAge  = Convert-ToIntegerOrNull -Value (Get-InfValue -Lines $lines -KeyName 'MinimumPasswordAge')
        MinimumPasswordLength = Convert-ToIntegerOrNull -Value (Get-InfValue -Lines $lines -KeyName 'MinimumPasswordLength')
        PasswordComplexity  = Convert-ToBooleanEnabledState -Value (Get-InfValue -Lines $lines -KeyName 'PasswordComplexity')
    }
}

function Get-DesiredState {
    return [pscustomobject]@{
        # ================================================================
        # STIG: WN11-AC-000020
        # Title: The password history must be configured to 24 passwords remembered
        # Requirement: 24 or greater
        # ================================================================
        PasswordHistorySize   = 24

        # ================================================================
        # STIG: WN11-AC-000030
        # Title: The minimum password age must be configured to at least 1 day
        # Requirement: 1 or greater
        # ================================================================
        MinimumPasswordAge    = 1

        # ================================================================
        # STIG: WN11-AC-000035
        # Title: Passwords must, at a minimum, be 14 characters
        # Requirement: 14 or greater
        # ================================================================
        MinimumPasswordLength = 14

        # ================================================================
        # STIG: WN11-AC-000040
        # Title: The built-in Microsoft password complexity filter must be enabled
        # Requirement: Enabled
        # ================================================================
        PasswordComplexity    = $true
    }
}

function Get-RollbackTargetState {
    return [pscustomobject]@{
        # ================================================================
        # Rollback Target: Simple non-enforced lab baseline
        # ================================================================
        PasswordHistorySize   = 0
        MinimumPasswordAge    = 0
        MinimumPasswordLength = 0
        PasswordComplexity    = $false
    }
}

function Test-Compliance {
    param([pscustomobject]$State)

    $historyCompliant    = ($State.PasswordHistorySize -ge 24)
    $minAgeCompliant     = ($State.MinimumPasswordAge -ge 1)
    $minLengthCompliant  = ($State.MinimumPasswordLength -ge 14)
    $complexityCompliant = ($State.PasswordComplexity -eq $true)

    return ($historyCompliant -and $minAgeCompliant -and $minLengthCompliant -and $complexityCompliant)
}

function New-SecurityPolicyInfContent {
    param(
        [int]$PasswordHistorySize,
        [int]$MinimumPasswordAge,
        [int]$MinimumPasswordLength,
        [bool]$PasswordComplexity
    )

    $complexityValue = if ($PasswordComplexity) { 1 } else { 0 }

    return @"
[Unicode]
Unicode=yes

[Version]
signature=`"`$CHICAGO$`"
Revision=1

[System Access]
PasswordHistorySize = $PasswordHistorySize
MinimumPasswordAge = $MinimumPasswordAge
MinimumPasswordLength = $MinimumPasswordLength
PasswordComplexity = $complexityValue
"@
}

function Apply-SecurityPolicyConfiguration {
    param(
        [int]$PasswordHistorySize,
        [int]$MinimumPasswordAge,
        [int]$MinimumPasswordLength,
        [bool]$PasswordComplexity
    )

    $cfgPath = Get-TemporaryPath -FileName 'PasswordPolicy_Apply.inf'
    $dbPath  = Get-TemporaryPath -FileName 'PasswordPolicy_Apply.sdb'

    $content = New-SecurityPolicyInfContent `
        -PasswordHistorySize $PasswordHistorySize `
        -MinimumPasswordAge $MinimumPasswordAge `
        -MinimumPasswordLength $MinimumPasswordLength `
        -PasswordComplexity $PasswordComplexity

    Set-Content -Path $cfgPath -Value $content -Encoding Unicode -Force

    secedit /configure /db $dbPath /cfg $cfgPath /areas SECURITYPOLICY | Out-Null
}

function Invoke-Apply {
    # Password policy changes generally do not require an immediate reboot,
    # but a sign-out or password policy refresh context may be useful before rescanning.
    Set-RebootPreference -Level 'NotRequired'

    $currentState = Get-CurrentState
    $desiredState = Get-DesiredState

    $needsHistoryChange    = ($currentState.PasswordHistorySize -lt $desiredState.PasswordHistorySize)
    $needsMinAgeChange     = ($currentState.MinimumPasswordAge -lt $desiredState.MinimumPasswordAge)
    $needsMinLengthChange  = ($currentState.MinimumPasswordLength -lt $desiredState.MinimumPasswordLength)
    $needsComplexityChange = ($currentState.PasswordComplexity -ne $desiredState.PasswordComplexity)

    # ================================================================
    # STIG: WN11-AC-000020
    # ================================================================
    if ($needsHistoryChange) {
        Write-Host 'Password history is below the required minimum. It will be set to 24.'
    }
    else {
        Write-Host ("Password history is already compliant ({0}). No change is needed." -f $currentState.PasswordHistorySize) -ForegroundColor Green
    }

    # ================================================================
    # STIG: WN11-AC-000030
    # ================================================================
    if ($needsMinAgeChange) {
        Write-Host 'Minimum password age is below the required minimum. It will be set to 1 day.'
    }
    else {
        Write-Host ("Minimum password age is already compliant ({0}). No change is needed." -f $currentState.MinimumPasswordAge) -ForegroundColor Green
    }

    # ================================================================
    # STIG: WN11-AC-000035
    # ================================================================
    if ($needsMinLengthChange) {
        Write-Host 'Minimum password length is below the required minimum. It will be set to 14.'
    }
    else {
        Write-Host ("Minimum password length is already compliant ({0}). No change is needed." -f $currentState.MinimumPasswordLength) -ForegroundColor Green
    }

    # ================================================================
    # STIG: WN11-AC-000040
    # ================================================================
    if ($needsComplexityChange) {
        Write-Host 'Password complexity is not enabled. It will be enabled.'
    }
    else {
        Write-Host 'Password complexity is already enabled. No change is needed.' -ForegroundColor Green
    }

    if (-not ($needsHistoryChange -or $needsMinAgeChange -or $needsMinLengthChange -or $needsComplexityChange)) {
        return
    }

    Write-Host 'Applying password policy configuration...'
    Apply-SecurityPolicyConfiguration `
        -PasswordHistorySize 24 `
        -MinimumPasswordAge 1 `
        -MinimumPasswordLength 14 `
        -PasswordComplexity $true

    Set-ChangeFlag
}

function Invoke-Rollback {
    # Rollback restores a simple non-enforced lab baseline.
    Set-RebootPreference -Level 'NotRequired'

    $currentState = Get-CurrentState
    $rollbackState = Get-RollbackTargetState

    $needsRollback =
        ($currentState.PasswordHistorySize -ne $rollbackState.PasswordHistorySize) -or
        ($currentState.MinimumPasswordAge -ne $rollbackState.MinimumPasswordAge) -or
        ($currentState.MinimumPasswordLength -ne $rollbackState.MinimumPasswordLength) -or
        ($currentState.PasswordComplexity -ne $rollbackState.PasswordComplexity)

    if (-not $needsRollback) {
        Write-Host 'Password policy is already at the rollback baseline. No rollback change is needed.' -ForegroundColor Green
        return
    }

    Write-Host 'Restoring password policy to the rollback baseline...'
    Apply-SecurityPolicyConfiguration `
        -PasswordHistorySize 0 `
        -MinimumPasswordAge 0 `
        -MinimumPasswordLength 0 `
        -PasswordComplexity $false

    Set-ChangeFlag
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
    Write-Host '2. If the password policy settings are non-compliant, re-run this script with -Mode Apply.'
    Write-Host '3. Re-run your DISA STIG or Tenable compliance scan if you need independent validation.'
}
elseif ($Mode -eq 'Apply') {
    Write-Host '1. Review BEFORE STATE, DESIRED STATE, and AFTER STATE.'
    Write-Host '2. Re-run this script with -Mode Verify to confirm the final state.'
    Write-Host '3. Re-run your DISA STIG or Tenable compliance scan to validate the password policy findings.'
    Write-Host '4. Capture before/after screenshots or terminal output for project evidence.'
    Write-Host '5. If needed, sign out and sign back in before rescanning so local policy reporting is refreshed.'
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