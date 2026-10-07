#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Summarizes failed Windows logons (Event ID 4625) by source IP to help spot brute-force activity.

.DESCRIPTION
Reads failed logon events from the local Security event log for a configurable
time window, parses each event by property name, and groups the results by
source IP address. Each IP is reported with its attempt count, the number of
distinct usernames it targeted, and the first and last time it was seen. IPs
at or above the threshold are marked 'Suspicious'.

The script is read-only: it does not change any system state.

.PARAMETER Hours
How far back to search, in hours. Valid range is 1-720. Default is 24.

.PARAMETER Threshold
Number of failed attempts from a single source IP at or above which that IP is
marked 'Suspicious'. Valid range is 1-10000. Default is 10.

.PARAMETER OutputPath
Optional path to a CSV file for the summary. The parent folder must already exist.

.EXAMPLE
.\Get-FailedLogonReport.ps1

Summarizes failed logons from the last 24 hours using the default threshold of 10.

.EXAMPLE
.\Get-FailedLogonReport.ps1 -Hours 6 -Threshold 5 -OutputPath .\failed-logons.csv -Verbose

Looks back 6 hours, flags any IP with 5 or more failures, writes a CSV, and
shows verbose progress messages.

.INPUTS
None. This script does not accept pipeline input.

.OUTPUTS
System.Management.Automation.PSCustomObject
One object per source IP: SourceIp, FailedAttempts, UniqueUsernames, FirstSeen, LastSeen, Status.

.NOTES
Requires an elevated session because reading the Security log needs administrator rights.
Exit codes: 0 = no suspicious sources, 1 = at least one suspicious source, 2 = script error.
Event 4625 only exists if "Audit Logon" failure auditing is enabled on the machine.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$Hours = 24,

    [ValidateRange(1, 10000)]
    [int]$Threshold = 10,

    [ValidateScript({
        $dir = Split-Path -Path $_ -Parent
        if (-not $dir) { $dir = '.' }
        Test-Path -Path $dir -PathType Container
    })]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $startTime = (Get-Date).AddHours(-$Hours)
    Write-Verbose "Searching Security log for Event ID 4625 since $startTime"

    # Get-WinEvent throws when nothing matches, so treat that specific case as "zero events".
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625
            StartTime = $startTime
        })
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $events = @()
        }
        else {
            throw
        }
    }

    Write-Verbose "Found $($events.Count) failed logon event(s)"

    if ($events.Count -eq 0) {
        Write-Information "No failed logon events in the last $Hours hour(s)." -InformationAction Continue
        exit 0
    }

    # Parse each event by field name, not by position, because the order of
    # fields in the event data can differ between Windows versions.
    $parsed = foreach ($logEvent in $events) {
        $xml  = [xml]$logEvent.ToXml()
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            $data[$node.Name] = $node.InnerText
        }

        $ip = $data['IpAddress']
        if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq '-') {
            $ip = 'Unknown/Local'
        }

        [PSCustomObject]@{
            TimeCreated = $logEvent.TimeCreated
            TargetUser  = $data['TargetUserName']
            SourceIp    = $ip
        }
    }

    $summary = $parsed |
        Group-Object -Property SourceIp |
        ForEach-Object {
            $times = @($_.Group.TimeCreated | Sort-Object)

            [PSCustomObject]@{
                SourceIp        = $_.Name
                FailedAttempts  = $_.Count
                UniqueUsernames = @($_.Group.TargetUser | Sort-Object -Unique).Count
                FirstSeen       = $times[0]
                LastSeen        = $times[-1]
                Status          = if ($_.Count -ge $Threshold) { 'Suspicious' } else { 'Normal' }
            }
        } |
        Sort-Object -Property FailedAttempts -Descending

    if ($OutputPath) {
        $summary | Export-Csv -Path $OutputPath -NoTypeInformation
        Write-Verbose "Summary written to $OutputPath"
    }

    $summary

    if ($summary | Where-Object Status -eq 'Suspicious') {
        Write-Warning "One or more source IPs reached $Threshold or more failed logons in the last $Hours hour(s)."
        exit 1
    }
    exit 0
}
catch {
    Write-Error "Failed logon report failed: $($_.Exception.Message)"
    exit 2
}
