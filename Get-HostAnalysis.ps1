# Script and "helper" functions for quick host analysis/health check.


#################################################
#
# 3rd party helper function
# https://github.com/brianbunke/vCmdlets
#
#################################################
<#PSScriptInfo
.VERSION     1.2.0
.GUID        e4945281-2135-4365-a194-739fcf54456b
.AUTHOR      Brian Bunke
.DESCRIPTION Report on recent vMotion events in your VMware environment.
.COMPANYNAME brianbunke
.COPYRIGHT 
.TAGS        vmware powercli vmotion vcenter
.LICENSEURI  https://github.com/brianbunke/vCmdlets/blob/master/LICENSE
.PROJECTURI  https://github.com/brianbunke/vCmdlets
.ICONURI 
.EXTERNALMODULEDEPENDENCIES VMware.VimAutomation.Core
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
1.2.0 - 2019/05/09 - Add cluster output; replace ArrayList with Generic.List; apply ScriptAnalyzer recommendations
1.1.0 - 2017/10/24 - Support new Encrypted vMotion type in 6.5; localize time; add datacenter properties
1.0.1 - 2017/10/12 - Fix improper filtering on VCSA 6.5
1.0.0 - 2017/01/02 - Initial release
#>

#Requires -Version 3 -Module VMware.VimAutomation.Core

function Get-VMotion {
    <#
    .SYNOPSIS
    Report on recent vMotion events in your VMware environment.
    
    .DESCRIPTION
    Use to check DRS history, or to help with troubleshooting.
    vMotion and Storage vMotion events are returned by default.
    Can filter to view only results from recent days, hours, or minutes (default is 1 day).
    
    For performance, "Get-VMotion" is good. "Get-VM | Get-VMotion" is very slow.
    The cmdlet gathers and parses each entity's events one by one.
    This means that while one VM and one datacenter will have similar speeds,
    a "Get-VM | Get-VMotion" that contains 50 VMs will take a while.
    
    Get-VMotion has been tested on Windows 6.0 and VCSA 6.5 vCenter servers.
    
    "Get-Help Get-VMotion -Examples" for some common usage tips.
    
    .NOTES
    Thanks to lucdekens/alanrenouf/sneddo for doing the hard work long ago.
    http://www.lucd.info/2013/03/31/get-the-vmotionsvmotion-history/
    https://github.com/alanrenouf/vCheck-vSphere
    
    .EXAMPLE
    Get-VMotion
    By default, searches $global:DefaultVIServers (all open Connect-VIServer sessions).
    For all datacenters found by Get-Datacenter, view all s/vMotion events in the last 24 hours.
    VM name, vMotion type (compute/storage/both), start time, and duration are returned by default.
    
    .EXAMPLE
    Get-VMotion -Verbose | Format-List *
    For each s/vMotion event found in Example 1, show all properties instead of the default four.
    Verbose output tracks current progress, and helps when troubleshooting results.
    
    .EXAMPLE
    Get-Cluster '*arcade' | Get-VMotion -Hours 8 | Where-Object {$_.Type -eq 'vmotion'}
    For the cluster Flynn's Arcade, view all vMotions in the last eight hours.
    NOTE: Piping "Get-Datacenter" or "Get-Cluster" will be much faster than an unfiltered "Get-VM".
    
    .EXAMPLE
    Get-VM 'Sam' | Get-VMotion -Days 30 | Format-List *
    View hosts/datastores the VM "Sam" has been on in the last 30 days,
    when changes happened, and how long any migrations took to complete.
    When supplying VM objects, a generic warning displays once about result speed.
    
    .EXAMPLE
    $Grid = $global:DefaultVIServers | Where-Object {$_.Name -eq 'Grid'}
    PS C:\>Get-VM -Name 'Tron','Rinzler' | Get-VMotion -Days 7 -Server $Grid
    
    View all s/vMotion events for only VMs "Tron" and "Rinzler" in the last week.
    If connected to multiple servers, will only search for events on vCenter server Grid.
    
    .EXAMPLE
    Get-VMotion | Select-Object Name,Type,Duration | Sort-Object Duration
    For all s/vMotions in the last day, return only VM name, vMotion type, and total migration time.
    Sort all events from fastest to slowest.
    Selecting < 5 properties automatically formats output in a table, instead of a list.
    
    .INPUTS
    [VMware.VimAutomation.ViCore.Types.V1.Inventory.InventoryItem[]]
    PowerCLI cmdlets Get-Datacenter / Get-Cluster / Get-VM
    
    .OUTPUTS
    [System.Collections.ArrayList]
    [System.Management.Automation.PSCustomObject]
    [vMotion.Object] = arbitrary PSCustomObject typename, to enable default property display
    
    .LINK
    http://www.brianbunke.com/blog/2017/10/25/get-vmotion-65/
    
    .LINK
    https://github.com/brianbunke/vCmdlets
    #>
    [CmdletBinding(DefaultParameterSetName='Days')]
    [OutputType([System.Collections.ArrayList])]
    param (
        # Filter results to only the specified object(s)
        # Tested with datacenter, cluster, and VM entities
        [Parameter(ValueFromPipeline = $true)]
        [ValidateScript({$_.GetType().Name -match 'VirtualMachine|Cluster|Datacenter'})]
        [Alias('Name','VM','Cluster','Datacenter')]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.InventoryItem[]]$Entity,

        # Number of days to return results from. Defaults to 1
        # Mutually exclusive from Hours, Minutes
        [Parameter(ParameterSetName='Days')]
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Days = 1,
        # Number of hours to return results from
        # Mutually exclusive from Days, Minutes
        [Parameter(ParameterSetName='Hours')]
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Hours,
        # Number of minutes to return results from
        # Mutually exclusive from Days, Hours
        [Parameter(ParameterSetName='Minutes')]
        [ValidateRange(0,[int]::MaxValue)]
        [int]$Minutes,

        # Specifies the vCenter Server system(s) on which you want to run the cmdlet.
        # If no value is passed to this parameter, the command runs on the default servers.
        # For more information about default servers, "Get-Help Connect-VIServer".
        [VMware.VimAutomation.Types.VIServer[]]$Server = $global:DefaultVIServers
    )

    BEGIN {
        If (-not $Server) {
            throw 'Please open a vCenter session with Connect-VIServer first.'
        }
        Write-Verbose "Processing against vCenter server(s) $("'$Server'" -join ' | ')"

        # Based on parameter supplied, set $Time for $EventFilter below
        switch ($PSCmdlet.ParameterSetName) {
            'Days'    {$Time = (Get-Date).AddDays(-$Days).ToUniversalTime()}
            'Hours'   {$Time = (Get-Date).AddHours(-$Hours).ToUniversalTime()}
            'Minutes' {$Time = (Get-Date).AddMinutes(-$Minutes).ToUniversalTime()}
        }
        Write-Verbose "Using parameter set $($PSCmdlet.ParameterSetName)"
        Write-Verbose "Searching for all vMotion events since $($Time.ToLocalTime().ToString())"

        # Construct an empty array for events returned
        # Performs faster than @() when appending; matters if running against many VMs
        $Events = New-Object System.Collections.ArrayList

        # Build a vMotion-specific event filter query
        $EventFilter        = New-Object VMware.Vim.EventFilterSpec
        $EventFilter.Entity = New-Object VMware.Vim.EventFilterSpecByEntity
        $EventFilter.Time   = New-Object VMware.Vim.EventFilterSpecByTime
        $EventFilter.Time.BeginTime = $Time
        # After moving from Win 6.0 to VCSA 6.5, apparently the Category filter no longer works?
        # $EventFilter.Category = 'Info'
        $EventFilter.DisableFullMessage = $true
        $EventFilter.EventTypeID = @(
            'com.vmware.vc.vm.VmHotMigratingWithEncryptionEvent',
            'DrsVmMigratedEvent',
            'VmBeingHotMigratedEvent',
            'VmBeingMigratedEvent',
            'VmMigratedEvent'
        )
    } #Begin

    PROCESS {
        ForEach ($vCenter in $Server) {
            Write-Verbose "Searching for events in vCenter server '$vCenter'"
            Write-Verbose "Calling Get-View for EventManager against server '$vCenter'"
            $EventMgr = Get-View EventManager -Server $vCenter -Verbose:$false -Debug:$false

            If ($Entity) {
                # Acknowledge user-supplied inventory item(s)
                $InventoryObjects = $Entity
            } Else {
                # If -Entity was not specified, return datacenter object(s)
                Write-Verbose "Calling Get-Datacenter to process all objects in server '$vCenter'"
                $InventoryObjects = Get-Datacenter -Server $vCenter -Verbose:$false -Debug:$false
            }

            $InventoryObjects | ForEach-Object {
                Write-Verbose "Processing $($_.GetType().Name) inventory object $($_.Name)"

                # Warn once against using VMs in -Entity parameter
                If ($_.GetType().Name -match 'VirtualMachine' -and $null -eq $AlreadyWarned) {
                    Write-Warning 'Get-VMotion must process VM objects one by one, which slows down results.'
                    Write-Warning 'Consider supplying parent Cluster(s) or Datacenter(s) to -Entity parameter.'
                    $AlreadyWarned = $true
                }

                # Add the entity details for the current loop of the Process block
                $EventFilter.Entity.Entity = $_.ExtensionData.MoRef
                $EventFilter.Entity.Recursion = &{
                    If ($_.ExtensionData.MoRef.Type -eq 'VirtualMachine') {'self'} Else {'all'}
                }
                # Create the event collector, and collect 100 events at a time
                Write-Verbose "Calling Get-View to gather event results for object $($_.Name)"
                $CollectorSplat = @{
                    Server  = $vCenter
                    Verbose = $false
                    Debug   = $false
                }
                $Collector = Get-View ($EventMgr).CreateCollectorForEvents($EventFilter) @CollectorSplat
                $Buffer = $Collector.ReadNextEvents(100)

                If (-not $Buffer) {
                    Write-Verbose "No vMotion events found for object $($_.Name)"
                }

                While ($Buffer) {
                    $EventCount = ($Buffer | Measure-Object).Count
                    Write-Verbose "Processing $EventCount events from object $($_.Name)"

                    # Append up to 100 results into the $Events array
                    If ($EventCount -gt 1) {
                        # .AddRange if more than one event
                        $Events.AddRange($Buffer) | Out-Null
                    } Else {
                        # .Add if only one event; should never happen since gathering begin & end events
                        $Events.Add($Buffer) | Out-Null
                    }
                    # Were there more than 100 results? Get the next batch and restart the While loop
                    $Buffer = $Collector.ReadNextEvents(100)
                }
                # Destroy the collector after each entity to avoid running out of memory :)
                $Collector.DestroyCollector()
            } #ForEach $Entity

            $InventoryObjects = $null
        } #ForEach $vCenter
    } #Process

    END {
        # Construct an empty array for results within the ForEach
        $Results = New-Object System.Collections.Generic.List[object]

        # Group together by ChainID; each vMotion has begin/end events
        ForEach ($vMotion in ($Events | Sort-Object CreatedTime | Group-Object ChainID)) {
            # Each vMotion should have start and finish events
            # "% 2" correctly processes duplicate vMotion results
            # (duplicate results can occur, for example, if you have duplicate vCenter connections open)
            If ($vMotion.Group.Count % 2 -eq 0) {
                # New 6.5 migration event type is changing fields around on me
                If ($vMotion.Group[0].EventTypeID -eq 'com.vmware.vc.vm.VmHotMigratingWithEncryptionEvent') {
                    $DstDC   = ($vMotion.Group[0].Arguments | Where-Object {$_.Key -eq 'destDatacenter'}).Value
                    $DstDS   = ($vMotion.Group[0].Arguments | Where-Object {$_.Key -eq 'destDatastore'}).Value
                    $DstHost = ($vMotion.Group[0].Arguments | Where-Object {$_.Key -eq 'destHost'}).Value
                } Else {
                    $DstDC   = $vMotion.Group[0].DestDatacenter.Name
                    $DstDS   = $vMotion.Group[0].DestDatastore.Name
                    $DstHost = $vMotion.Group[0].DestHost.Name
                } #If 'com.vmware.vc.vm.VmHotMigratingWithEncryptionEvent'

                # Mark the current vMotion as vMotion / Storage vMotion / Both
                If ($vMotion.Group[0].Ds.Name -eq $DstDS) {
                    $Type = 'vMotion'
                } ElseIf ($vMotion.Group[0].Host.Name -eq $DstHost) {
                    $Type = 's-vMotion'
                } Else {
                    $Type = 'Both'
                }

                # Add the current vMotion into the $Results array
                $Results.Add([PSCustomObject][Ordered]@{
                    PSTypeName = 'vMotion.Object'
                    Name       = $vMotion.Group[0].Vm.Name
                    Type       = $Type
                    SrcHost    = $vMotion.Group[0].Host.Name
                    DstHost    = $DstHost
                    SrcDS      = $vMotion.Group[0].Ds.Name
                    DstDS      = $DstDS
                    SrcCluster = $vMotion.Group[0].ComputeResource.Name
                    DstCluster = $vMotion.Group[1].ComputeResource.Name
                    SrcDC      = $vMotion.Group[0].Datacenter.Name
                    DstDC      = $DstDC
                    # Hopefully people aren't performing vMotions that take >24 hours, because I'm ignoring days in the string
                    Duration   = (New-TimeSpan -Start $vMotion.Group[0].CreatedTime -End $vMotion.Group[1].CreatedTime).ToString('hh\:mm\:ss')
                    StartTime  = $vMotion.Group[0].CreatedTime.ToLocalTime()
                    EndTime    = $vMotion.Group[1].CreatedTime.ToLocalTime()
                    # Making an assumption that all events with an empty username are DRS-initiated
                    Username   = &{If ($vMotion.Group[0].UserName) {$vMotion.Group[0].UserName} Else {'DRS'}}
                    ChainID    = $vMotion.Group[0].ChainID
                })
            } #If vMotion Group % 2
            ElseIf ($vMotion.Group.Count % 2 -eq 1) {
                Write-Debug "vMotion chain ID $($vMotion.Group[0].ChainID -join ', ') had an odd number of events; cannot match start/end times. Inspect `$vMotion for more details"
                # If you're here, try to gather some details and tell me what happened! @brianbunke
            }
        } #ForEach ChainID

        # Reduce default property set for readability
        $TypeData = @{
            TypeName = 'vMotion.Object'
            DefaultDisplayPropertySet = 'Name','Duration','Type','StartTime', 'srcHost','dstHost'
        }
        # Include -Force to avoid errors after the first run
        Update-TypeData @TypeData -Force

        # Display all results found
        $Results
    } #End
} # End Get-vMotion

#################################################
#
# End 3rd party helper function
#
#################################################


#################################################
#
# Helper functions
#
#################################################

Function Get-MyVMHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$vmhost
    )

    $TP = "-30" # time period - 30 days

    # Gather host info that we can work with
    Try {
        $ESXiHost = Get-VMHost $vmhost -ErrorAction Stop
    } Catch {
        Write-Host " Unable to find a host with that name." -ForegroundColor Red
        Read-Host "Press ENTER to exit`n"
        Break
    }

    # Gather info about the (hopefully) connected datastores
    $TotalDatastores = $ESXiHost | Get-Datastore
    $ConnectedDatastores = $TotalDatastores | Where-Object {$_.State -eq "Available"} # hopefully this will be the same number as the total datastores ...

    # Gather info about the VMs on this host.
    $VMsPerHost = $ESXiHost | Get-VM
    $RunningVMs = $VMsPerHost | Where-Object {$_.powerstate -eq "PoweredOn"}
    $AllocatedCPUs = $RunningVMs | Measure-Object -Property numcpu -Sum | Select-Object -ExpandProperty sum
    $AllocatedMemory = $RunningVMS | Measure-Object -Property MemoryGB -Sum | Select-Object -ExpandProperty sum
    if ($ESXiHost.IsStandalone) { $clusterName = 'Standalone' } else { $clusterName = $ESXiHost.Parent.Name }				

    # Work out some performance figures
    $hoststat = "" | Select-Object HostName, MemMax, MemAvg, MemMin, CPUMax, CPUAvg, CPUMin, Ballooning
    $statcpu = Get-Stat -Entity ($ESXiHost)-start (get-date).AddDays($TP) -Finish (Get-Date)-MaxSamples 10000 -stat cpu.usage.average
    $statmem = Get-Stat -Entity ($ESXiHost)-start (get-date).AddDays($TP) -Finish (Get-Date)-MaxSamples 10000 -stat mem.usage.average
    $hostBallooning =  Get-Stat -Entity ($ESXiHost)-start (get-date).AddDays($TP) -Finish (Get-Date)-MaxSamples 10000 -stat mem.vmmemctl.average

    $cpu = $statcpu | Measure-Object -Property value -Average -Maximum -Minimum
    $mem = $statmem | Measure-Object -Property value -Average -Maximum -Minimum
    $ballooning = $hostBallooning | Measure-Object -Property value -Average -Maximum -Minimum
    
    $hoststat.CPUMax = [math]::round($cpu.Maximum, 2)
    $hoststat.CPUAvg = [math]::round($cpu.Average, 2)
    $hoststat.CPUMin = [math]::round($cpu.Minimum, 2)
    $hoststat.MemMax = [math]::round($mem.Maximum, 2)
    $hoststat.MemAvg = [math]::round($mem.Average, 2)
    $hoststat.MemMin = [math]::round($mem.Minimum, 2)
    $hoststat.Ballooning = [math]::round($ballooning.Maximum, 2)

    # Determine the host uptime and boot date
    $Uptime = $Esxihost | Select-Object @{N = "Uptime"; E = { New-Timespan -Start $_.ExtensionData.Summary.Runtime.BootTime -End (Get-Date) | Select-Object -ExpandProperty Days } }
    $hostUptime = $Uptime.uptime

    # Pop all the info into a custom object that we can then output.
    $ESXinfo = [PSCustomObject]@{
        Hypervisor                  = $ESXiHost.Name
        Cluster                     = $clusterName
        ConnectionState             = $ESXiHost.ConnectionState
        "Boot time (UTC)"           = $ESXiHost.ExtensionData.Summary.Runtime.BootTime
        "Uptime (days)"             = $hostUptime
        Vendor                      = $ESXiHost.ExtensionData.Summary.Hardware.Vendor
        Model                       = $ESXiHost.ExtensionData.Summary.Hardware.Model
        Version                     = $ESXiHost.Version
        Build                       = $ESXiHost.Build
        CpuModel                    = $ESXiHost.ExtensionData.Summary.Hardware.CpuModel
        CpuSockets                  = $ESXiHost.ExtensionData.Summary.Hardware.NumCpuPkgs
        CpuCores                    = $ESXiHost.ExtensionData.Summary.Hardware.NumCpuCores
        CpuThreads                  = $ESXiHost.ExtensionData.Summary.Hardware.NumCpuThreads
        "Memory (GB)"               = [math]::round($ESXiHost.MemoryTotalGB)
        "Total datastores"          = $TotalDatastores.Count
        "Connected Datastores"      = $ConnectedDatastores.Count
        "Total VMs"                 = $VMsPerHost.Count
        "Running VMs"               = $RunningVMs.Count
    }     

    $ESXPerformance = [PSCustomObject]@{
        "Allocated CPUs"            = $AllocatedCPUs
        "CPU Ratio"                 = "$("{0:N2}" -f ($AllocatedCPUs/$ESXiHost.ExtensionData.Summary.Hardware.NumCpuThreads))" + " : 1"
        "Current memory usage (GB)" = [math]::round($ESXiHost.MemoryUsageGB)
        "Allocated memory (GB)"     = $AllocatedMemory
        "30 days Max CPU (%)"       = $hoststat.CPUMax
        "30 days Min CPU (%)"       = $hoststat.CPUMin
        "30 days Avg CPU (%)"       = $hoststat.CPUAvg
        "30 days Max Mem (%)"       = $hoststat.MemMax
        "30 days Min Mem (%)"       = $hoststat.MemMin
        "30 days Avg Mem (%)"       = $hoststat.MemAvg
        "Ballooning"                = $hoststat.Ballooning
    }     

    Write-Host "`b complete :" -ForegroundColor Magenta
    Write-Host "///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta

    Write-Host "Host summary.`n-------------" -NoNewline
    $ESXinfo | Out-Host

    Write-Host "Host performance overview.`n--------------------------" -NoNewline
    $ESXPerformance | Out-Host
    Write-Host "`nPlease use these figures as a guide only. If there is a concern about performance, review more closely.`n" -ForegroundColor Green


    Return $ESXiHost
} # End Get-MyVMHost

#################################################
#
# Main function
#
#################################################

Function Get-HostAnalysis {
    <#
    .SYNOPSIS
        Basic ESXi triage/review/healthcheck script, designed to quickly check the host for any clear and obvious issues.
    .DESCRIPTION
        The script will perform a basic review of the specified host, to review if there are any obvious issues observed.

        It will pull and check from the tasks and events on the host (using Get-VIEvent) - default is 500, otherwise, set -NumEvents to the required amount.

        If some of the checks result in more than 20 events, the latest 20 will be displayed, and the full list will be output to .csv for further review.

        In the console output :
        1) Warnings will be in yellow
        2) Errors or alerts to definitely check, in red.

        Anything in these colours should definitely be investigated further.
    .PARAMETER vmhost
        ESXi host to review
    .PARAMETER NumEvents
        Maximum number of tasks and events entries to retrieve as part of the review. Default is 500.
    .PARAMETER DetailLevel
        Controls how much information to output. Summary will just state the number of matches for checks against the tasks and events, whereas full will display the results.
        If full is selected, and a check returns more than 20 entries, the latest 20 will be displayed to console, and all the matches will be output to .csv file 
    .EXAMPLE
        Get-HostAnalysis -vmhost samplehost.domain.local -NumEvents 1000 -DetailLevel Summary
        This runs the script against the host samplehost.domain.local and retrieves up to 1000 entries from the host Tasks and Events. Output is provided in summary form.
    .EXAMPLE
        Get-HostAnalysis -vmhost samplehost.domain.local -DetailLevel Summary
        This runs the script against the host samplehost.domain.local and retrieves up to the default 500 entries from the host Tasks and Events. Output is provided in summary form.
    .EXAMPLE
        Get-HostAnalysis -vmhost samplehost.domain.local -NumEvents 1000 -DetailLevel Summary
        This runs the script against the host samplehost.domain.local and retrieves up to 1000 entries from the host Tasks and Events. Output is provided in full form. Any events 
        that return more than 20 results, will generate .csv files with the full results.
    .NOTES
        Author          : Dave Lloyd
        Version         : 0.1

        Get-vMotion function - Brian Bunke https://github.com/brianbunke/vCmdlets

        Code within Get-HostAnalysis function :
            Active Alerts on host - https://blogs.vmware.com/PowerCLI/2019/11/new-vsphere-alarm-management.html
            Host hardware health status - https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/checking-esxi-hardware-for-problems-using-powercli/m-p/1373221
            pNIC -> vNIC mapping for vds - https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/PowerCLI-function-to-get-Hosts-NICs-CDP-LLDP-vSwitch-Info-end-to/td-p/529693
            Dead paths - https://github.com/alanrenouf/vCheck-vSphere/blob/master/Plugins/30%20Host/08%20Hosts%20Dead%20LUN%20Path.ps1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string]$vmhost,
        
        [Parameter(Mandatory = $False)]
        $NumEvents = 500, # default

        [Parameter(Mandatory = $False)]
        [ValidateSet('Summary', 'Full')] 
        [string]$DetailLevel = "Summary"
    )
    
    ###########################################################################################
    # Some variables.
    ###########################################################################################
    $OutputMsgSizeThreshold = 20 # If we get more messages in output than this, we'll display this many, and output the full list to .csv
    $EventsToCheckForVMHA = 10000 # Max samples to collect in order to check for VM HA restart events - these don't come from the host, so collect seperately.

    ###########################################################################################
    # Gather info for common checks and configuration details.
    ###########################################################################################
    Write-Host "`n///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "Gathering host information ....." -ForegroundColor Magenta -NoNewline
    $ESXiHost = Get-MyVMHost $vmhost

    # List of VMs on host - include VMwareTools status just because people like to ask if they're running/up to date ...
    $VMsOnHost = $ESXiHost| Get-VM
    $RunningVMs = $VMsOnHost | Where-Object {$_.powerstate -eq "PoweredOn"} | Select-Object Name, MemoryGB, numCPU,
        @{ n = "VMware Tools Status"; E = {$_.ExtensionData.Guest.ToolsStatus } },
        @{ n = "VMware Tools Version"; E = {$_.ExtensionData.Guest.ToolsVersion } }

    # Check for memory ballooning and swapping 
    $VMsWithBallooning = $VMsOnHost | where-Object {$_.ExtensionData.Summary.QuickStats.BalloonedMemory -ne 0} | Select-Object Name

    # Are there any active alerts on the host
    # https://blogs.vmware.com/PowerCLI/2019/11/new-vsphere-alarm-management.html
    $entity = $ESXiHost
    $alarmOutput = @()
    foreach ($alarm in $entity.ExtensionData.TriggeredAlarmState) {
        $tempObj = "" | Select-Object -Property Entity, Alarm, AlarmStatus, AlarmTime
        $tempObj.Entity = Get-View $alarm.Entity | Select-Object -ExpandProperty Name
        $tempObj.Alarm = Get-View $alarm.Alarm | Select-Object -ExpandProperty Info | Select-Object -ExpandProperty Name
        $tempObj.AlarmStatus = $alarm.OverallStatus
        $tempObj.AlarmTime = $alarm.Time
        $alarmOutput += $tempObj
    }

    # Now, let's get all the events - will use for subsequent checks
    Write-Host "///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "Gathering tasks and events entries for review ....." -ForegroundColor Magenta 
    $AllHostEvents = Get-VIEvent -Entity $vmHost -MaxSamples $NumEvents
    $GetEnvironmentEvents = Get-VIEvent -Start (Get-Date).AddDays(-5) -MaxSamples $EventsToCheckForVMHA -Types Warning # For checking for VM HA restarts

    Write-Host "///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "`n$NumEvents specified, " $AllHostEvents.Count "collected from host.`n" -ForegroundColor Green
    Write-Host $GetEnvironmentEvents.count "environment events collected to analyze for any VM HA restarts.`n" -ForegroundColor Green
    ###########################################################################################
    # Analyze the events
    ###########################################################################################
    Write-Host "`n///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "Analyzing the collected tasks and events" -ForegroundColor Magenta
    Write-Host "///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta

    # Check if there have been any VMs vMotioned on to or off of the host.
    $vMotionEvents = Get-VMotion
    $vMotionsToFromHost = $vMotionEvents | Where-Object {$_.srcHost -eq $vmhost -or $_.dstHost -eq $vmhost}

    $HAEvents = $GetEnvironmentEvents | Where-Object {$_.FullFormattedMessage -like "*vSphere HA restarted virtual machine*"}
    $ClusterMatch = $ESXihost.parent.name # Cluster to try and match the HA events with the cluster the host we're checking resides in.
    $HARestarts = $HAEvents | Where-Object {$_.FullFormattedMessage -like "*$ClusterMatch*"} | Select-Object ObjectName, CreatedTime, FullFormattedMessage 

    # Check the host hardware health status for any irregularities
    # https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/checking-esxi-hardware-for-problems-using-powercli/m-p/1373221
    foreach($esx in $ESXihost){
        $hs = Get-View -Id $esx.ExtensionData.ConfigManager.HealthStatusSystem
        $hostHealthStatus  = $hs.Runtime.SystemHealthInfo.NumericSensorInfo |
            Where-Object{$_.HealthState.Label -ne 'Green' -and $_.Name -notmatch 'Rollup'} |
            Select-Object @{N='Host';E={$esx.Name}},Name,@{N='Health';E={$_.HealthState.Label}}
    }

    # Check vmnic status for any physical nics that are showing as down.
    $HostNICDetails = (Get-ESXcli -V2 -VMHost $vmhost).network.nic.list.Invoke() | Where-Object {$_.linkstatus -eq "down"} | 
        Select-Object Name, Description, Link, LinkStatus | Format-Table -AutoSize

    # Get the pNIC -> vSwitch mapping        
    # vds - https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/PowerCLI-function-to-get-Hosts-NICs-CDP-LLDP-vSwitch-Info-end-to/td-p/529693
    $netSys = Get-View -Id $ESXiHost.ExtensionData.ConfigManager.NetworkSystem
    $vdsHostNICDetails = $netSys.NetworkInfo.ProxySwitch |
    ForEach-Object -Process {
        $vds = $_
        $vds.Pnic |
        Select-Object @{N='Switch';E={$vds.DvsName}},
            @{N='Type';E={'VDS'}},
            @{N='pNIC';E={$_.Split('-')[-1]}}
    }

    # Standard vSwitch
    $vmnicAssignment = $ESXihost | Get-VirtualSwitch | Where-Object {$_.nic -ne $null} | Select-Object Name, NIC                            

    # HBAs    
    $HBAList = $ESXiHost | Get-VMHostHba | Where-Object {$_.type -eq "FibreChannel"} #|  Select-Object Name, Type, Status, Model, NodeWorldWideName, PortWorldWideName
    $HBAStatus = ForEach ($HBA in $HBAList) {
        If ($HBA.Status -eq "offline") {
            Write-Host $HBA.Name "is in state :" $HBA.Status -ForegroundColor Red
        }
    }

    # Check for dead paths - based off the dead paths plugin from vCheck script
    # https://github.com/alanrenouf/vCheck-vSphere/blob/master/Plugins/30%20Host/08%20Hosts%20Dead%20LUN%20Path.ps1
    $deadluns = @()
    foreach ($esxhost in (Get-VMHost $ESXihost | Get-View | Where-Object { $_.Runtime.ConnectionState -match "Connected|Maintenance" })) {
        $esxhost | Foreach-Object { $_.config.storageDevice.multipathInfo.lun } | Foreach-Object { $_.path } | Where-Object { $_.State -eq "Dead" } | Foreach-Object {
            $myObj = New-Object PSObject -Property @{
                VMHost  = $esxhost.Name
                Lunpath = $_.Name
                State   = $_.state
            }
            $deadluns += $myObj
        }
    }

    ###########################################################################################
    # Output results
    ###########################################################################################
    Write-Host "`n`n///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "Results and findings" -ForegroundColor Magenta
    Write-Host "///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta

    # Running VMs and VMware Tools status
    Write-Host "Check : What VMs are currently running on the host and their VMware Tools status" -ForegroundColor Cyan
    $RunningVMs | Format-Table -Autosize

    Write-Host "`nCheck : Do any running VMs have ballooning?" -ForegroundColor Cyan
    If ($VMsWithBallooning) {
        Write-Host "Following VMs have ballooning." -ForegroundColor Red
        $VMsWithBallooning | Out-Host
    } else {
        Write-Host "`tNo VMs currently with ballooning" -ForegroundColor Green
    }

    Write-Host "`nCheck : Are any physical network adapters down, and if so, do they belong to a vSwitch" -ForegroundColor Cyan
    # vmnics showing as down - if any
    If ($HostNICDetails) {
        Write-Host "`nCurrent vmnic's that show as down - this doesn't necessarily mean there's an issue, as they may be always down." -ForegroundColor Yellow -NoNewline
        $HostNICDetails | Out-Host
    } else {
        Write-Host "`tNo physical NICs appear to be down" -ForegroundColor Green
    }

    Write-Host "`nvSwitch -> vmnic assignment" -ForegroundColor Cyan
    If ($vmnicAssignment) {
        Write-Host "Standard vSwitch" -ForegroundColor Green -NoNewline
        $vmnicAssignment | Out-Host
    }

    If ($vdsHostNICDetails) {
        Write-Host "vDS" -ForegroundColor Green -NoNewline
        $vdsHostNICDetails | Out-Host
    }

    Write-Host "Check : Any HBAs showing as NOT in 'online' state " -ForegroundColor Cyan
    If ($HBAStatus) {
        $HBAStatus | Out-Host
    } else {
        Write-Host "`tAll HBA's are showing as online." -ForegroundColor Green
    }

    # What do the hosts in the cluster have in terms of datastores.
    $DatastoreDifference = $False
    $TCDS = $ESXiHost | Get-Datastore | Where-Object {$_.State -eq "Available"} # TCDS = TotalConnectedDataStores
    Write-Host "`nCheck : Datastore count against other hosts in the cluster." -ForegroundColor Cyan
    Foreach ($vmh in Get-Cluster $ESXihost.parent.name | Get-VMHost) {
        $DStore = $vmh | Get-Datastore
        If ($DStore.count -ne $TCDS.count) {
            Write-Host "`t$vmh in the cluster has a different number of datastores connected - please review" -ForegroundColor Red
            $DatastoreDifference = $true
        }
    }
    If ($DatastoreDifference -eq $False) {
        Write-Host "`tAll hosts in the cluster have the same number of datastores in an available state." -ForegroundColor Green
    }

    Write-Host "`nCheck : Checking LUNs for any dead paths" -ForegroundColor Cyan
    If ($deadluns) {
        Write-Host "`tLUNs with dead paths detected - please investigate further." -ForegroundColor Red
        $deadluns | Out-Host
    } else {
        Write-Host "`tNo LUNs with dead paths detected." -ForegroundColor Green
    }

    Write-Host "`nCheck : any recent vMotions to and from the host" -ForegroundColor Cyan
    If ($vMotionsToFromHost.count -gt 0) {
            Write-Host "The following vMotions to/from the host are logged." -ForegroundColor Green
            $vMotionsToFromHost | Format-Table -AutoSize
    } else {
        Write-Host "`tNo vMotion details in the events." -ForegroundColor Green        
    }

    Write-Host "`nCheck : any VM HA restart events for the cluster." -ForegroundColor Cyan
    If ($HARestarts) {
        $vmHAEventsLog = "$Global:DefaultVIServer-VMHARestarts.csv"
        Write-Host "`tThe following VM HA restart events are logged within the cluster." -ForegroundColor Red
        Write-Host "`tPlease review further to see if they are related to the specific host."
        Write-Host "`tNote that times given will be based on the timezone will be local to the system you are running this from"
        Write-Host "`tFile generated as $vmHAEventsLog"
        $HARestarts | Export-CSV -NoTypeInformation -Path $vmHAEventsLog
        $HARestarts | Format-List
    } else {
        Write-Host "`tNo VM HA restart events found" -ForegroundColor Green
    }

    Write-Host "`nCheck : system health status" -ForegroundColor Cyan
    if ($hostHealthStatus) {
        # We have some 
        # Is the summary option selected
        If ($DetailLevel -eq "Summary") {
            # Just say alarms found
            Write-Host "`tSystem health status alerts found" -ForegroundColor Red
            Write-Host "`tRe-run script with DetailLevel = full to get the full details." -ForegroundColor Green
        } else {
            # Are there more than 20 
            If ($hostHealthStatus.count -gt $OutputMsgSizeThreshold) {
                # provide 20 and generate .csv
                Write-Host "More than 20 System health status alerts found - displayed latest 20" -ForegroundColor Red
                $hostHealthStatus | Sort-Object -Property CreatedTime | Select-Object CreatedTime, FullFormattedMessage -First 20 | Format-List
            } else {
                # less than 20 - show full list
                Write-Host "System health status alerts found" -ForegroundColor Red
                $hostHealthStatus | Out-Host
            }
        }
    } else {
        # No alarms found
        Write-Host "`tNo system health status errors found." -ForegroundColor Green
    }

    Write-Host "`nCheck : any active Alarms on host" -ForegroundColor Cyan
    If ($alarmOutput) {
        Write-Host "`tActive alarms found." -ForegroundColor Yellow
        $alarmOutput | Format-Table -AutoSize
    } else {
        Write-Host "`tNo active alarms on the host." -ForegroundColor Green
    }

    Write-Host "`n`n///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "Checks of the collected tasks and events." -ForegroundColor Magenta
    Write-Host "///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta

    # array of the patterns we're going to be searching for in the collected tasks and events.
    $alertType = "error","alarm","not responding","host connection and power state","vmnic","Host CPU usage","Host Memory Usage","Lost access to volume","PDL","All Paths Down"

    foreach ($alert in $alertType) {
        Write-Host "`nCheck : any '$alert' type events" -ForegroundColor Green    
        $errorCheck = "*$alert*"
        $ErrorsFound = $AllHostEvents | Where-Object {$_.FullFormattedMessage -like $errorCheck}
    
        if ($ErrorsFound) {
            If ($DetailLevel -eq "Summary") {
                Write-Host "`t" $ErrorsFound.count " events found." -ForegroundColor Red
                Write-Host "`tRe-run script with DetailLevel = full to get the full details." -ForegroundColor Green    
            } else {    
                If ($ErrorsFound.count -gt $OutputMsgSizeThreshold) {
                    Write-Host "`tEvents found - last 20 presented here to review to see if there is anything that may be applicable" -ForegroundColor Red
                    Write-Host "`tFull list being exported to .csv. Please review this further." -ForegroundColor Red
                    $LogFile = "$vmhost-$alert-events.csv"
                    $ErrorsFound | Sort-Object -Property CreatedTime | Select-Object CreatedTime, FullFormattedMessage -Last 20 | Format-List
                    $ErrorsFound | Export-CSV -NoTypeInformation $LogFile
                    Write-Host "`nFile generated as $LogFile"
        
                } else {
                    Write-Host "`tEvents found - please review to see if there is anything that may be applicable" -ForegroundColor Red
                    $ErrorsFound | Sort-Object -Property CreatedTime | Select-Object CreatedTime, FullFormattedMessage | Format-List                
                }
            }
        } else {
            Write-Host "`tNo '$alert' type events found" -ForegroundColor Green
        }
    }
    
    Write-Host "`n///////////////////////////////////////////////////////////////////////////" -ForegroundColor Magenta
    Write-Host "Analysis complete. Please review" -ForegroundColor Magenta
    Write-Host "///////////////////////////////////////////////////////////////////////////`n" -ForegroundColor Magenta

    $Recommendations = @"
    * From the host details, check the uptime - if it's looking suspicious, investigate further.

    * Check the CPU ratio, just in case it's higher than we would recommend - in excess of 4 : 1

    * Check the number of running VMs on the host, and also the results of running VMs (what's the 
    VMware Tools status) and whether there are any ballooning or not.

    * Take note of the CPU and memory values (though do take them with a pinch of salt), but in 
    the event that they are high, and for example, the CPU ratio is high, or we see memory and 
    CPU alerts later in the report, then maybe we do have a resource issue.

    * This ties in as well with whether any VMs are reporting ballooning - if they are, at least 
    review the memory allocation and usage values.

    * For the NICs, if there are any NICs reported as down (likely), try to check whether they are 
    assigned in the virtual switches, either standard or distributed. If they are, then check this 
    out, if not, then it likely just means that there's no connection to that physical NIC, and so 
    we can ignore this.

    * For HBAs, if there are any that are not in an online state, review if this is expected - not
    all the HBAs present may actually be being used, so this may be ok.

    * If there are system health alerts, then these need to be checked out, and likely arrange a 
    maintenenance to correct them.

    * Any active alarms should also obviously be reviewed, and determined if they have any bearing
    on the issue the host is being reviewed for - if not, they should still look to be addressed.

"@
    
    $DisplayRecommendations = Read-Host "Do you wish to see recommendations - Y/N"
    If ($DisplayRecommendations -eq "Y") {
        $Recommendations
    }

} # End Get-HostAnalysis
