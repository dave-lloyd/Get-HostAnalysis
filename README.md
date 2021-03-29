# Get-HostAnalysis

This script is intended to provide a basic host analysis for potential issues. It was written for work based situations where requests are received to "check if there are any issues with the host". It's not exhaustive, but meant instead to give a quick overview. If you have vROPS or other such tooling, then that is obviously a better starting point.

Level of output is managed by the DetailLevel parameter, which accepts Summary or Full - default is Summary.

The analysis is the same, but in Summary mode, the review of the collected tasks/events, will simply show the number of matches, rather than detail. If Full is selected, then the additional detailed is displayed as part of the output. In addition, if any of the tasks/events checks returns more than 20 matches, the last 20 entries will be displayed, and a .csv file generated with all the matches.

## Sample usage :
    Get-HostAnalysis -vmhost samplehost.domain.local -NumEvents 1000 -DetailLevel Summary
    This runs the script against the host samplehost.domain.local and retrieves up to 1000 entries from the host Tasks and Events. Output is provided in summary form.

    Get-HostAnalysis -vmhost samplehost.domain.local -DetailLevel Summary
    This runs the script against the host samplehost.domain.local and retrieves up to the default 500 entries from the host Tasks and Events. Output is provided in summary form.

    Get-HostAnalysis -vmhost samplehost.domain.local -NumEvents 1000 -DetailLevel Summary
    This runs the script against the host samplehost.domain.local and retrieves up to 1000 entries from the host Tasks and Events. Output is provided in full form. Any events 
    that return more than 20 results, will generate .csv files with the full results.

## Code from other sources
It leverages code from other sources, notably :

* Get-vMotion function - Brian Bunke https://github.com/brianbunke/vCmdlets

Code within Get-HostAnalysis function :
* Active Alerts on host - https://blogs.vmware.com/PowerCLI/2019/11/new-vsphere-alarm-management.html
* Host hardware health status - https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/checking-esxi-hardware-for-problems-using-powercli/m-p/1373221
* pNIC -> vNIC mapping for vds - https://communities.vmware.com/t5/VMware-PowerCLI-Discussions/PowerCLI-function-to-get-Hosts-NICs-CDP-LLDP-vSwitch-Info-end-to/td-p/529693
* Dead paths - https://github.com/alanrenouf/vCheck-vSphere/blob/master/Plugins/30%20Host/08%20Hosts%20Dead%20LUN%20Path.ps1

