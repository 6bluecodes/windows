#================================================================================
# Test_Windows_server_check.ps1 - windows server check pre and post migration
# Auther: Suyog.mahajan@Test.net
# Version - 1.2 [15thJune, 2021]
#
# 	Server checks (Windows), Test OS - windows 2012 r2, windows 2016, windows 2019, windows 10
#   Run this script locally on server for which information is to be collected
# v1.1 - updated 
# v1.2 - updated TopMemory script paramters, corrected description in server CPU details, IPv6 DisabledComponents value 
#================================================================================


#CSS codes
$header = @"
<style>

    h1 {
            font-family: Arial, Helvetica, sans-serif;
        color: #ff9900;
        font-size: 36px;
    }

    
    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
    }

    h3 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000033;
        font-size: 12px;
    }
   
   table {
		font-size: 12px;
		border: 1px solid black; 
		font-family: Arial, Helvetica, sans-serif;
        margin-left:50px;
	} 
	    td {
		padding: 4px;
		margin: 0px;
		border: 1px solid black;
	}
        th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

        tbody tr:nth-child(even) {
        background: #d6d6db;
    }
    
    #CreationDate {
        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;
    }

    .StopStatus {
        color: #ff0000;
    }
    
    .RunningStatus {
        color: #008000;
    }

</style>
"@

#The command below will get the name of the computer
$ComputerName = "<h1>COMPUTER NAME: $env:computername</h1>"
$CDate = "<h3>REPORT CREATED ON: $(Get-Date) by user $env:USERNAME using $env:USERDOMAIN domain credentials</h3>"
$login = "<h2>Report was executed by user $env:USERNAME using $env:USERDOMAIN domain credentials</h2>" 

#The command below will get the server memory and cpu usage details
$Processor = (Get-WmiObject win32_processor -ErrorAction Stop | Measure-Object -Property LoadPercentage -Average | Select-Object Average).Average
$ComputerMemory = Get-WmiObject win32_operatingsystem -ErrorAction Stop
$Memory = ((($ComputerMemory.TotalVisibleMemorySize - $ComputerMemory.FreePhysicalMemory)*100)/ $ComputerMemory.TotalVisibleMemorySize)
$RoundMemory = [math]::Round($Memory, 2)
$CPUusage = "<h2>$env:COMPUTERNAME has memory usage $Roundmemory % and cpu usage $processor % while running report</h2>" 

#The command below will get the server memory and cpu installed details
$CPUcount = systeminfo | findstr /C:”Processor” |%{"$_<br/>"}
$totalMemory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1gb
$TMemory = "<h2>$env:COMPUTERNAME has Memory: $totalMemory GB and Socket $CPUcount </h2>"

#The command below will get the Operating System information, convert the result to HTML code as table and store it to a variable
$OSinfo = Get-CimInstance Win32_OperatingSystem | ConvertTo-Html -As List -Property CSName,Version,Caption,OSArchitecture,BuildNumber,Manufacturer,InstallDate,LastBootUpTime,WindowsDirectory -Fragment -PreContent "<h2>Operating System Information</h2>"

#The command below will get the Processor information, convert the result to HTML code as table and store it to a variable
$ProcessInfo = Get-CimInstance Win32_Processor | ConvertTo-Html -As table -Property DeviceID,Name,Caption,MaxClockSpeed,SocketDesignation,Manufacturer,NumberOfCores,ThreadCount -Fragment -PreContent "<h2>Processor Information</h2>"

#The command below will get the Processor information, convert the result to HTML code as table and store it to a variable
$MemoryInfo = Get-CimInstance Win32_PhysicalMemory | ConvertTo-Html -As table -Property Tag,Manufacturer,PartNumber,Speed,DeviceLocator,Capacity -Fragment -PreContent "<h2>Memory Information</h2>"


#The command below will get the BIOS information, convert the result to HTML code as table and store it to a variable
$BiosInfo = Get-CimInstance  Win32_BIOS | ConvertTo-Html -As Table -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber -Fragment -PreContent "<h2>BIOS Information</h2>"

#The command below will get the details of Disk, convert the result to HTML code as table and store it to a variable
$DiscInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select DeviceID, DriveType,VolumeName,
@{N='TotalSize(GB)';E={[Math]::Ceiling($_.Size/1GB)}}, @{N='FreeSize(GB)';E={[Math]::Ceiling($_.FreeSpace/1GB)}}| ConvertTo-Html -As Table -Fragment -PreContent "<h2>Disk Information</h2>"

#The command below will get services information, convert the result to HTML code as table and store it to a variable
$ServicesInfo = Get-CimInstance Win32_Service | Sort-Object DisplayName |ConvertTo-Html -Property DisplayName,Name,StartMode,State -Fragment -PreContent "<h2>Services Information</h2>"
$ServicesInfo = $ServicesInfo -replace '<td>Running</td>','<td class="RunningStatus">Running</td>'
$ServicesInfo = $ServicesInfo -replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'

#The command below will get the name of the automatic stopped services
$Agentservice = Get-WmiObject Win32_Service | Where {($_.DisplayName -like "*Splunk*") -or ($_.DisplayName -like "*Trend*") -or ($_.DisplayName -like "*Tripwire*") } | Sort-Object DisplayName |ConvertTo-Html -Property DisplayName,Name,StartMode,State -Fragment -PreContent "<h2>Agent services</h2>"
$Agentservice = $Agentservice -replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'
$Agentservice = $Agentservice -replace '<td>Running</td>','<td class="RunningStatus">Running</td>'

#The command below will get the name of the automatic stopped services
$AutoServicesInfo = Get-WmiObject Win32_Service -Filter "state = 'stopped' AND startmode = 'auto'" | Sort-Object DisplayName |ConvertTo-Html -Property DisplayName,Name,StartMode,State -Fragment -PreContent "<h2>Automatic service in Stopped state</h2>"
$AutoServicesInfo = $AutoServicesInfo -replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'

#The command below will get the local user information
$localusers = Get-WmiObject Win32_UserAccount -Filter  "LocalAccount='True'" | ConvertTo-Html -As Table -Property Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, PasswordExpires, SID -Fragment -PreContent "<h2>Local Users</h2>"

#The command below will get the local Groups information
$localGroups = Get-LocalGroup | ConvertTo-Html -As Table -Property Name,Description -Fragment -PreContent "<h2>Local Groups</h2>"

#The command below will get the local Guests group members 
$localAdminGroupMemebers = Get-LocalGroupMember -Group Administrators | ConvertTo-Html -As Table -Property Name,PrincipleSource -Fragment -PreContent "<h2>Local Administrators Group Members</h2>"

#The command below will get the share folder information 
$ShareFolders = get-WmiObject Win32_Share -computer . | ConvertTo-Html -As Table -Property Name,Path,Description -Fragment -PreContent "<h2>Shares</h2>" 

#The command below will get the routes details on computer 
$routetable = Get-NetRoute | ConvertTo-Html -As Table -Property ifIndex,DestinationPrefix,NextHop,RouteMetric,ifMetric,PolicyStore -Fragment -PreContent "<h2>Route Details</h2>" 

#The command below will get the ipconfig details on computer 
$ip = "<h2>Server IP configuration</h2>"
$ipconfig = ipconfig /all |%{"$_<br/>"}

#The command below will get the route details on computer 
$RprintHead = "<h2>Static routes</h2>"
$Rprint = route print |%{"$_<br/>"}


#The command below will get the OS activation details on computer 
$OSA = "<h2>OS activation details</h2>"
$KMS = cscript C:\Windows\System32\slmgr.vbs /dlv |%{"$_<br/>"}

#The command below will get the Nslookup details
#mention the server name against which nslookup is to made

#$Server_Nslookup = Read-Host -prompt "Mention the server name against which Nslookup should be tested"
$DNSresolve = Resolve-DnsName $env:computername |ConvertTo-Html -Fragment -PreContent "<h2>NSlookup details</h2>"
$DNSresolveN = "<h3>Note :: If no information is populated here it means server has failed NSlookup command. Please check manually</h3>"


#The command below will get the server time zone infromation
$TZone = Get-timeZone |ConvertTo-Html -Fragment -PreContent "<h2>Server Time Zone</h2>"

#The command below will get the server firewall setting
$firewallH = "<h2>Firewall Settings</h2>"
$firewall = Netsh Advfirewall show allprofile state  |%{"$_<br/>"}


#The command below will get the server page file details
$pagefile = Get-CimInstance Win32_PageFileUsage | ConvertTo-Html -As Table -Property Name, AllocatedBaseSize, PeakUsage, CurrentUsage, TempPageFile -Fragment -PreContent "<h2>Page File</h2>" 

#The command below will get the server installed application and their version details
$InstalledApp = Get-WmiObject win32_product |Sort-Object name | ConvertTo-Html -As Table -Property name, version, InstallDate -Fragment -PreContent "<h2>Installed Application</h2>" 


#The command below will get the server installed patches details
$InstalledUpdates = Get-wmiobject win32_quickfixengineering | Sort-Object InstalledOn | ConvertTo-Html -As Table -Property HotFixID, InstalledBy, InstalledOn, Description -Fragment -PreContent "<h2>Installed Updates</h2>" 


#The command below will get the server top CPU consuming process info
$TopCPU = Get-WmiObject Win32_PerfFormattedData_PerfProc_Process | where-object{ $_.Name -ne "_Total" -and $_.Name -ne "Idle"} | Sort-Object PercentProcessorTime -Descending | select -First 5 | ConvertTo-Html -As Table -Property Name,IDProcess,PercentProcessorTime -Fragment -PreContent "<h2>Top CPU usage process</h2>" 


#The command below will get the server top Memory consuming process info
$TopMemory = Get-Process | Sort-Object -Descending WS | select -first 5 | ConvertTo-Html -As Table -Property ProcessName,ID,Handles,PM,WS -Fragment -PreContent "<h2>Top Memory usage process</h2>" 


#The command below will get the server IPV6 setting details
$IPV6 = Get-ItemProperty -Path Registry::HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters\ -Name DisabledComponents | ConvertTo-Html -As List -Fragment -PreContent "<h2>IPv6 settings</h2>" 
$IPV6Note = "<h3>Note :: DisabledComponents = 255, 4294967295 or FF means IPv6 is disabled</h3>"

#The command below will get the server wsus settings
$WSUS = Get-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\  | ConvertTo-Html -As List -Fragment -PreContent "<h2>WSUS settings from registry</h2>" 
$WSUSN = "<h3>Note :: If no information is populated here it means server dont have wsus settings configured. Please check Manually</h3>"

#The command below will get the server network adaptor DNS binding information
$NICdns = Get-DnsClient | ConvertTo-Html -As Table -Property InterfaceAlias,InterfaceIndex,ConnectionSpecificSuffix,RegisterThisConnectionsAddress -Fragment -PreContent "<h2>Network adaptor and DNS register settings</h2>" 

#The command below will get the server default log file size
$EventFileSize = Get-EventLog -list | ConvertTo-Html -As Table -Property MaximumKilobytes,MinimumRetentionDays,OverflowAction,Log -Fragment -PreContent "<h2>Event Log file size</h2>" 


#The command below will get the server System event log "ERROR" details
$SystemEvent = Get-eventlog -LogName System -EntryType Error -After (Get-Date).AddHours(-24) | ConvertTo-Html -As Table -Property  EventID, source, TimeGenerated, Message -Fragment -PreContent "<h2>System Error events</h2>" 


#The command below will get the server Application event log "ERROR" details
$ApplicationEvent = Get-eventlog -LogName Application -EntryType Error -After (Get-Date).AddHours(-24) | ConvertTo-Html -As Table -Property  EventID, source, TimeGenerated, Message -Fragment -PreContent "<h2>Application Error events</h2>" 


#The command below will combine all the information gathered into a single HTML report
$Report = ConvertTo-HTML -Body "$ComputerName $CDate $Cpuusage $TMemory $OSinfo $ProcessInfo $MemoryInfo $BiosInfo $TZone $DiscInfo $pagefile  $TopCPU $TopMemory    $Agentservice $AutoServicesInfo $ServicesInfo $NetworkDetails  $InstalledApp $InstalledUpdates $localusers $localAdminGroupMemebers $ShareFolders $WSUS $WSUSN $DNSresolve $DNSresolveN $IPV6 $IPV6Note $NICdns $IP $ipconfig $RprintHead $Rprint $OSA $KMS $firewallH $firewall $EventFileSize $SystemEvent $ApplicationEvent" -Head $header -Title "Computer Information Report" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

#The command below will generate the report to an HTML file
$Report | Out-File $PSScriptRoot\""$env:computername"_$((Get-Date).ToString("yyyyMMdd_HHmmss")).html"
#
