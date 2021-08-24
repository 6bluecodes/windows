$Servers = Get-Content -Path "C:\temp\computers.txt"
$Array = @()
 
Foreach($Server in $Servers)
{
If(Get-WmiObject win32_operatingSystem -computer $Server -ea 0 )
{
    $DNSCheck = $null
    $Server = $Server.trim()
 
    $DNSCheck = ([System.Net.Dns]::GetHostByName(("$server")))
 
    $Object = New-Object PSObject -Property ([ordered]@{ 
      
                "Server name"             = $Server
                "FQDN"                    = $DNSCheck.hostname
                "IP Address0"             = $DNSCheck.AddressList[0]
                "IP Address1"             = $DNSCheck.AddressList[1]
                "IP Address2"             = $DNSCheck.AddressList[2]
 
    })
 }  else

 {

     $Object = New-Object PSObject -Property ([ordered]@{ 
      
                "Server name"             = $Server
                "FQDN"                    = "Unreachable"

 })
 }
    # Add object to our array
    $Array += $Object
 
}
$Array
$Array | Export-Csv -Path C:\temp\results.csv -NoTypeInformation
