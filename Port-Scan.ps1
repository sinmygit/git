
function Port-Scan {
<#
.PARAMETER Ports
Ports That should be scanned, default values are: 21,22,23,53,69,71,80,98,110,139,111,
389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,
5801,5900,5555,5901

.PARAMETER TimeOut
Time (in MilliSeconds) before TimeOut, Default set to 100

.EXAMPLE
PS > Port-Scan -SIP 192.168.0.1 -EIP 192.168.0.254

.EXAMPLE
PS > Port-Scan -SIP 192.168.0.1 -EIP 192.168.0.254 

.EXAMPLE
PS > Port-Scan -SIP 192.168.0.1 -EIP 192.168.0.254  
Use above to do a port scan on default ports.

.EXAMPLE
PS > Port-Scan -SIP 192.168.0.1 -EIP 192.168.0.254   -TimeOut 500

.EXAMPLE
PS > Port-Scan -SIP 192.168.0.1 -EIP 192.168.10.254   -Port 80

.LINK
http://www.truesec.com
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/02/use-powershell-for-network-host-and-port-discovery-sweeps.aspx
https://github.com/samratashok/nishang
    
.NOTES
Goude 2012, TrueSec
#>
    [CmdletBinding()] Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
        [string]
        $SIP,

        [parameter(Mandatory = $true, Position = 1)]
        [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
        [string]
        $EIP,
        

        [int[]]
        $Ports = @(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901),
        
        [int]
        $TimeOut = 100
    )  
    Begin {
    $ping = New-Object System.Net.Networkinformation.Ping
    }
    Process {
    foreach($a in ($SIP.Split(".")[0]..$EIP.Split(".")[0])) {
        foreach($b in ($SIP.Split(".")[1]..$EIP.Split(".")[1])) {
        foreach($c in ($SIP.Split(".")[2]..$EIP.Split(".")[2])) {
            foreach($d in ($SIP.Split(".")[3]..$EIP.Split(".")[3])) {
            write-progress -activity PingSweep -status "$a.$b.$c.$d" -percentcomplete (($d/($EIP.Split(".")[3])) * 100)
            $pingStatus = $ping.Send("$a.$b.$c.$d",$TimeOut)
            if($pingStatus.Status -eq "Success") {
               
                
                $openPorts = @()
                for($i = 1; $i -le $ports.Count;$i++) {
                    $port = $Ports[($i-1)]
                    write-progress -activity PortScan -status "$a.$b.$c.$d" -percentcomplete (($i/($Ports.Count)) * 100) -Id 2
                    $client = New-Object System.Net.Sockets.TcpClient
                    $beginConnect = $client.BeginConnect($pingStatus.Address,$port,$null,$null)
                    if($client.Connected) {
                    $openPorts += $port
                    } else {
                    # Wait
                    Start-Sleep -Milli $TimeOut
                    if($client.Connected) {
                        $openPorts += $port
                    }
                    }
                    $client.Close()
                }
               
                # Return Object
                "$a.$b.$c.$d" + " : " $openPorts
            }
            
        }
        }
    }
    }
    End {
    }
}
