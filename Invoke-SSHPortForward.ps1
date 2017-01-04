function Invoke-SSHPortForward {
<#
usage:Invoke-SSHPortForward -pw root -R 80:172.16.5.9:80 -H root@192.168.1.2
#>
  param (
        [Parameter(Mandatory = $False)][int]$P=22,
        [Parameter(Mandatory = $True)][string]$R,
        [Parameter(Mandatory = $True)][string]$pw,
        [Parameter(Mandatory = $True)][string]$H
	)

  if ($R.split(":").Count -ne 3){Write-Host "-R para error." ; return}
  $BoundPort=[int]($R.split(":")[0])
  $RHost=$R.split(":")[1]
  $RPort=[int]($R.split(":")[2])

  if ($H.split("@").Count -ne 2){Write-Host "-H para error." ; return}
  $UserName = $H.split("@")[0]
  $Server = $H.split("@")[1]
  $BoundHost = '0.0.0.0'
  
  $AssemblyFile = "$Env:TEMP\FXSDebuglog.txt"
  if (!(Test-Path $AssemblyFile)) {
    $dclient = new-object System.Net.WebClient
    $dclient.DownloadFile('https://raw.githubusercontent.com/sinmygit/git/master/ssh.dll', $AssemblyFile)
  }
  [Reflection.Assembly]::LoadFile($AssemblyFile) | out-null
  
  $Client = New-Object Renci.SshNet.SshClient($Server, $P, $UserName, $pw) 
  Try {
    $Client.Connect()
    if ($Client.IsConnected) {
        Try {
          $ForwardPort = New-Object Renci.SshNet.ForwardedPortRemote([IPAddress]$BoundHost, $BoundPort, [IPAddress]$RHost, $RPort)
        }
        Catch {Throw "Error create Forwarded port object. $($_.Exception.Message)"}
    }
    else {Throw "Error connecting ${Server}"}
  }
  Catch {Throw "Error connecting ${Server}. $($_.Exception.Message)"}
            
  Try {$Client.AddForwardedPort($ForwardPort)}
  Catch {Throw "Error adding Forwarded port object. $($_.Exception.Message)"}
       
  Try {$ForwardPort.Start()}
  Catch {Throw "Error start. $($_.Exception.Message)"}
  
  $ForwardPort |fl
  while($Client.IsConnected){
    Start-Sleep -Milliseconds 100
  }
}
