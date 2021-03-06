<#
For remote port forwarding,same as connectclient.exe,use listenserver.exe to run in local computer.
Usage:
  ConnectClient -R 45.62.5.4:443:192.168.16.100:3389 [-v]
#>      
function Stream_Setup
{
    param($FuncSetupVars)
    $c,$l,$p,$t = $FuncSetupVars
    if($global:Verbose){$Verbose = $True}
    $FuncVars = @{}
    if(!$l)
    {
      $FuncVars["l"] = $False
      $Socket = New-Object System.Net.Sockets.TcpClient
      Write-Verbose "Connecting..."
      $Handle = $Socket.BeginConnect($c,$p,$null,$null)
    }
    else
    {
      $FuncVars["l"] = $True
      Write-Verbose ("Listening on [0.0.0.0] (port " + $p + ")")
      $Socket = New-Object System.Net.Sockets.TcpListener $p
      $Socket.Start()
      $Handle = $Socket.BeginAcceptTcpClient($null, $null)
    }
    
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while($True)
    {
      if($Host.UI.RawUI.KeyAvailable)
      {
        if(@(17,27) -contains ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").VirtualKeyCode))
        {
          Write-Verbose "CTRL or ESC caught. Stopping TCP Setup..."
          if($FuncVars["l"]){$Socket.Stop()}
          else{$Socket.Close()}
          $Stopwatch.Stop()
          break
        }
      }
      if($Stopwatch.Elapsed.TotalSeconds -gt $t)
      {
        if(!$l){$Socket.Close()}
        else{$Socket.Stop()}
        $Stopwatch.Stop()
        Write-Verbose "Timeout!" ; break
        break
      }
      if($Handle.IsCompleted)
      {
        if(!$l)
        {
          try
          {
            $Socket.EndConnect($Handle)
            $Stream = $Socket.GetStream()
            $BufferSize = $Socket.ReceiveBufferSize
            Write-Verbose ("Connection to " + $c + ":" + $p + " succeeded!")
          }
          catch
          {
            $Socket.Close(); $Stopwatch.Stop();
            Write-Verbose ("Connection to " + $c + ":" + $p + " failed!");
            break
          }
        }
        else
        {
          $Client = $Socket.EndAcceptTcpClient($Handle)
          $Stream = $Client.GetStream()
          $BufferSize = $Client.ReceiveBufferSize
          Write-Verbose ("Connection from [" + $Client.Client.RemoteEndPoint.Address.IPAddressToString + "] port " + $port + " [tcp] accepted (source port " + $Client.Client.RemoteEndPoint.Port + ")")
        }
        break
      }
    }
    $Stopwatch.Stop()
    if($Socket -eq $null){break}
    $FuncVars["Stream"] = $Stream
    $FuncVars["Socket"] = $Socket
    $FuncVars["BufferSize"] = $BufferSize
    $FuncVars["StreamDestinationBuffer"] = (New-Object System.Byte[] $FuncVars["BufferSize"])
    $FuncVars["StreamReadOperation"] = $FuncVars["Stream"].BeginRead($FuncVars["StreamDestinationBuffer"], 0, $FuncVars["BufferSize"], $null, $null)
    $FuncVars["Encoding"] = New-Object System.Text.AsciiEncoding
    $FuncVars["StreamBytesRead"] = 1
    return $FuncVars
  
}

function Stream_ReadData
{

    param($FuncVars)
    $Data = $null
    if($FuncVars["StreamBytesRead"] -eq 0){break}
    if($FuncVars["StreamReadOperation"].IsCompleted)
    {
      $StreamBytesRead = $FuncVars["Stream"].EndRead($FuncVars["StreamReadOperation"])
      if($StreamBytesRead -eq 0){break}
      $Data = $FuncVars["StreamDestinationBuffer"][0..([int]$StreamBytesRead-1)]
      $FuncVars["StreamReadOperation"] = $FuncVars["Stream"].BeginRead($FuncVars["StreamDestinationBuffer"], 0, $FuncVars["BufferSize"], $null, $null)
    }
    return $Data,$FuncVars
  
}

function Stream_WriteData
{

    param($Data,$FuncVars)
    $FuncVars["Stream"].Write($Data, 0, $Data.Length)
    return $FuncVars
  
}

function Stream_Close
{

    param($FuncVars)
    try{$FuncVars["Stream"].Close()}
    catch{}
    if($FuncVars["l"]){$FuncVars["Socket"].Stop()}
    else{$FuncVars["Socket"].Close()}
  
}



function Main
{

    param($Stream1SetupVars,$Stream2SetupVars,$modeVars)
    while($True)
    {
    try
    {      
      Write-Verbose "Setting up Stream 1..."
      try{$Stream1Vars = Stream_Setup $Stream1SetupVars}
      catch{Write-Verbose "Stream 1 Setup Failure" ; break}
      
      $Data = $null

      while($Data -eq $null)
      {
        try 
        {
          $Data,$Stream1Vars = Stream_ReadData $Stream1Vars
        }
        catch
        {
          Write-Verbose "Failed to readdata" ; break
        }
      }
      $Data = $null

      Write-Verbose "Setting up Stream 2..."
      try{$Stream2Vars = Stream_Setup $Stream2SetupVars}
      catch{Write-Verbose "Stream 2 Setup Failure" ; break}
      
  
      
      if($d){Write-Verbose "-d (disconnect) Activated. Disconnecting..." ; break}
      
      Write-Verbose "Both Communication Streams Established. Redirecting Data Between Streams..."
      while($True)
      {
        try
        {
          $Data,$Stream2Vars = Stream_ReadData $Stream2Vars
          if($Data -ne $null){$Stream1Vars = Stream_WriteData $Data $Stream1Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 2 to Stream 1" ; break
        }
        
        try
        {
          $Data,$Stream1Vars = Stream_ReadData $Stream1Vars
          if($Data -ne $null){$Stream2Vars = Stream_WriteData $Data $Stream2Vars}
          $Data = $null
        }
        catch
        {
          Write-Verbose "Failed to redirect data from Stream 1 to Stream 2" ; break
        }
      }
    }
    finally
    {
      try
      {
        #Write-Verbose "Closing Stream 2..."
        Stream_Close $Stream2Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 2"
      }
      try
      {
        #Write-Verbose "Closing Stream 1..."
        Stream_Close $Stream1Vars
      }
      catch
      {
        Write-Verbose "Failed to close Stream 1"
      }
    }
  }
}
#$VerbosePreference = "Continue"


function ConnectClient
{
  Param(
    [String]$R,
    [Switch]$v
  )

  if ($R.split(":").Count -ne 4){Write-Host "-R para error." ; return}
  
  $iplocal=$R.split(":")[0]
  $portlocal=[int]($R.split(":")[1])
  $ipremote=$R.split(":")[2]
  $portremote=[int]($R.split(":")[3])
  
  if($v) {$VerbosePreference = "Continue"}

  Main @($iplocal,$False,$portlocal,60) @($ipremote,$False,$portremote,'60')
}