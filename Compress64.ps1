function Compress64{

[CmdletBinding()]
Param(
    [Parameter(Position = 0)]
    [String]
    $ExeArgs
)
$File = $ExeArgs

$Path = Resolve-Path $File

if (! [IO.File]::Exists($Path))
{
    Throw "$Path does not exist."
}

$FileBytes = [System.IO.File]::ReadAllBytes($Path)

if (($FileBytes[0..1] | % {[Char]$_}) -join '' -cne 'MZ')
{
    Throw "$Path is not a valid executable."
}

$Length = $FileBytes.Length
$CompressedStream = New-Object IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$DeflateStream.Write($FileBytes, 0, $FileBytes.Length)
$DeflateStream.Dispose()
$CompressedFileBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()
$EncodedCompressedFile = [Convert]::ToBase64String($CompressedFileBytes)

Write-Verbose "Compression ratio: $(($EncodedCompressedFile.Length/$FileBytes.Length).ToString('#%'))"

$Output = @"
`$EncodedCompressedFile = @'
$EncodedCompressedFile
'@
`$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`$EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
`$UncompressedFileBytes = New-Object Byte[]($Length)
`$DeflatedStream.Read(`$UncompressedFileBytes, 0, $Length) | Out-Null
`[System.IO.File]::WriteAllBytes('out.exe', `$UncompressedFileBytes)
"@

$Output | set-content ($File + ".ps1")
}