using module .\Assets\CustomCheckedListBoxModule
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


# ----------------------------------------------------------- DEBLOAT FUNCTIONS ---------------------------------------------------

function Custom-MsgBox {
    param(
        [string]$message,
        [ValidateSet('Question', 'Warning', 'None')]
        [string]$type
    )
    Add-Type -AssemblyName System.Windows.Forms

    # Enable visual styles
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'ZOICWARE'
    if ($type -eq 'None') {
        $form.Size = New-Object System.Drawing.Size(280, 180)
    }
    else {
        $form.Size = New-Object System.Drawing.Size(370, 200)
    }
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [System.Drawing.Color]::Black
    $form.ForeColor = [System.Drawing.Color]::White
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    # Add Icon
    $pictureBox = New-Object System.Windows.Forms.PictureBox
    $pictureBox.Location = New-Object System.Drawing.Point(20, 30) 
    $pictureBox.Size = New-Object System.Drawing.Size(50, 50) 
    $pictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
    if ($type -eq 'Warning') {
        $imagePath = 'C:\Windows\System32\SecurityAndMaintenance_Alert.png'
    }
    if ($type -eq 'Question') {
        $imagePath = Search-File '*questionIcon.png'
    }
    if ($type -eq 'None') {
        $imagePath = "$PSScriptRoot\Assets\greencheckIcon.png"
    }
    
    try {
        $image = [System.Drawing.Image]::FromFile($imagePath)
    }
    catch {
        Write-Host 'Unable to Load Icon' -ForegroundColor Red
    }
    $pictureBox.Image = $image
    $form.Controls.Add($pictureBox)

    # Create the label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $message
    if ($type -eq 'None') {
        $label.Size = New-Object System.Drawing.Size(200, 60)
    }
    else {
        $label.Size = New-Object System.Drawing.Size(250, 80)
    }
    $label.Location = New-Object System.Drawing.Point(90, 40)
    $label.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($label)

    # Create the OK button
    $okButton = New-Object System.Windows.Forms.Button
    if ($type -eq 'Question') {
        $okButton.Text = 'Yes'
    }
    else {
        $okButton.Text = 'OK'
    }
    if ($type -eq 'None') {
        $okButton.Location = New-Object System.Drawing.Point(105, 110)
    }
    else {
        $okButton.Location = New-Object System.Drawing.Point(100, 120)
    }
    $okButton.BackColor = [System.Drawing.Color]::FromArgb(53, 53, 52)
    $okButton.ForeColor = [System.Drawing.Color]::White
    $oKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($okButton)

    if (!($type -eq 'None')) {
        # Create the Cancel button
        $cancelButton = New-Object System.Windows.Forms.Button
        if ($type -eq 'Question') {
            $cancelButton.Text = 'No'
        }
        else {
            $cancelButton.Text = 'Cancel'
        }
        $cancelButton.Location = New-Object System.Drawing.Point(180, 120)
        $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(53, 53, 52)
        $cancelButton.ForeColor = [System.Drawing.Color]::White
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Controls.Add($cancelButton)

    }
   
    # Show the form
    $result = $form.ShowDialog()

    return $result
}


function Add-CustomFont {

    $privateFontCollection = New-Object System.Drawing.Text.PrivateFontCollection
    #add dm mono font
    $fontFile = "$PSScriptRoot\Assets\DMMono-Regular.ttf"
    $privateFontCollection.AddFontFile($fontFile)
    $Global:dmMonoFont = $privateFontCollection.Families[0]
    return $Global:dmMonoFont
  
  
}


function Get-InstalledSoftware {
  
    [CmdletBinding()]
    param(
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object { try { Get-ItemPropertyValue -Path $_.pspath -Name DisplayName -ErrorAction Stop } catch { $null } } | Where-Object { $_ -like "*$WordToComplete*" } | ForEach-Object { "'$_'" }
            })]
        [string[]] $appName,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $computerName,

        [switch] $dontIgnoreUpdates,

        [ValidateNotNullOrEmpty()]
        [ValidateSet('AuthorizedCDFPrefix', 'Comments', 'Contact', 'DisplayName', 'DisplayVersion', 'EstimatedSize', 'HelpLink', 'HelpTelephone', 'InstallDate', 'InstallLocation', 'InstallSource', 'Language', 'ModifyPath', 'NoModify', 'NoRepair', 'Publisher', 'QuietUninstallString', 'UninstallString', 'URLInfoAbout', 'URLUpdateInfo', 'Version', 'VersionMajor', 'VersionMinor', 'WindowsInstaller')]
        [string[]] $property = ('DisplayName', 'DisplayVersion', 'UninstallString'),

        [switch] $ogv
    )

    PROCESS {
        $scriptBlock = {
            param ($Property, $DontIgnoreUpdates, $appName)

            # where to search for applications
            $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

            # define what properties should be outputted
            $SelectProperty = @('DisplayName') # DisplayName will be always outputted
            if ($Property) {
                $SelectProperty += $Property
            }
            $SelectProperty = $SelectProperty | Select-Object -Unique

            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)
            if (!$RegBase) {
                Write-Error "Unable to open registry on $env:COMPUTERNAME"
                return
            }

            foreach ($RegKey in $RegistryLocation) {
                Write-Verbose "Checking '$RegKey'"
                foreach ($appKeyName in $RegBase.OpenSubKey($RegKey).GetSubKeyNames()) {
                    Write-Verbose "`t'$appKeyName'"
                    $ObjectProperty = [ordered]@{}
                    foreach ($CurrentProperty in $SelectProperty) {
                        Write-Verbose "`t`tGetting value of '$CurrentProperty' in '$RegKey$appKeyName'"
                        $ObjectProperty.$CurrentProperty = ($RegBase.OpenSubKey("$RegKey$appKeyName")).GetValue($CurrentProperty)
                    }

                    if (!$ObjectProperty.DisplayName) {
                        # Skipping. There are some weird records in registry key that are not related to any app"
                        continue
                    }

                    $ObjectProperty.ComputerName = $env:COMPUTERNAME

                    # create final object
                    $appObj = New-Object -TypeName PSCustomObject -Property $ObjectProperty

                    if ($appName) {
                        $appNameRegex = $appName | ForEach-Object {
                            [regex]::Escape($_)
                        }
                        $appNameRegex = $appNameRegex -join '|'
                        $appObj = $appObj | Where-Object { $_.DisplayName -match $appNameRegex }
                    }

                    if (!$DontIgnoreUpdates) {
                        $appObj = $appObj | Where-Object { $_.DisplayName -notlike '*Update for Microsoft*' -and $_.DisplayName -notlike 'Security Update*' }
                    }

                    $appObj
                }
            }
        }

        $param = @{
            scriptBlock  = $scriptBlock
            ArgumentList = $property, $dontIgnoreUpdates, $appName
        }
        if ($computerName) {
            $param.computerName = $computerName
            $param.HideComputerName = $true
        }

        $result = Invoke-Command @param

        if ($computerName) {
            $result = $result | Select-Object * -ExcludeProperty RunspaceId
        }
    }

    END {
        if ($ogv) {
            $comp = $env:COMPUTERNAME
            if ($computerName) { $comp = $computerName }
            $result | Out-GridView -PassThru -Title "Installed software on $comp"
        }
        else {
            $result
        }
    }
}

function Uninstall-ApplicationViaUninstallString {
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('displayName')]
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object { try { Get-ItemPropertyValue -Path $_.pspath -Name DisplayName -ErrorAction Stop } catch { $null } } | Where-Object { $_ -like "*$WordToComplete*" } | ForEach-Object { "'$_'" }
            })]
        [string[]] $name,

        [string] $addArgument
    )

    begin {
        # without admin rights msiexec uninstall fails without any error
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            throw 'Run with administrator rights'
        }

        if (!(Get-Command Get-InstalledSoftware)) {
            throw 'Function Get-InstalledSoftware is missing'
        }
    }

    process {
        $appList = Get-InstalledSoftware -property DisplayName, UninstallString, QuietUninstallString | Where-Object DisplayName -In $name

        if ($appList) {
            foreach ($app in $appList) {
                if ($app.QuietUninstallString) {
                    $uninstallCommand = $app.QuietUninstallString
                }
                else {
                    $uninstallCommand = $app.UninstallString
                }
                $name = $app.DisplayName

                if (!$uninstallCommand) {
                    Write-Warning "Uninstall command is not defined for app '$name'"
                    continue
                }

                if ($uninstallCommand -like 'msiexec.exe*') {
                    # it is MSI
                    $uninstallMSIArgument = $uninstallCommand -replace 'MsiExec.exe'
                    # sometimes there is /I (install) instead of /X (uninstall) parameter
                    $uninstallMSIArgument = $uninstallMSIArgument -replace '/I', '/X'
                    # add silent and norestart switches
                    $uninstallMSIArgument = "$uninstallMSIArgument /QN"
                    if ($addArgument) {
                        $uninstallMSIArgument = $uninstallMSIArgument + ' ' + $addArgument
                    }
                    Write-Warning "Uninstalling app '$name' via: msiexec.exe $uninstallMSIArgument"
                    Start-Process 'msiexec.exe' -ArgumentList $uninstallMSIArgument -Wait
                }
                else {
                    # it is EXE
                    #region extract path to the EXE uninstaller
                    # path to EXE is typically surrounded by double quotes
                    $match = ([regex]'("[^"]+")(.*)').Matches($uninstallCommand)
                    if (!$match.count) {
                        # string doesn't contain ", try search for ' instead
                        $match = ([regex]"('[^']+')(.*)").Matches($uninstallCommand)
                    }
                    if ($match.count) {
                        $uninstallExe = $match.captures.groups[1].value
                    }
                    else {
                        # string doesn't contain even '
                        # before blindly use the whole string as path to an EXE, check whether it doesn't contain common argument prefixes '/', '-' ('-' can be part of the EXE path, but it is more safe to make false positive then fail later because of faulty command)
                        if ($uninstallCommand -notmatch '/|-') {
                            $uninstallExe = $uninstallCommand
                        }
                    }
                    if (!$uninstallExe) {
                        Write-Error "Unable to extract EXE path from '$uninstallCommand'"
                        continue
                    }
                    #endregion extract path to the EXE uninstaller
                    if ($match.count) {
                        $uninstallExeArgument = $match.captures.groups[2].value
                    }
                    else {
                        Write-Verbose "I've used whole uninstall string as EXE path"
                    }
                    if ($addArgument) {
                        $uninstallExeArgument = $uninstallExeArgument + ' ' + $addArgument
                    }
                    # Start-Process param block
                    $param = @{
                        FilePath = $uninstallExe
                        Wait     = $true
                    }
                    if ($uninstallExeArgument) {
                        $param.ArgumentList = $uninstallExeArgument
                    }
                    Write-Warning "Uninstalling app '$name' via: $uninstallExe $uninstallExeArgument"
                    Start-Process @param
                }
            }
        }
        else {
            Write-Warning "No software with name $($name -join ', ') was found. Get the correct name by running 'Get-InstalledSoftware' function."
        }
    }
}


function debloat-TeamsOneDrive {
    Write-Host 'Uninstalling Teams and OneDrive...'
    #   Description:
    # This script will remove and disable OneDrive integration.
    Write-Output 'Kill OneDrive process'
    taskkill.exe /F /IM 'OneDrive.exe' >$null 2>&1
    taskkill.exe /F /IM 'explorer.exe' >$null 2>&1

    Write-Output 'Remove OneDrive'
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
    }
    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
    }

    Write-Output 'Removing OneDrive leftovers'
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
    # check if directory is empty before removing:
    If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
    }


    Write-Output 'Remove Onedrive from explorer sidebar'
    New-PSDrive -PSProvider 'Registry' -Root 'HKEY_CLASSES_ROOT' -Name 'HKCR'
    mkdir -Force 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
    Set-ItemProperty -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' 0
    mkdir -Force 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
    Set-ItemProperty -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' 0
    Remove-PSDrive 'HKCR'

    # Thank you Matthew Israelsson
    Write-Output 'Removing run hook for new users'
    reg load 'hku\Default' 'C:\Users\Default\NTUSER.DAT'
    reg delete 'HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v 'OneDriveSetup' /f
    reg unload 'hku\Default'

    Write-Output 'Removing startmenu entry'
    Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe"

    Write-Output 'Restarting explorer'
    Start-Process 'explorer.exe'

    Write-Output 'Waiting 10 seconds for explorer to complete loading'
    Start-Sleep 10


    ## Teams Removal - Source: https://github.com/asheroto/UninstallTeams
    function getUninstallString($match) {
        return (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$match*" }).UninstallString
    }
            
    $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
    $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
            
    Write-Output 'Stopping Teams process...'
    Stop-Process -Name '*teams*' -Force -ErrorAction SilentlyContinue
        
    Write-Output 'Uninstalling Teams from AppData\Microsoft\Teams'
    if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
        # Uninstall app
        $proc = Start-Process $TeamsUpdateExePath '-uninstall -s' -PassThru
        $proc.WaitForExit()
    }
        
    Write-Output 'Removing Teams AppxPackage...'
    Get-AppxPackage '*Teams*' | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxPackage '*Teams*' -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        
    Write-Output 'Deleting Teams directory'
    if ([System.IO.Directory]::Exists($TeamsPath)) {
        Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
    }
        
    Write-Output 'Deleting Teams uninstall registry key'
    # Uninstall from Uninstall registry key UninstallString
    $us = getUninstallString('Teams');
    if ($us.Length -gt 0) {
        $us = ($us.Replace('/I', '/uninstall ') + ' /quiet').Replace('  ', ' ')
        $FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
        $ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('  ', ' '))
        $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
        $proc.WaitForExit()
    }
}



function debloat-LockedPackages {
    
    $lockedPackages = @(
        'Microsoft.Windows.NarratorQuickStart' 
        'Microsoft.Windows.ParentalControls'
        'Microsoft.Windows.PeopleExperienceHost'
        'Microsoft.ECApp'
        'Microsoft.LockApp'
        'NcsiUwpApp'
        'Microsoft.XboxGameCallableUI'
        'Microsoft.Windows.XGpuEjectDialog'
        'Microsoft.Windows.SecureAssessmentBrowser'
        'Microsoft.Windows.PinningConfirmationDialog'
        'Microsoft.AsyncTextService'
        'Microsoft.AccountsControl'
        'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE'
        'E2A4F912-2574-4A75-9BB0-0D023378592B'
        'Microsoft.Windows.PrintQueueActionCenter'
        'Microsoft.Windows.CapturePicker'
        'Microsoft.CredDialogHost'
        'Microsoft.Windows.AssignedAccessLockApp'
        'Microsoft.Windows.Apprep.ChxApp'
        'Windows.PrintDialog'
        'Microsoft.Windows.ContentDeliveryManager'
        'Microsoft.BioEnrollment'
        'Microsoft.Windows.CloudExperienceHost'
        'MicrosoftWindows.UndockedDevKit'
        'Microsoft.Windows.OOBENetworkCaptivePortal'
        'Microsoft.Windows.OOBENetworkConnectionFlow'
        'Microsoft.AAD.BrokerPlugin'
        'MicrosoftWindows.Client.CoPilot'
        'Clipchamp.Clipchamp'
        'Microsoft.BingSearch'
        'Microsoft.Services.Store.Engagement'
        'Microsoft.WidgetsPlatformRuntime'
    )
    
    Write-Host 'Removing Locked Appx Packages...'

    $provisioned = get-appxprovisionedpackage -online 
    $appxpackage = get-appxpackage -allusers
    $eol = @()
    $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    $users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }


    #uninstall packages
    foreach ($choice in $lockedPackages) {
        if ('' -eq $choice.Trim()) { continue }
        foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {
            $next = !1; foreach ($no in $skip) { if ($appx.PackageName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
            $PackageName = $appx.PackageName; $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
            New-Item "$store\Deprovisioned\$PackageFamilyName" -force >''; 
            foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageName" -force >'' } ; $eol += $PackageName
            dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
            remove-appxprovisionedpackage -packagename $PackageName -online -allusers >''
        }
        foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {
            $next = !1; foreach ($no in $skip) { if ($appx.PackageFullName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
            $PackageFullName = $appx.PackageFullName;
            New-Item "$store\Deprovisioned\$appx.PackageFamilyName" -force >''; 
            foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force >'' } ; $eol += $PackageFullName
            dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
            remove-appxpackage -package $PackageFullName -allusers >''
        }
    }

    ## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
    foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >'' } }

}


function debloat-HealthUpdateTools {
    #uninstall health update tools and installed updates
    $apps = Get-InstalledSoftware  
    foreach ($app in $apps) {
        if ($app.DisplayName -like '*Update for Windows*' -or $app.DisplayName -like '*Microsoft Update Health Tools*') {
            Uninstall-ApplicationViaUninstallString $app.DisplayName
        }
    }
}

function debloat-remotedesktop {
    #uninstall remote desktop connection
    
    try {
        #get uninstall string 
        $uninstallstr = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\mstsc*' -Name 'UninstallString').UninstallString
        $path, $arg = $uninstallstr -split ' '
        Start-Process -FilePath $path -ArgumentList $arg
        Start-Sleep 1
        $running = $true
        do {
            $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
            foreach ($window in $openWindows) {
                if ($window.MainWindowTitle -eq 'Remote Desktop Connection') {
                    Stop-Process -Name 'mstsc' -Force
                    $running = $false
                }
            }
        }while ($running)
    }
    catch {
        #remote desktop not found
        Write-Host 'Remote Desktop Not Found'
    }
    
    
    
}


function debloat-dism {
    $packagesToRemove = @('Microsoft-Windows-QuickAssist-Package', 'Microsoft-Windows-Hello-Face-Package', 'Microsoft-Windows-StepsRecorder-Package')
    $packages = (Get-WindowsPackage -Online).PackageName
    foreach ($package in $packages) {
        foreach ($packageR in $packagesToRemove) {
            #ignore 32 bit packages [wow64]
            if ($package -like "$packageR*" -and $package -notlike '*wow64*') {
                #erroraction silently continue doesnt work since error comes from dism
                #using catch block to ignore error
                try {
                    Remove-WindowsPackage -Online -PackageName $package -NoRestart -ErrorAction Stop | Out-Null
                }
                catch {
                    #error from outdated package version
                    #do nothing
                }
           
            }
        }
    
    }
}

function debloatPreset {
    param (
        [string]$choice
    )

    function debloatAppx {

        param (
            [string]$Bloat
        )
        #silentlycontinue doesnt work sometimes so trycatch block is needed to supress errors
        try {
            Get-AppXPackage $Bloat -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
        }
        catch {}
        try {
            Remove-AppxPackage -Package $Bloat -AllUsers -ErrorAction Stop
        }
        catch {}
        try {
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Stop | Out-Null
        }
        catch {}    
    }




    $packages = (Get-AppxPackage -AllUsers).name
    #remove dups
    $Bloatware = $packages | Sort-Object | Get-Unique
    $ProgressPreference = 'SilentlyContinue'

    switch ($choice) {
        'debloatAll' {
            foreach ($Bloat in $Bloatware) {
                #using where-obj for wildcards to work
                $isProhibited = $prohibitedPackages | Where-Object { $Bloat -like $_ }
                #skip locked packages to save time
                if ($Bloat -notin $lockedAppxPackages -and !$isProhibited) {
                    #dont remove nvcp, photos, notepad(11) and paint on 11 (win10 paint is "MSPaint")
                    #using -like because microsoft like to randomly change package names
                    if (!($Bloat -like '*NVIDIA*' -or $Bloat -like '*Photos*' -or $Bloat -eq 'Microsoft.Paint' -or $Bloat -like '*Notepad*')) { 
                        Write-Host "Trying to remove $Bloat"
                        debloatAppx -Bloat $Bloat
                    }          
                }

            }
        }
        'debloatKeepStore' {
            foreach ($Bloat in $Bloatware) {
                #using where-obj for wildcards to work
                $isProhibited = $prohibitedPackages | Where-Object { $Bloat -like $_ }
                #skip locked packages to save time
                if ($Bloat -notin $lockedAppxPackages -and !$isProhibited) {
                    #dont remove nvcp, photos or paint on 11 (win10 paint is "MSPaint")
                    #dont remove store
                    if (!($Bloat -like '*NVIDIA*' -or $Bloat -like '*Photos*' -or $Bloat -eq 'Microsoft.Paint' -or $Bloat -like '*Store*' -or $Bloat -like '*Notepad*')) { 
                        Write-Host "Trying to remove $Bloat"
                        debloatAppx -Bloat $Bloat
                    }          
                }

            }
        }
        'debloatKeepStoreXbox' {
            foreach ($Bloat in $Bloatware) {
                #using where-obj for wildcards to work
                $isProhibited = $prohibitedPackages | Where-Object { $Bloat -like $_ }
                #skip locked packages to save time
                if ($Bloat -notin $lockedAppxPackages -and !$isProhibited) {
                    #dont remove nvcp, photos or paint on 11 (win10 paint is "MSPaint")
                    #dont remove store and xbox
                    if (!($Bloat -like '*NVIDIA*' -or $Bloat -like '*Photos*' -or $Bloat -eq 'Microsoft.Paint' -or $Bloat -like '*Store*' -or $Bloat -like '*Xbox*' -or $Bloat -like '*Gaming*' -or $Bloat -like '*Notepad*')) { 
                        Write-Host "Trying to remove $Bloat"
                        debloatAppx -Bloat $Bloat
                    }          
                }

            }
        }
    }


}



    


# ----------------------------------------------------------- DEBLOAT FUNCTIONS ---------------------------------------------------



$checkbox2 = New-Object System.Windows.Forms.RadioButton
$checkbox3 = New-Object System.Windows.Forms.RadioButton
$checkbox4 = New-Object System.Windows.Forms.RadioButton
$checkbox5 = New-Object System.Windows.Forms.RadioButton
$checkbox6 = New-Object System.Windows.Forms.RadioButton
 
    
  
#creating powershell list box 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

Add-CustomFont | Out-Null        

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Debloat'
$form.Size = New-Object System.Drawing.Size(670, 580)
$form.StartPosition = 'CenterScreen'
$form.BackColor = 'Black'
$form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

$url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#debloat'
$infobutton = New-Object Windows.Forms.Button
$infobutton.Location = New-Object Drawing.Point(620, 0)
$infobutton.Size = New-Object Drawing.Size(30, 27)
$infobutton.Add_Click({
        try {
            Start-Process $url -ErrorAction Stop
        }
        catch {
            Write-Host 'No Internet Connected...' -ForegroundColor Red
        }
            
    })
$infobutton.BackColor = 'Black'
$image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
$resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
$infobutton.Image = $resizedImage
$infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$infobutton.FlatAppearance.BorderSize = 1
#$infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$form.Controls.Add($infobutton)

  
$groupBox = New-Object System.Windows.Forms.GroupBox
$groupBox.Text = 'Debloat Presets'
$groupBox.Size = New-Object System.Drawing.Size(240, 215)
$groupBox.Location = New-Object System.Drawing.Point(10, 10)
$groupBox.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
$groupBox.ForeColor = 'White'
$form.Controls.Add($groupBox)

$groupBox2 = New-Object System.Windows.Forms.GroupBox
$groupBox2.Text = 'Custom Debloat Extras'
$groupBox2.Size = New-Object System.Drawing.Size(240, 235)
$groupBox2.Location = New-Object System.Drawing.Point(10, 280)
$groupBox2.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
$groupBox2.ForeColor = 'White'
$form.Controls.Add($groupBox2)

$applyPreset = New-Object System.Windows.Forms.Button
$applyPreset.Location = New-Object System.Drawing.Point(18, 190)
$applyPreset.Size = New-Object System.Drawing.Size(200, 25)
$applyPreset.Text = 'Apply Preset'
$applyPreset.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$applyPreset.ForeColor = [System.Drawing.Color]::White
#$applyPreset.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$applyPreset.FlatAppearance.BorderSize = 0
#$applyPreset.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$applyPreset.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$applyPreset.DialogResult = [System.Windows.Forms.DialogResult]::OK
$groupBox.Controls.Add($applyPreset)
#$form.Controls.Add($applyPreset)

$removeAppxPackages = {
    if ($customCheckedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Packages Selected' }
    else {
        foreach ($package in $customCheckedListBox.CheckedItems.GetEnumerator()) {
            Write-Host "Trying to remove $package"
            #silentlycontinue doesnt work sometimes so trycatch block is needed to supress errors
            try {
                Get-AppXPackage $package -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
            }
            catch {}
            try {
                Remove-AppxPackage -Package $package -AllUsers -ErrorAction Stop
            }
            catch {}
            try {
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$package*" | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Stop | Out-Null
            }
            catch {}    
        }
        #refresh list box
        Get-Packages -showLockedPackages $false
    }
}


$removeAppx = New-Object System.Windows.Forms.Button
$removeAppx.Location = New-Object System.Drawing.Point(510, 465)
$removeAppx.Size = New-Object System.Drawing.Size(120, 35)
$removeAppx.Text = 'Remove Appx Packages'
$removeAppx.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 
$removeAppx.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$removeAppx.ForeColor = [System.Drawing.Color]::White
#$removeAppx.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$removeAppx.FlatAppearance.BorderSize = 0
#$removeAppx.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$removeAppx.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$removeAppx.Add_Click({
        &$removeAppxPackages
    })
$form.Controls.Add($removeAppx)

    
$removeLockedPackages = {
    if ($customCheckedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Locked Packages Selected' }
    else {
        $selectedLockedPackages = @()
        foreach ($package in $customCheckedListBox.CheckedItems.GetEnumerator()) {
            $selectedLockedPackages += $package
        }

        $provisioned = get-appxprovisionedpackage -online 
        $appxpackage = get-appxpackage -allusers
        $eol = @()
        $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
        $users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

        #uninstall packages
        foreach ($choice in $selectedLockedPackages) {
            Write-Host "Trying to remove $choice"
            if ('' -eq $choice.Trim()) { continue }
            foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {
                $next = !1; foreach ($no in $skip) { if ($appx.PackageName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
                $PackageName = $appx.PackageName; $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
                New-Item "$store\Deprovisioned\$PackageFamilyName" -force >''; 
                foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageName" -force >'' } ; $eol += $PackageName
                dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
                remove-appxprovisionedpackage -packagename $PackageName -online -allusers >''
            }
            foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {
                $next = !1; foreach ($no in $skip) { if ($appx.PackageFullName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
                $PackageFullName = $appx.PackageFullName;
                New-Item "$store\Deprovisioned\$appx.PackageFamilyName" -force >''; 
                foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force >'' } ; $eol += $PackageFullName
                dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
                remove-appxpackage -package $PackageFullName -allusers >''
            }
        }

        ## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
        foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >'' } }
    }
    #update list
    Get-Packages -showLockedPackages $true
}
    
$removeLocked = New-Object System.Windows.Forms.Button
$removeLocked.Location = New-Object System.Drawing.Point(270, 465)
$removeLocked.Size = New-Object System.Drawing.Size(120, 35)
$removeLocked.Text = 'Remove Locked Packages'
$removeLocked.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 
$removeLocked.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$removeLocked.ForeColor = [System.Drawing.Color]::White
#$removeLocked.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$removeLocked.FlatAppearance.BorderSize = 0
#$removeLocked.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$removeLocked.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$removeLocked.Add_Click({
        &$removeLockedPackages
    })
$form.Controls.Add($removeLocked)

$applyExtras = New-Object System.Windows.Forms.Button
$applyExtras.Location = New-Object System.Drawing.Point(18, 210)
$applyExtras.Size = New-Object System.Drawing.Size(200, 25)
$applyExtras.Text = 'Apply Extras'
$applyExtras.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$applyExtras.ForeColor = [System.Drawing.Color]::White
#$applyExtras.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$applyExtras.FlatAppearance.BorderSize = 0
#$applyExtras.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$applyExtras.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$applyExtras.DialogResult = [System.Windows.Forms.DialogResult]::OK
$groupBox2.Controls.Add($applyExtras)
#$form.Controls.Add($applyExtras)

$checkAllBoxes = {
    if (!$checkAll.Checked) {
        #uncheck boxes
        for (($i = 0); $i -lt $customCheckedListBox.Items.Count; $i++) {
            $customCheckedListBox.SetItemChecked($i, $false)
        }
    }
    else {
        #check all buttons
        for (($i = 0); $i -lt $customCheckedListBox.Items.Count; $i++) {
            $customCheckedListBox.SetItemChecked($i, $true)
        }

    }

}

$checkAll = New-Object System.Windows.Forms.CheckBox
$checkAll.Location = New-Object System.Drawing.Point(555, 28)
$checkAll.Size = New-Object System.Drawing.Size(90, 21)
$checkAll.Text = 'Check All'
$checkALL.ForeColor = 'White'
$checkAll.Add_Click({
        &$checkAllBoxes
    })
$form.Controls.Add($checkAll)
  
  

$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(269, 10)
$label2.Size = New-Object System.Drawing.Size(280, 20)
$label2.Text = 'Installed Appx Packages:'
$label2.ForeColor = 'White'
$label2.Font = New-Object System.Drawing.Font($dmMonoFont, 10) 
$form.Controls.Add($label2)

$label3 = New-Object System.Windows.Forms.Label
$label3.Location = New-Object System.Drawing.Point(10, 230)
$label3.Size = New-Object System.Drawing.Size(200, 20)
$label3.Text = 'Custom Debloat:'
$label3.ForeColor = 'White'
$label3.Font = New-Object System.Drawing.Font($dmMonoFont, 10) 
$form.Controls.Add($label3)


       
$checkbox2.Location = new-object System.Drawing.Size(15, 30)
$checkbox2.Size = new-object System.Drawing.Size(150, 20)
$checkbox2.Text = 'Debloat All'
$checkbox2.ForeColor = 'White'
$checkbox2.Checked = $false
$groupBox.Controls.Add($checkbox2)
#$Form.Controls.Add($checkbox2)  
      
  
      
$checkbox3.Location = new-object System.Drawing.Size(15, 60)
$checkbox3.Size = new-object System.Drawing.Size(190, 20)
$checkbox3.Text = 'Keep Store,Xbox and Edge'
$checkbox3.ForeColor = 'White'
$checkbox3.Checked = $false
$groupBox.Controls.Add($checkbox3)
#$Form.Controls.Add($checkbox3)
      
  
      
$checkbox4.Location = new-object System.Drawing.Size(15, 90)
$checkbox4.Size = new-object System.Drawing.Size(170, 20)
$checkbox4.Text = 'Keep Store and Xbox'
$checkbox4.ForeColor = 'White'
$checkbox4.Checked = $false
$groupBox.Controls.Add($checkbox4)
#$Form.Controls.Add($checkbox4)
     
  
      
$checkbox5.Location = new-object System.Drawing.Size(15, 120)
$checkbox5.Size = new-object System.Drawing.Size(200, 20)
$checkbox5.Text = 'Debloat All Keep Edge'
$checkbox5.ForeColor = 'White'
$checkbox5.Checked = $false
$groupBox.Controls.Add($checkbox5)
#$Form.Controls.Add($checkbox5)
      
  
      
$checkbox6.Location = new-object System.Drawing.Size(15, 150)
$checkbox6.Size = new-object System.Drawing.Size(200, 20)
$checkbox6.Text = 'Debloat All Keep Store'
$checkbox6.ForeColor = 'White'
$checkbox6.Checked = $false
$groupBox.Controls.Add($checkbox6)
#$Form.Controls.Add($checkbox6)




function Get-Packages {
    param (
        [bool]$showLockedPackages
    )

    # Clear the logos hashtable and the checked list box items
    $Global:logos.Clear()
    $customCheckedListBox.Items.Clear()

    $packageNames = (Get-AppxPackage -AllUsers).name
    #remove dups
    $Global:sortedPackages = $packageNames | Sort-Object | Get-Unique

    if ($showLockedPackages) {
        $Global:BloatwareLocked = @()
        foreach ($package in $sortedPackages) {
            $isProhibited = $prohibitedPackages | Where-Object { $package -like $_ }
            if ($package -in $lockedAppxPackages -and !$isProhibited) {
                if ($package -eq 'E2A4F912-2574-4A75-9BB0-0D023378592B') {
                    $package = 'Microsoft.Windows.AppResolverUX'
                }
                elseif ($package -eq 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE') {
                    $package = 'Microsoft.Windows.AppSuggestedFoldersToLibraryDialog'
                }
                $Global:BloatwareLocked += $package
            }
        }

        # Populate logos for locked packages
        foreach ($packageName in $Global:BloatwareLocked) {
            Add-LogoForPackage -packageName $packageName
        }

    }
    else {
        $Global:Bloatware = @()
        foreach ($package in $sortedPackages) {
            $isProhibited = $prohibitedPackages | Where-Object { $package -like $_ }
            if ($package -notin $lockedAppxPackages -and !$isProhibited) {
                $Global:Bloatware += $package
            }
        }

        # Populate logos for regular packages
        foreach ($packageName in $Global:Bloatware) {
            Add-LogoForPackage -packageName $packageName
        }

    }

    # Add items to the checked list box
    foreach ($package in $Global:logos.GetEnumerator()) {
        $customCheckedListBox.Items.Add($package.Key) *>$null
    }
}

# Define the function to add logo for a package
function Add-LogoForPackage {
    param (
        [string]$packageName
    )

    $systemApps = 'C:\Windows\SystemApps'
    $windowsApps = 'C:\Program Files\WindowsApps'
     
    $sysAppFolders = (Get-ChildItem -Path $systemApps -Directory).FullName
    foreach ($folder in $sysAppFolders) {
        if ($folder -like "*$packageName*") {
            if (Test-Path "$folder\Assets" -PathType Container) {
                #specfic logos
                if ($packageName -like 'Microsoft.AAD.BrokerPlugin') {
                    $logos.Add($packageName, "$folder\Assets\PasswordExpiry.contrast-black_scale-100.png")
                }
                elseif ($packageName -like 'Microsoft.Windows.CallingShellApp') {
                    $logos.Add($packageName, "$folder\Assets\square44x44logo.scale-100.png")
                }
                elseif ($packageName -like 'Microsoft.Windows.AssignedAccessLockApp') {
                    try { $Global:logos.Add($packageName, $noLogoPath) }catch {}
                    
                }
                elseif ($packageName -like 'Microsoft.LockApp') {
                    try { $Global:logos.Add($packageName, $noLogoPath) }catch {}
    
                }
                elseif ($packageName -like 'Microsoft.XboxGameCallableUI') {
                    $logos.Add($packageName, "$folder\Assets\SmallLogo.scale-100.png")
                }
                else {
                    #get generic logo
                    $logo = (Get-ChildItem -Path "$folder\Assets\*.scale-100.png" | Select-Object -First 1).FullName
                    if ($logo) {
                        try { $Global:logos.Add($packageName, $logo) }catch {}
                    }
                }
            
            }
        }
    }

    $winAppFolders = (Get-ChildItem -Path $windowsApps -Directory).FullName
    foreach ($folder in $winAppFolders) {
        if ($folder -like "*$packageName*") {
            if (Test-Path "$folder\Assets" -PathType Container) {
                if ($packageName -like '*Microsoft.549981C3F5F10*') {
                    #cortana
                    if (Test-Path "$folder\Assets\Store" -PathType Container) {
                        $logo = (Get-ChildItem -Path "$folder\Assets\Store\*.scale-100.png" | Select-Object -First 1).FullName
                        try { $Global:logos.Add($packageName, $logo) }catch {}
                    }

                }
                elseif ($packageName -like '*MicrosoftStickyNotes*') {
                    if (Test-Path "$folder\Assets\Icons" -PathType Container) {
                        $logo = (Get-ChildItem -Path "$folder\Assets\Icons\*.scale-100.png" | Select-Object -First 1).FullName
                        if ($logo) {
                            try { $Global:logos.Add($packageName, $logo) }catch {}
                        }
                
                    }
                }
                elseif ($packageName -like '*MicrosoftSolitaireCollection*') {
                    if (Test-Path "$folder\Win10" -PathType Container) {
                        $logo = (Get-ChildItem -Path "$folder\Assets\Icons\*.scale-100.png" | Select-Object -First 1).FullName
                        if ($logo) {
                            try { $Global:logos.Add($packageName, $logo) }catch {}
                        }
                
                    }
                }
                elseif ($packageName -like '*Microsoft.Windows.Photos*') {
                    if (Test-Path "$folder\Assets\Retail" -PathType Container) {
                        $logo = (Get-ChildItem -Path "$folder\Assets\Retail\*.scale-100.png" | Select-Object -First 1).FullName
                        if ($logo) {
                            try { $Global:logos.Add($packageName, $logo) }catch {}
                        }
                
                    }
                }
                else {
                    $logo = (Get-ChildItem -Path "$folder\Assets\*.scale-100.png" | Select-Object -First 1).FullName
                    if ($logo) {
                        try { $Global:logos.Add($packageName, $logo) }catch {}
                    }
                    else {
                        if (Test-Path "$folder\Assets\AppTiles" -PathType Container) {
                            $logo = (Get-ChildItem -Path "$folder\Assets\AppTiles\*.scale-100.png" | Select-Object -First 1).FullName
                            if ($logo) {
                                try { $Global:logos.Add($packageName, $logo) }catch {}
                            }
                        }
              
                    }
                }
            
            }
            elseif (Test-Path "$folder\Images" -PathType Container) {
                $logo = (Get-ChildItem -Path "$folder\Images\*.scale-100.png" | Select-Object -First 1).FullName
                if ($logo) {
                    try { $Global:logos.Add($packageName, $logo) }catch {}
                }
            }
                    
        }
    }
    if (-not $Global:logos.ContainsKey($packageName)) {
        $Global:logos.Add($packageName, $noLogoPath) 
    }
}
    


        
$showLockedPackages = New-Object System.Windows.Forms.CheckBox
$showLockedPackages.Location = new-object System.Drawing.Size(15, 255)
$showLockedPackages.Size = new-object System.Drawing.Size(200, 20)
$showLockedPackages.Text = 'Show Locked Packages'
$showLockedPackages.ForeColor = 'White'
$showLockedPackages.Checked = $false
$showLockedPackages.Add_CheckedChanged({ Get-Packages -showLockedPackages $showLockedPackages.Checked })
$Form.Controls.Add($showLockedPackages)

$extraEdge = New-Object System.Windows.Forms.CheckBox
$extraEdge.Location = new-object System.Drawing.Size(15, 25)
$extraEdge.Size = new-object System.Drawing.Size(115, 20)
$extraEdge.Text = 'Microsoft Edge'
$extraEdge.ForeColor = 'White'
$extraEdge.Checked = $false
$groupBox2.Controls.Add($extraEdge)

$extraWebview = New-Object System.Windows.Forms.CheckBox
$extraWebview.Location = new-object System.Drawing.Size(130, 25)
$extraWebview.Size = new-object System.Drawing.Size(108, 20)
$extraWebview.Text = 'Edge WebView'
$extraWebview.ForeColor = 'White'
$extraWebview.Checked = $false
$groupBox2.Controls.Add($extraWebview)

$extraTeamsOneDrive = New-Object System.Windows.Forms.CheckBox
$extraTeamsOneDrive.Location = new-object System.Drawing.Size(15, 55)
$extraTeamsOneDrive.Size = new-object System.Drawing.Size(150, 20)
$extraTeamsOneDrive.Text = 'Teams and OneDrive'
$extraTeamsOneDrive.ForeColor = 'White'
$extraTeamsOneDrive.Checked = $false
$groupBox2.Controls.Add($extraTeamsOneDrive)
#$Form.Controls.Add($extraTeamsOneDrive)

$extraUpdateTools = New-Object System.Windows.Forms.CheckBox
$extraUpdateTools.Location = new-object System.Drawing.Size(15, 85)
$extraUpdateTools.Size = new-object System.Drawing.Size(150, 20)
$extraUpdateTools.Text = 'Windows Update Tools'
$extraUpdateTools.ForeColor = 'White'
$extraUpdateTools.Checked = $false
$groupBox2.Controls.Add($extraUpdateTools)
#$Form.Controls.Add($extraUpdateTools)


$extraRemoveRemote = New-Object System.Windows.Forms.CheckBox
$extraRemoveRemote.Location = new-object System.Drawing.Size(15, 115)
$extraRemoveRemote.Size = new-object System.Drawing.Size(170, 20)
$extraRemoveRemote.Text = 'Remote Desktop Connection'
$extraRemoveRemote.ForeColor = 'White'
$extraRemoveRemote.Checked = $false
$groupBox2.Controls.Add($extraRemoveRemote)
#$Form.Controls.Add($extraRemoveRemote)

$extraDISM = New-Object System.Windows.Forms.CheckBox
$extraDISM.Location = new-object System.Drawing.Size(15, 145)
$extraDISM.Size = new-object System.Drawing.Size(220, 27)
$extraDISM.Text = 'Hello Face, Quick-Assist and Steps Recorder'
$extraDISM.ForeColor = 'White'
$extraDISM.Checked = $false
$groupBox2.Controls.Add($extraDISM)
#$Form.Controls.Add($extraDISM)

$extraStartMenu = New-Object System.Windows.Forms.CheckBox
$extraStartMenu.Location = new-object System.Drawing.Size(15, 175)
$extraStartMenu.Size = new-object System.Drawing.Size(220, 20)
$extraStartMenu.Text = 'Clean Start Menu Icons'
$extraStartMenu.ForeColor = 'White'
$extraStartMenu.Checked = $false
$groupBox2.Controls.Add($extraStartMenu)
#$Form.Controls.Add($extraStartMenu)


       
#GLOBAL VARS
$Global:logos = [System.Collections.Hashtable]::new()
# $Global:Bloatware = @()
$customCheckedListBox = [CustomCheckedListBox]::new()
$Global:noLogoPath = "$PSScriptRoot\Assets\1X1.png"
$Global:sortedPackages = @()

$Global:lockedAppxPackages = @(
    'Microsoft.Windows.NarratorQuickStart' 
    'Microsoft.Windows.ParentalControls'
    'Microsoft.Windows.PeopleExperienceHost'
    'Microsoft.ECApp'
    'Microsoft.LockApp'
    'NcsiUwpApp'
    'Microsoft.XboxGameCallableUI'
    'Microsoft.Windows.XGpuEjectDialog'
    'Microsoft.Windows.SecureAssessmentBrowser'
    'Microsoft.Windows.PinningConfirmationDialog'
    'Microsoft.AsyncTextService'
    'Microsoft.AccountsControl'
    'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE'
    'E2A4F912-2574-4A75-9BB0-0D023378592B'
    'Microsoft.Windows.PrintQueueActionCenter'
    'Microsoft.Windows.CapturePicker'
    'Microsoft.CredDialogHost'
    'Microsoft.Windows.AssignedAccessLockApp'
    'Microsoft.Windows.Apprep.ChxApp'
    'Windows.PrintDialog'
    'Microsoft.Windows.ContentDeliveryManager'
    'Microsoft.BioEnrollment'
    'Microsoft.Windows.CloudExperienceHost'
    'MicrosoftWindows.UndockedDevKit'
    'Microsoft.Windows.OOBENetworkCaptivePortal'
    'Microsoft.Windows.OOBENetworkConnectionFlow'
    'Microsoft.AAD.BrokerPlugin'
    'MicrosoftWindows.Client.CoPilot'
    'MicrosoftWindows.Client.CBS'
    'MicrosoftWindows.Client.Core'
    'MicrosoftWindows.Client.FileExp'
    'Microsoft.SecHealthUI'
    'Microsoft.Windows.SecHealthUI'
    'windows.immersivecontrolpanel'
    'Windows.CBSPreview'
    'MicrosoftWindows.Client.WebExperience'
    'Microsoft.Windows.CallingShellApp'
    'Microsoft.Win32WebViewHost'
    'Microsoft.MicrosoftEdgeDevToolsClient'
    'Microsoft.Advertising.Xaml'
    'Microsoft.Services.Store.Engagement'
    'Microsoft.WidgetsPlatformRuntime'
)

$Global:prohibitedPackages = @(
    'Microsoft.NET.Native.Framework.*'
    'Microsoft.NET.Native.Runtime.*'
    'Microsoft.UI.Xaml.*'
    'Microsoft.VCLibs.*'
    'Microsoft.WindowsAppRuntime.*'
    'c5e2524a-ea46-4f67-841f-6a9465d9d515'
    '1527c705-839a-4832-9118-54d4Bd6a0c89'
    'Microsoft.Windows.ShellExperienceHost'
    'Microsoft.Windows.StartMenuExperienceHost'
    'Microsoft.DekstopAppInstaller'
    'Microsoft.Windows.Search'
    'MicrosoftWindows.LKG*'
    'MicrosoftWindows.Client.LKG'
    'MicrosoftWindows.Client.Photon'
    'MicrosoftWindows.Client.AIX'
    'MicrosoftWindows.Client.OOBE'
)

        
$customCheckedListBox.Location = New-Object System.Drawing.Point(270, 50)
$customCheckedListBox.Size = New-Object System.Drawing.Size(360, 415)
$customCheckedListBox.BackColor = 'Black'
$customCheckedListBox.ForeColor = 'White'
$customCheckedListBox.CheckOnClick = $true
$form.Controls.Add($customCheckedListBox)
Get-Packages -showLockedPackages $false
[CustomCheckedListBox]::logos = $Global:logos



    
$form.Topmost = $true
  
$result = $form.ShowDialog()
    


  
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
       
  
    if ($checkbox2.Checked) {
          
        debloatPreset -choice 'debloatAll'
        Write-Host 'Removing Teams and One Drive'
        debloat-TeamsOneDrive
        debloat-LockedPackages
        Write-Host 'Removing Remote Desktop Connection'
        debloat-remotedesktop
        debloat-HealthUpdateTools
        Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
        debloat-dism
      
        Write-Host 'Uninstalling Edge...'
        $edge = "$PSScriptRoot\Assets\EdgeRemove.ps1"
        &$edge -Webview
        Write-Host 'Cleaning Start Menu...'
        $unpin = "$PSScriptRoot\Assets\unpin.ps1"
        & $unpin
    }
    if ($checkbox3.Checked) {
     
      
        debloatPreset -choice 'debloatKeepStore'
        Write-Host 'Removing Teams and One Drive'
        debloat-TeamsOneDrive
        debloat-HealthUpdateTools
        Write-Host 'Removing Remote Desktop Connection'
        debloat-remotedesktop
        Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
        debloat-dism
  
        Write-Host 'Cleaning Start Menu...'
        $unpin = "$PSScriptRoot\Assets\unpin.ps1"
        & $unpin
  
    }
    if ($checkbox4.Checked) {
  
     
        debloatPreset -choice 'debloatKeepStoreXbox'
        Write-Host 'Removing Teams and One Drive'
        debloat-TeamsOneDrive
        debloat-HealthUpdateTools
        Write-Host 'Removing Remote Desktop Connection'
        debloat-remotedesktop
        Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
        debloat-dism

        Write-Host 'Uninstalling Edge...'
        $edge = "$PSScriptRoot\Assets\EdgeRemove.ps1"
        &$edge
        Write-Host 'Cleaning Start Menu...'
        $unpin = "$PSScriptRoot\Assets\unpin.ps1"
        & $unpin     
      
    }
    if ($checkbox5.Checked) {
        debloatPreset -choice 'debloatAll'
        Write-Host 'Removing Teams and One Drive'
        debloat-TeamsOneDrive
        Write-Host 'Removing Remote Desktop Connection'
        debloat-remotedesktop
        debloat-HealthUpdateTools
        Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
        debloat-dism

        Write-Host 'Cleaning Start Menu...'
        $unpin = "$PSScriptRoot\Assets\unpin.ps1"
        & $unpin
  
    }
    if ($checkbox6.Checked) { 
    
     
        debloatPreset -choice 'debloatKeepStore'
        Write-Host 'Removing Teams and One Drive'
        debloat-TeamsOneDrive
        debloat-HealthUpdateTools
        Write-Host 'Removing Remote Desktop Connection'
        debloat-remotedesktop
        Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
        debloat-dism
  
        Write-Host 'Uninstalling Edge...'
        $edge = "$PSScriptRoot\Assets\EdgeRemove.ps1"
        &$edge
        Write-Host 'Cleaning Start Menu...'
        $unpin = "$PSScriptRoot\Assets\unpin.ps1"
        & $unpin
  
    }



    #------------------------- debloat extras

    if ($extraEdge.Checked) {
        if ($extraWebview.Checked) {
            Write-Host 'Uninstalling Edge && WebView...'
            $edge = "$PSScriptRoot\Assets\EdgeRemove.ps1"
            &$edge -Webview
        }
        else {
            Write-Host 'Uninstalling Edge...'
            $edge = "$PSScriptRoot\Assets\EdgeRemove.ps1"
            &$edge
        }
    }

    if ($extraTeamsOneDrive.Checked) {
        Write-Host 'Removing Teams and One Drive'
        debloat-TeamsOneDrive
    }

    if ($extraUpdateTools.Checked) {
        Write-Host 'Removing Windows Update Tools'
        debloat-HealthUpdateTools
    }

    if ($extraDISM.Checked) {
        Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
        debloat-dism
    }

    if ($extraRemoveRemote.Checked) {
        Write-Host 'Removing Remote Desktop Connection'
        debloat-remotedesktop
    }

    if ($extraStartMenu.Checked) {
        Write-Host 'Cleaning Start Menu...'
        $unpin = "$PSScriptRoot\Assets\unpin.ps1"
        & $unpin
    }


   
    Custom-MsgBox -message 'Bloat Removed!' -type None
    
     
}

