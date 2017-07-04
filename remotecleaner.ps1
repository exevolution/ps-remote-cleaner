# requires -Version 3.0
# Version 1.5.0.5
# This PowerShell script is designed to perform regular maintainance on domain computers
# If you encounter any errors, please contact Elliott Berglund x8981

# Get current local username
$LocalAdmin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# Per-admin log path setup
$LogRoot = ($LocalAdmin).Replace("$env:USERDOMAIN\", '')
$LogPath = "$PSScriptRoot\Logs\$LogRoot"

# Make log directory if it doesn't exist and start the transcript
Try
{
    If (!([System.IO.Directory]::Exists($LogPath)))
    {
        New-Item -ItemType Directory -Path "$PSScriptRoot\Logs" -Name $LogRoot -ErrorAction Stop
    }
    Else
    {
        Write-Host "$LogPath already exists."
    }
}
Catch
{
    Write-Host "Unhandled exception creating $LogPath" -ForegroundColor Yellow
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
}
Finally
{
    Start-Transcript -OutputDirectory $LogPath
}

# Config options
$VerbosePreference = "SilentlyContinue"
$DelProfPreference = "Unattended"
$DNSNameLengthLimit = 15
$LogLimitDays = 14

# Log pruning
Get-ChildItem -LiteralPath $LogPath -Attributes !D,!D+H,!D+S,!D+H+S -Recurse -Force -ErrorAction Stop | Where-Object {$_.CreationTime -lt (Get-Date).AddDays(-$LogLimitDays)} | Remove-Item

# Import AD module
If (!(Get-Module ActiveDirectory))
{
    Import-Module -Name ActiveDirectory -ErrorAction Stop
}

# Paths to commonly used folders
$BinaryPath = Join-Path -Path "$PSScriptRoot" -ChildPath "Bin"
$PSToolsPath = Join-Path -Path "$BinaryPath" -ChildPath "PSTools"
$DelProfPath = Join-Path -Path "$BinaryPath" -ChildPath "DelProf2 1.6.0"
$DownloadPath = Join-Path -Path "$PSScriptRoot" -ChildPath "Downloads"

# Check for existance of standalone applications, download and extract if missing.
If (!(Test-Path "$BinaryPath"))
{
    New-Item -ItemType Directory "$BinaryPath"
}

If (!(Test-Path "$DownloadPath"))
{
    New-Item -ItemType Directory "$DownloadPath"
}

If (!(Test-Path "$PSToolsPath"))
{
    # Add ability to (de)compress ZIP files
    Add-Type -AssemblyName "system.io.compression.filesystem"

    New-Item -ItemType Directory "$PSToolsPath"
    $PSToolsDownloadUri = "https://download.sysinternals.com/files/PSTools.zip"
    $PSToolsDownloadDestination = Join-Path -Path "$DownloadPath" -ChildPath "PSTools.zip"
    Invoke-WebRequest -Uri "$PSToolsDownloadUri" -OutFile "$PSToolsDownloadDestination"
    [io.compression.zipfile]::ExtractToDirectory($PSToolsDownloadDestination, $PSToolsPath)
}

If (!(Test-Path "$DelProfPath"))
{
    New-Item -ItemType Directory "$DelProfPath"
    $DelProf2DownloadUri = "https://helgeklein.com/downloads/DelProf2/current/Delprof2%201.6.0.zip"
    $DelProf2DownloadDestination = Join-Path -Path "$DownloadPath" -ChildPath "DelProf2-1.6.0.zip"
    Invoke-WebRequest -Uri "$DelProf2DownloadUri" -OutFile "$DelProf2DownloadDestination"
    [io.compression.zipfile]::ExtractToDirectory($DelProf2DownloadDestination, $BinaryPath)
}

# Set buffer and window size
$PSHost = Get-Host
$PSHost.UI.RawUI.BufferSize.Height = 2000
$PSHost.UI.RawUI.BufferSize.Width = 130

# ----------------
# Define Functions
# ----------------

Function Test-PathEx
{
    Param($Path)

    If (Test-Path $Path)
    {
        $True
    }
    Else
    {
        $Parent = Split-Path $Path
        [System.IO.Directory]::EnumerateFiles($Parent) -Contains $Path
    }
}
Function Get-FreeSpace
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Low")]

    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,

        [Parameter(Mandatory=$True, Position=1)]
        [ValidateNotNullOrEmpty()]
        [String]$DriveLetter
)
    Begin
    {
        $DriveLetter = $DriveLetter -replace '[:|$]',''
    }
    Process
    {
        $FreeSpace = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName | Where-Object { $_.DeviceID -eq "$DriveLetter`:" } | Select-Object SystemName, Caption, @{Name="FreeSpace"; Expression={"$([math]::Round($_.FreeSpace / 1GB,2))GB"}}, @{Name="PercentFree"; Expression={"$([math]::Round($_.FreeSpace / $_.Size,2) * 100)%"}}
        $Out = [PSCustomObject][Ordered]@{
        'ComputerName' = $FreeSpace.SystemName
        'DriveLetter' = $FreeSpace.Caption
        'FreeSpace' = $FreeSpace.FreeSpace
        'PercentFree' = $FreeSpace.PercentFree
        }
    }
    End
    {
        Return $Out
    }
}

Function Run-DelProf2
{
    Switch ($Args[0])
    {
        'Unattended'
            {
            $VarAttend = '/u'
            }
        'Prompt'
            {
            $VarAttend = '/p'
            }
        Default
            {
            $VarAttend = ''
            }
    }
    'Deleting Stale User Profiles With DelProf2.'
    'Please wait... This may take several minutes.'
    ''
    $Global:DelProf = Start-Process -FilePath "$DelProfPath\DelProf2.exe" -ArgumentList "/c:$HostName /ed:$ShortUser`* /ed:Admin* /ed:00* /ed:Default* /ed:Public* /ed:MsDts* $VarAttend /ntuserini" -Wait -PassThru
    $Global:DelProfExit = $Global:DelProf.ExitCode
    If ($Global:DelProfExit -eq "0")
    {
        'DelProf2 completed successfully'
    }
    ElseIf ($Global:DelProfExit -eq $null)
    {
        'DelProf2 exited but the error code was lost'
    }
    Else
    {
        "DelProf2 encountered an error. Exit code $Global:DelProfExit"
    }
    Return
}

Function Resolve-Host
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Low")]

    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName
    )

    Begin
    {

    }

    Process
    {
        If ($ComputerName -As [IPAddress])
        {
            $IP = $ComputerName
            $ComputerName = [System.Net.Dns]::GetHostEntry($ComputerName).HostName
        }
        Else
        {
            $ComputerName = $ComputerName.ToUpper()
            $IP = [System.Net.Dns]::GetHostAddresses($ComputerName) | Where-Object {$_.AddressFamily -eq "InterNetwork"} | Select-Object -ExpandProperty IPAddressToString
        }
    }

    End
    {
        Return [PSCustomObject][Ordered]@{
        'ComputerName' = $ComputerName
        'IPAddress' = $IP
        }
    }
}

Function Remove-WithProgress
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Medium")]

    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,

        [Parameter(Mandatory=$True, Position=1)]
        [ValidateNotNullOrEmpty()]
        [String]$Title
    )

    Begin
    {
        Write-Host (('-' * 130) + "`n")
    }

    Process
    {
        # Progress Bar counter
        $CurrentFileCount = 0
        $CurrentFolderCount = 0

        # Start progress bar
        Write-Progress -Id 0 -Activity "Enumerating $Title from $HostName" -PercentComplete 0

        Write-Host "Enumerating $Title"
        Write-Host "Please wait..."

        # Enumerate files, silence errors
        Try
        {
            $Files = @(Get-ChildItem -Force -LiteralPath "$Path" -Attributes !D,!D+H,!D+S,!D+H+S -Recurse -ErrorAction Stop) | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
        }
		Catch
		{
            Write-Host "Unhandled exception enumerating $Path" -ForegroundColor Yellow
            Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		}

        # Total file count for progress bar
        $TotalSize = [Math]::Round(($Files | Measure-Object -Sum Length).Sum / 1GB,3)

        Write-Host "Removing $($Files.Count) $Title... $TotalSize`GB."
        ForEach ($File in $Files)
        {
            $CurrentFileCount++
            Write-Progress -Id 0 -Activity "Removing $Title" -CurrentOperation "File: $($File.FullName)" -PercentComplete ([math]::Round(($CurrentFileCount / $($Files.Count)) * 100)) -Status "Progress: $CurrentFileCount of $($Files.Count), $([math]::Round(($CurrentFileCount / $($Files.Count)) * 100))%"
            Write-Verbose "Removing file $($File.FullName)"
            Try
            {
                Write-Verbose -Message "Removing file $($File.FullName)"
                $File | Remove-Item -ErrorAction Stop
            }
            Catch [System.IO.IOException]
            {
                Write-Host "Encountered an error while deleting $($File.FullName)" -ForegroundColor Yellow
                Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
            }
            Catch [System.UnauthorizedAccessException]
            {
                Write-Host "Encountered an error while deleting $($File.FullName)" -ForegroundColor Yellow
                Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
            }
            Catch
            {
                Write-Host "Encountered an error while deleting $($File.FullName)" -ForegroundColor Yellow
                Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            }
            Finally
            {
                
            }
        }
        Write-Progress -Id 0 -Completed -Activity 'Done'

        # Enumerate folders with 0 files
        Try
		{
			$EmptyFolders = @(Get-ChildItem -Force -LiteralPath "$Path" -Attributes D,D+H,D+S,D+S+H -Recurse -ErrorAction Stop) | Where-Object {($_.GetFiles()).Count -eq 0} -ErrorAction Stop | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
		}
		Catch
		{
            Write-Host "Unhandled exception enumerating $Path" -ForegroundColor Yellow
            Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
		}
    
        If ($EmptyFolders.Count -gt 0)
        {
            "Removing $($EmptyFolders.Count) empty folders"
            $Title = 'Removing Empty Directories'

            ForEach ($EmptyFolder in $EmptyFolders)
            {
                # Increment Folder Counter
                $CurrentFolderCount++

                If ((($EmptyFolder.GetFiles()).Count + ($EmptyFolder.GetDirectories()).Count) -ne 0)
                {
                    Write-Verbose "$($EmptyFolder.FullName) not empty, skipping..."
                    Continue
                }

                Write-Progress -Id 1 -Activity "Removing $Title" -CurrentOperation "Removing Empty Directory: $($EmptyFolder.FullName)" -PercentComplete $([math]::Round(($CurrentFolderCount / $($EmptyFolders.Count)) * 100)) -Status "Progress: $CurrentFolderCount of $($EmptyFolders.Count), $([math]::Round(($CurrentFolderCount / $($EmptyFolders.Count)) * 100))%"
                Write-Verbose "Removing folder $($EmptyFolder.FullName)"

                Try
                {
                    Write-Verbose -Message "Removing folder $($EmptyFolder.FullName)"
                    $EmptyFolder | Remove-Item -ErrorAction Stop
                }
                Catch [System.IO.IOException]
                {
                    Write-Host "Encountered an error while deleting $($EmptyFolder.FullName)" -ForegroundColor Yellow
                    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
                }
                Catch [System.UnauthorizedAccessException]
                {
                    Write-Host "Encountered an error while deleting $($EmptyFolder.FullName)" -ForegroundColor Yellow
                    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
                }
                Catch
                {
                    Write-Host "Encountered an error while deleting $($EmptyFolder.FullName)" -ForegroundColor Yellow
                    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
                }
                Finally
                {
                    
                }
            }
            Write-Progress -Id 1 -Completed -Activity 'Done'
        }
    }

    End
    {
        Write-Host ("`n" + ('-' * 130))
        Return
    }
}

Function Test-Credential 
{ 
    [CmdletBinding()] 
    [OutputType([Bool])] 
    Param 
    ( 
        # Credential, Type PSCredential, The PSCredential Object to test. 
        [Parameter(Position = 0, ValueFromPipeLine = $True)] 
        [PSCredential]
        $AdminCreds, 
 
        # Domain, Type String, The domain name to test PSCredetianl Object against. 
        [Parameter(Position = 1)] 
        [String] 
        $Domain = $env:USERDOMAIN 
    ) 
 
    Begin 
    { 
        If (-not($PSBoundParameters.ContainsValue($AdminCreds))) 
        { 
            $AdminCreds = Get-Credential -Credential $LocalAdmin
        } 
         
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement") 
        $PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain) 
    } 
 
    Process 
    { 
        $NetworkCredential = $AdminCreds.GetNetworkCredential() 
        return $PrincipalContext.ValidateCredentials($NetworkCredential.UserName, $NetworkCredential.Password) 
    } 
 
    End 
    { 
        $PrincipalContext.Dispose() 
    } 
}

# ----------------
# End Functions
# ----------------

# Validate credentials against AD
Do
{
    $Credentials = Get-Credential -Credential $LocalAdmin
}
Until (Test-Credential $Credentials)
Write-Host "Credentials validated!"

# Begin main loop
Do
{
    # Get current date for logs
    $LogDate = (Get-Date).ToString('yyyy-MM-dd')
    $DateSelect = $LogDate

    Clear-Host
    Write-Host '
                      ▄███████▄    ▄████████ ███▄▄▄▄   ███▄▄▄▄   ▄██   ▄     ▄▄▄▄███▄▄▄▄      ▄████████  ▄████████
                     ███    ███   ███    ███ ███▀▀▀██▄ ███▀▀▀██▄ ███   ██▄ ▄██▀▀▀███▀▀▀██▄   ███    ███ ███    ███
                     ███    ███   ███    █▀  ███   ███ ███   ███ ███▄▄▄███ ███   ███   ███   ███    ███ ███    █▀
                     ███    ███  ▄███▄▄▄     ███   ███ ███   ███ ▀▀▀▀▀▀███ ███   ███   ███   ███    ███ ███
                   ▀█████████▀  ▀▀███▀▀▀     ███   ███ ███   ███ ▄██   ███ ███   ███   ███ ▀███████████ ███
                     ███          ███    █▄  ███   ███ ███   ███ ███   ███ ███   ███   ███   ███    ███ ███    █▄
                     ███          ███    ███ ███   ███ ███   ███ ███   ███ ███   ███   ███   ███    ███ ███    ███
                    ▄████▀        ██████████  ▀█   █▀   ▀█   █▀   ▀█████▀   ▀█   ███   █▀    ███    █▀  ████████▀

    ▀█████████▄   ▄██████▄      ███         ███      ▄█          ▄████████ ███▄▄▄▄      ▄████████  ▄████████    ▄█   ▄█▄    ▄████████
      ███    ███ ███    ███ ▀█████████▄ ▀█████████▄ ███         ███    ███ ███▀▀▀██▄   ███    ███ ███    ███   ███ ▄███▀   ███    ███
      ███    ███ ███    ███    ▀███▀▀██    ▀███▀▀██ ███         ███    █▀  ███   ███   ███    █▀  ███    █▀    ███▐██▀     ███    █▀
     ▄███▄▄▄██▀  ███    ███     ███   ▀     ███   ▀ ███        ▄███▄▄▄     ███   ███  ▄███▄▄▄     ███         ▄█████▀      ███
    ▀▀███▀▀▀██▄  ███    ███     ███         ███     ███       ▀▀███▀▀▀     ███   ███ ▀▀███▀▀▀     ███        ▀▀█████▄    ▀███████████
      ███    ██▄ ███    ███     ███         ███     ███         ███    █▄  ███   ███   ███    █▄  ███    █▄    ███▐██▄            ███
      ███    ███ ███    ███     ███         ███     ███▌    ▄   ███    ███ ███   ███   ███    ███ ███    ███   ███ ▀███▄    ▄█    ███
    ▄█████████▀   ▀██████▀     ▄████▀      ▄████▀   █████▄▄██   ██████████  ▀█   █▀    ██████████ ████████▀    ███   ▀█▀  ▄████████▀
                                                    ▀                                                          ▀'
    Write-Host "`nThis PowerShell script is designed to perform regular maintainance on desktops and VDDs."
    Write-Host "If you encounter any errors, please contact Elliott Berglund x8981"
    Write-Host ('=' * 130) -ForegroundColor Red
    Write-Host "WARNING: Do not run this script on servers!" -ForegroundColor Red
    Write-Host ('=' * 130) -ForegroundColor Red

    # Collect Computer Info
    Do
    {
        # If IP entry does not resolve as an IP, loop
        Do
        {
            $HostEntry = (Read-Host -Prompt 'Enter the computer name or IP address') -replace "`r`n","" -replace " ","" -replace "`t",""
            If ($HostEntry.Length -gt $DNSNameLengthLimit)
            {
                $HostEntry = $HostEntry.Substring(0,$DNSNameLengthLimit)
            }
            $Resolved = Try
            {
                Resolve-Host -ComputerName $HostEntry -ErrorAction Stop
            }
            Catch
            {
                Write-Host "Failed to resolve $HostEntry!" -ForegroundColor Yellow
                Write-Host $_.Exception.Message -ForegroundColor Red
                If ($Resolved)
                {
                    Remove-Variable Resolved
                }
                Continue
            }
        }
        Until ($Resolved)

        $HostName = $Resolved.ComputerName
        $HostIP = $Resolved.IPAddress

        ''
        '-------------------------------------------------------'
        "Computer Name: $HostName"
        "IP Address: $HostIP"
        "Admin Username: $LocalAdmin"
        '-------------------------------------------------------'
        ''

        $VerifyHost = Read-Host 'Is this correct? (Y/N)'
        If ($VerifyHost -eq "Y")
        {
            Break
        }
    }
    While ($True)

    # Collect info from computer, get active user
    ''
    '-------------------------------------------------------'
    "Collecting information from $HostName, please wait..."
    '-------------------------------------------------------'
    ''

    If (Test-Path  "\\$HostName\Admin`$\*")
    {
        "Admin rights confirmed on $HostName"
    }
    Else
    {
        Write-Warning 'Admin rights not detected on remote machine.'
        Continue
    }

    $ComputerSys =  Get-WmiObject Win32_ComputerSystem -Computer $HostName

    # Create blank array
    $UserArray = @()

    # Store all non system profiles
    $AllProfiles = @(Get-WmiObject -Class Win32_UserProfile -ComputerName $HostName -Property *) | Where-Object {($_.LocalPath -notmatch "00") -and ($_.LocalPath -notmatch "Admin") -and ($_.LocalPath -notmatch "Default") -and ($_.LocalPath -notmatch "Public") -and ($_.LocalPath -notmatch "LocalService") -and ($_.LocalPath -notmatch "NetworkService") -and ($_.LocalPath -notmatch "systemprofile") -and ($_.LocalPath -notmatch "MsDts")} | Sort-Object LastUseTime -Descending

    ForEach ($Profile in $AllProfiles)
    {
        If ($ADAccount)
        {
            Remove-Variable ADAccount
        }
        $SID = $Profile | Select-Object -ExpandProperty SID
        $ADACcount = Get-ADUser -Filter {SID -eq $SID}
        If (!($ADAccount))
        {
            Write-Host "User Profile: $($Profile.LocalPath.Split("\")[-1])"
            Write-Host "SID: $SID"
            Write-Host "Account does not exist in Active Directory"
            Continue
        }
        $UserArray += $ADAccount
    }

    If ($UserArray.Count -eq 0)
    {
        "No valid user profiles on $HostName. Please run again on a different computer"
        Break
    }
    Else
    {
        Do
        {
            If ($SelectedUser)
            {
                Remove-Variable SelectedUser
            }

            # Display menu
            "`nProfile Listing"
            # Sort the hash table and output it
            
            For ($i=0;$i -lt "$($UserArray.Count)"; $i++)
            {
                Write-Host "[$($i + 1)] $($UserArray[$i].SamAccountName)"
            }

            # Ask user for numeric input
            ''
            [int32]$SelectedUser = Read-Host "Please select the assigned user"
            If (!($SelectedUser -as [int32]))
            {
                "`nYou must enter an integer value"
                Continue
            }
            # Subtract 1 from input for 0 indexed array
            If ($SelectedUser -gt $UserArray.Count)
            {
                "`nYou have entered a value out of range, please choose one from the list above."
                Continue
            }
            Break
        }
        While ($True)
    }

    $ShortUser = $UserArray[$SelectedUser - 1].SamAccountName
    "Selected: $ShortUser"
    ''

    # Assume, based on entered information, the active profile
    $ActiveProfile = Get-WmiObject -Class Win32_UserProfile -Computer $HostName | Where-Object {$_.LocalPath.Split('\')[-1] -Match $ShortUser}
    $OtherProfiles = $AllProfiles | Where-Object {$_.LocalPath.Split('\')[-1] -NotMatch $ShortUser}

    # If profile status Bit Field includes 8 (corrupt profile), quit.
    If ((8 -band $ActiveProfile.Status) -eq 8)
    {
        Write-Warning "PROFILE CORRUPT! User profile rebuild necessary. Quitting."
        Start-Sleep -Seconds 10
        Exit
    }

    # Grab local path from active profile
    $ProfilePath = $ActiveProfile.LocalPath

    # Convert to UNC compatible
    $ProfileShare = $ProfilePath -replace ':', '$'
    $DriveLetter = $ProfilePath.Substring(0,2)

    $Path0 = Join-Path -Path "\\$HostName" -ChildPath "$ProfileShare"

    # Calculate free space before beginning
    ''
    "Checking Free Space on $HostName, drive $DriveLetter"
    Write-Host ("`n" + ('-' * 130))
    Get-FreeSpace -ComputerName $HostName -DriveLetter $DriveLetter | Format-Table
    Write-Host (('-' * 130) + "`n")

    # Cleanup temp files and IE cache
    Do
    {
        If ($Next)
        {
            Remove-Variable Next
        }
        ''
        "Domain: $env:USERDNSDOMAIN"
        "Host: $HostName"
        "Username: $ShortUser"
        "UNC Path: $Path0"
        "Log Path: $LogPath"
        ''
        'Choose one of the following options to continue'
        '-------------------------------------------------------'
        '[1] Automated Cleanup'
        "[2] Send Logoff Command"
        "[3] Stale Profile Cleanup ($DelProfPreference)"
        "[E] Explore Files on $HostName"
        "[L] Open Logs"
        '[O] Options Menu'
        '[D] Do Nothing, Move To Next Computer'
        '[Q] Quit'
        '-------------------------------------------------------'
        $MainMenu = Read-Host 'Main Menu choice'
        Switch ($MainMenu)
        {
            # Clean drives
            1
            {
                # Give the user a chance to cancel before changes are made
                Write-Warning 'This makes permanent changes to the system. Press Ctrl+C now to cancel'
                Start-Sleep -Seconds 5

                <#
                Template for adding more cleanup locations.

                $Path = Join-Path -Path "$Path0" -ChildPath "" | Join-Path -ChildPath "" | Join-Path -ChildPath "" | Join-Path -ChildPath "" | Join-Path -ChildPath "" | Join-Path -ChildPath "" | Join-Path -ChildPath ""
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Windows Temp Files'
                }

                #>

                # USER WINDOWS TEMP
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Temp"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Profile Windows Temp Files'
                }

                # TEMP ON C:
                $Path = Join-Path -Path "\\$HostName" -ChildPath "c$" | Join-Path -ChildPath "Temp"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Root Temp Files'
                }

                # WINDOWS DIRECTORY TEMP
                $Path = Join-Path -Path "\\$HostName" -ChildPath "c$" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Temp"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Windows Temp Files'
                }

                # PROPATCHES
                $Path = Join-Path -Path "\\$HostName" -ChildPath "c$" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "ProPatches" | Join-Path -ChildPath "Patches"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Patch Installer Files'
                }

                # IE CACHE W7
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Temporary Internet Files"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 7)'
                }

                # IE COOKIES W7
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Cookies"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cookies (Windows 7)'
                }

                # IE CACHE W8.1
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCache"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 8.1)'
                }

                # IE COOKIES w8.1
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCookies"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cookies (Windows 8.1)'
                }

                # CRASH DUMPS
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "CrashDumps"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Crash Dumps'
                }

                # CHROME CACHE
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Cache"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Google Chrome Cache Files'
                }

                # CHROME MEDIA CACHE
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Media Cache"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Google Chrome Media Cache Files'
                }

                # GOOGLE CHROME UPDATES
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "Update"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Google Chrome Update Files'
                }

                # FIVE9 LOGS
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Roaming" | Join-Path -ChildPath "Five9" | Join-Path -ChildPath "Logs"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Five9 Log Files'
                }
                
                # FIVE9 INSTALLS
                $Path = Join-Path -Path "$Path0" -ChildPath "AppData" | Join-Path -ChildPath "Roaming" | Join-Path -ChildPath "Five9.*"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Old Five9 Installations'
                }

                # C: DRIVE RECYCLE BIN
                $Path = Join-Path -Path "\\$HostName" -ChildPath "c$" | Join-Path -ChildPath "`$Recycle.Bin"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Recycle Bin Files on drive C:'
                }

                # D: DRIVE RECYCLE BIN
                $Path = Join-Path -Path "\\$HostName" -ChildPath "d$" | Join-Path -ChildPath "`$Recycle.Bin"
                If (Test-Path "$Path")
                {
                    Remove-WithProgress -Path "$Path" -Title 'Recycle Bin Files on drive D:'
                }

                # Remove Other Profiles
                Write-Host "Attempting to delete $(($OtherProfiles | Measure-Object).Count) unused profiles"
                ForEach ($p in $OtherProfiles)
                {

                    Try
                    {
                        Write-Host "Removing profile: $($p.LocalPath.Split('\')[-1])"
                        $p.Delete()
                    }
                    Catch
                    {
                        Write-Host "An error occurred deleting $($p.LocalPath.Split('\')[-1])!" -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                        $DelProfNeeded = $True
                    }
                }
                If ($DelProfNeeded)
                {
                    Try
                    {
                        Write-Host "Trying backup utility DelProf2"
                        Run-DelProf2 Unattended
                    }
                    Catch
                    {
                        Write-Host "An error occurred deleting $($p.LocalPath.Split('\')[-1])!" -ForegroundColor Red
                        Write-Host $_.Exception.Message -ForegroundColor Red
                    }
                }

                Write-Host ("`n" + ('-' * 130))
                Get-FreeSpace -ComputerName $HostName -DriveLetter $DriveLetter | Format-Table
                Write-Host (('-' * 130) + "`n")
            }
            # Logoff user
            2
            {
                Try
                {
                    Import-Module -Name RemoteDesktop
                }
                Catch
                {
                    Write-Host "Unable to load RemoteDesktop PowerShell module" -ForegroundColor Yellow
                    Break
                }

                $Proceed1 = Read-Host "Are you sure you want to log off $ShortUser from $HostName`? YES to proceed (Case-sensitive)"
                If ($Proceed1 -ceq "YES")
                {
                    Try
                    {
                        $OSObject = Get-WmiObject Win32_OperatingSystem -ComputerName $HostName -ErrorAction Stop
                        $OSObject.PSBase.Scope.Options.EnablePrivileges = $True
                        $OSObject.Win32Shutdown(0)
                    }
                    Catch
                    {
                        Write-Host "An error occurred while attempting to log off $ShortUser"
                        Write-Host "Would you like to try again without prompting the user?"
                        Write-Warning "This causes applications to force close, and may result in loss of data"
                        $Proceed2 = Read-Host -Prompt "YES to proceed (Case-sensitive)"
                        If ($Proceed2 -ceq "YES")
                        {
                            Try
                            {
                                $OSObject = Get-WmiObject Win32_OperatingSystem -ComputerName $HostName -ErrorAction Stop
                                $OSObject.PSBase.Scope.Options.EnablePrivileges = $True
                                $OSObject.Win32Shutdown(4)
                            }
                            Catch
                            {
                                Write-Host "An error occurred while attempting to log off $ShortUser"
                                Write-Host "Would you like to reboot $HostName now?"
                                $Proceed3 = Read-Host -Prompt "YES to proceed (Case-sensitive)"
                                If ($Proceed3 -ceq "YES")
                                {
                                    Try
                                    {
                                        Restart-Computer -ComputerName $HostName -Wait -ErrorAction Stop
                                    }
                                    Catch
                                    {
                                        Write-Host "Unable to reboot $HostName"
                                        Write-Host "Please reboot manually"
                                    }

                                }
                                Else
                                {
                                    Break
                                }
                            }
                        }
                        Break
                    }
                }
                Break
            }
            # Run DelProf2
            3
            {
                # DelProf
                Run-DelProf2 $DelProfPreference
                Write-Host ("`n" + ('-' * 130))
                Get-FreeSpace -ComputerName $HostName -DriveLetter $DriveLetter | Format-Table
                Write-Host (('-' * 130) + "`n")
            }
            # Open Windows Explorer to UNC Path
            E
            {
                &explorer "\\$HostName\$ProfileShare\"
                Continue
            }
            # Old Logging Stuff, WIP
            L
            {
                Do
                {
                    'Daily Logs'
                    '-------------------------------------------------------'
                    "[1] Open Bottleneck Log: bottleneckreport-$DateSelect.txt"
                    "[2] Open Runtime Log: runtime-$DateSelect.txt"
                    "[3] Open Manual Log: manual-$DateSelect.txt"
                    "[4] Open All Logs for $DateSelect"
                    "[5] Open Log Folder"
                    "[6] Back 1 Day"
                    "[7] Back 7 Days"
                    "[8] Set to Today's Date"
                    "[B] Return to Main Menu"
                    '-------------------------------------------------------'

                    $LogMenu = Read-Host "Log menu choice"
                    Switch ($LogMenu)
                    {
                        1
                        {
                            If (Test-Path "$LogPath\bottleneckreport-$DateSelect.txt")
                            {
                                Invoke-Item "$LogPath\bottleneckreport-$DateSelect.txt"
                            }
                            Else
                            {
                                "Log file $LogPath\bottleneckreport-$DateSelect.txt does not exist"
                            }
                            Continue
                        }
                        2
                        {
                            If (Test-Path "$LogPath\runtime-$DateSelect.txt")
                            {
                                Invoke-Item "$LogPath\runtime-$DateSelect.txt"
                            }
                            Else
                            {
                                "Log file $LogPath\runtime-$DateSelect.txt does not exist"
                            }
                            Continue
                        }
                        3
                        {
                            If (Test-Path "$LogPath\manual-$DateSelect.txt")
                            {
                                Invoke-Item "$LogPath\manual-$DateSelect.txt"
                            }
                            Else
                            {
                                "Log file $LogPath\manual-$DateSelect.txt does not exist"
                            }
                            Continue
                        }
                        4
                        {
                            If (Test-Path "$LogPath\bottleneckreport-$DateSelect.txt")
                            {
                                Invoke-Item "$LogPath\bottleneckreport-$DateSelect.txt"
                            }
                            Else
                            {
                                "Log file $LogPath\bottleneckreport-$DateSelect.txt does not exist"
                            }
                            If (Test-Path "$LogPath\runtime-$DateSelect.txt")
                            {
                                Invoke-Item "$LogPath\runtime-$DateSelect.txt"
                            }
                            Else
                            {
                                "Log file $LogPath\runtime-$DateSelect.txt does not exist"
                            }
                            If (Test-Path "$LogPath\manual-$DateSelect.txt")
                            {
                                Invoke-Item "$LogPath\manual-$DateSelect.txt"
                            }
                            Else
                            {
                                "Log file $LogPath\manual-$DateSelect.txt does not exist"
                            }
                            Continue
                        }
                        5
                        {
                            Invoke-Item -LiteralPath "$LogPath"
                            Continue
                        }
                        6
                        {
                            $DateSelect = ([datetime]$DateSelect).AddDays(-1).ToString("yyyy-MM-dd")
                            "Log Date set to $DateSelect"
                            Continue
                        }
                        7
                        {
                            $DateSelect = ([datetime]$DateSelect).AddDays(-7).ToString("yyyy-MM-dd")
                            "Log Date set to $DateSelect"
                            Continue
                        }
                        8
                        {
                            $DateSelect = (Get-Date).ToString('yyyy-MM-dd')
                            "Log Date set to $DateSelect"
                            Continue
                        }
                        B
                        {
                            Write-Host "Returning to main menu"
                            $LMBack = $True
                        }
                        Default
                        {
                            Write-Host "Unrecognized input"
                            Continue
                        }
                    }
                }
                Until ($LMBack)
            }
            # Old Options Menu, WIP
            O
            {
                Do
                {
                    Write-Host "`nOptions Menu"
                    Write-Host ("`n" + ('-' * 130))
                    Write-Host "[1] Verbosity: $VerbosePreference"
                    Write-Host "[2] DelProf Confirmation Level: $DelProfPreference"
                    Write-Host "[B] Return to Main Menu"
                    Write-Host (('-' * 130) + "`n")

                    $OptionsMenu = Read-Host "Options menu"
                    Switch ($OptionsMenu)
                    {
                        1
                        {
                            # Toggle Verbosity
                            If ($VerbosePreference -eq "SilentlyContinue")
                            {
                                $VerbosePreference = "Continue"
                            }
                            Else
                            {
                                $VerbosePreference = "SilentlyContinue"
                            }
                        }
                        2
                        {
                            # Change DelProf Confirmation preference
                            If ($DelProfPreference -eq "Unattended")
                            {
                                $DelProfPreference = "Prompt"
                            }
                            ElseIf ($DelProfPreference -eq "Prompt")
                            {
                                $DelProfPreference = "Confirm"
                            }
                            Else
                            {
                                $DelProfPreference = "Unattended"
                            }
                        }
                        B
                        {
                            "Returning to main menu"
                            $Back = $True
                        }
                        Default
                        {
                            "Unrecognized input"
                        }
                    }
                }
                Until ($Back -eq $True)
            }
            # Restart main loop
            D
            {
                "`nNo further changes will be made to $HostName"
                Write-Host ("`n" + ('-' * 130))
                Start-Sleep -Seconds 1
                $Quit = $False
                $Next = $True
                Break
            }
            # Quit
            Q
            {
                "`nQuitting. No further changes will be made to $HostName"
                Write-Host ("`n" + ('-' * 130))
                Start-Sleep -Seconds 1
                $Quit = $True
                $Next = $True
                Break
            }
            Default
            {
                'Unrecognized input'
            }
        }
    }
    Until ($Next -eq $True)
}
Until ($Quit -eq $True)
Stop-Transcript
