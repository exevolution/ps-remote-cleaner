# requires -Version 3.0
# Version 1.4.0.4
# This PowerShell script is designed to perform regular maintainance on domain computers
# If you encounter any errors, please contact Elliott Berglund x8981
# Timer Start
$StopWatch1 = [System.Diagnostics.Stopwatch]::StartNew()

$VerbosePreference = "SilentlyContinue"
$DelProfPreference = "Unattended"
$DNSNameLengthLimit = 15

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



# Declare necessary, or maybe unnecessary global vars for functions
$Global:HostName = $Null
$Global:HostIP = $Null
$Global:HostInfo = $Null
$Global:DelProf = $Null

# Set buffer and window size
$PSHost = Get-Host
$PSWindow = $PSHost.UI.RawUI
$NewSize = $PSWindow.BufferSize
$NewSize.Height = 3000
$NewSize.Width = 150
$PSWindow.BufferSize = $NewSize

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
    # Define the FreeSpace calculator
    $Global:FreeSpace = Get-WmiObject Win32_LogicalDisk -ComputerName $Global:HostName |
    Where-Object { $_.DeviceID -eq "$DriveLetter" } |
    Select-Object @{Name="Computer Name"; Expression={ $_.SystemName } }, @{Name="Drive"; Expression={ $_.Caption } }, @{Name="Free Space (" + $Args[0..$Args.Length] + ")"; Expression={ "$([math]::Round($_.FreeSpace / 1GB,2))GB" } } |
    Format-List

    Return $Global:FreeSpace
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
    $T0 = Get-Date
    'Deleting Stale User Profiles With DelProf2.'
    'Please wait... This may take several minutes.'
    ''
    $Global:DelProf = Start-Process -FilePath "$DelProfPath\DelProf2.exe" -ArgumentList "/c:$Global:HostName /ed:$ShortUser`* /ed:Admin* /ed:00* /ed:Default* /ed:Public* /ed:MsDts* $VarAttend /ntuserini" -Wait -PassThru
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
    $T1 = Get-Date
    $T2 = New-TimeSpan -Start $T0 -End $T1
    "Operation Completed in {0:d2}:{1:d2}:{2:d2}" -F $T2.Hours,$T2.Minutes,$T2.Seconds

    "{0} | DelProf2 completed in {1:d2}:{2:d2}:{3:d2}" -F $Global:HostName,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$LogPath\runtime-$LogDate.txt" -Append
    ''
    Return
}

Function Resolve-Host
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Medium")]

    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$HostName
    )
    Begin
    {
    }

    Process
    {
        If ($HostName -As [IPAddress])
        {
            $HostIP = $HostName
            $HostInfo = [System.Net.Dns]::GetHostEntry($HostIP)
            $HostName = $HostInfo.HostName
        }
        Else
        {
            $HostName = $HostName.ToUpper()
            $HostIP = @([System.Net.Dns]::GetHostAddresses($HostName).IPAddressToString)[0]
        }

    }

    End
    {
        $Global:HostName = $HostName
        $Global:HostIP = $HostIP
        Return $HostName,$HostIP | Out-Null
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
        
    }

    Process
    {
        # Progress Bar counter
        $CurrentFileCount = 0
        $CurrentFolderCount = 0
    
        ''
        '--------------------------------------------------'
        "Enumerating $Title, please wait..."
    
        # Start progress bar
        Write-Progress -Id 0 -Activity "Enumerating $Title from $Global:HostName" -PercentComplete 0

        # Timer Start
        $T0 = Get-Date

        # Enumerate files, silence errors
        $Files = @(Get-ChildItem -Force -LiteralPath "$Path" -Recurse -ErrorAction SilentlyContinue -Attributes !Directory) | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
        # Timer Stop
        $T1 = Get-Date
        $T2 = New-TimeSpan -Start $T0 -End $T1
        "Operation Completed in {0:d2}:{1:d2}:{2:d2}" -F $T2.Hours,$T2.Minutes,$T2.Seconds

        # Total file count for progress bar
        $FileCount = ($Files | Measure-Object).Count
        $TotalSize = ($Files | Measure-Object -Sum Length).Sum
        $TotalSize = [math]::Round($TotalSize / 1GB,3)

        # Write detailed info to runtime log
        ''
        "{0} | {1} {2} enumerated in {3:d2}:{4:d2}:{5:d2}" -F $Global:HostName,$FileCount,$Title,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$LogPath\runtime-$LogDate.txt" -Append

        ''
        "Removing $FileCount $Title... $TotalSize`GB."

        # Timer Start
        $T0 = Get-Date
    
        $Error.Clear()
        ForEach ($File in $Files)
        {
            $CurrentFileCount++
            $FullFileName = $File.FullName
            $Percentage = [math]::Round(($CurrentFileCount / $FileCount) * 100)
            Write-Progress -Id 0 -Activity "Removing $Title" -CurrentOperation "File: $FullFileName" -PercentComplete $Percentage -Status "Progress: $CurrentFileCount of $FileCount, $Percentage%"
            Write-Verbose "Removing file $FullFileName"
            $File | Remove-Item -Force -ErrorAction SilentlyContinue
        }
        Write-Progress -Id 0 -Completed -Activity 'Done'

        # Show error count
        If (($Error | Measure-Object).Count -gt 0)
        {
            "{0} errors while removing files in {1}." -F ($Error | Measure-Object).Count, $Title
            "Check error-$Global:HostName-$LogDate.txt for details."
            $Error | Out-File -File "$LogPath\errors\error-$Global:HostName-$LogDate.txt" -Append

            # Enumerate remaining files
            $RemainingFiles = @(Get-ChildItem -Force -Path "$Path" -Recurse -ErrorAction SilentlyContinue -Attributes !Directory).Count
            If ($RemainingFiles -gt 0)
            {
                "{0} files were not deleted" -f $RemainingFiles
            }

        }
        #Timer Stop
        $T1 = Get-Date
        $T2 = New-TimeSpan -Start $T0 -End $T1
        "{0} {1} deleted in {2:d2}:{3:d2}:{4:d2}" -F $FileCount,$Title,$T2.Hours,$T2.Minutes,$T2.Seconds
        ''

        # Timer Start
        $T0 = Get-Date

        # Enumerate folders with 0 files
        $EmptyFolders = @(Get-ChildItem -Force -Path "$Path" -Recurse -Attributes Directory -ErrorAction SilentlyContinue) | Where-Object {($_.GetFiles()).Count -eq 0} | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
    
        # How many empty folders for progress bars
        $EmptyCount = ($EmptyFolders | Measure-Object).Count

        If ($EmptyCount -gt 0)
        {
            "Removing $EmptyCount empty folders"
            $Title = 'Removing Empty Directories'

            ForEach ($EmptyFolder in $EmptyFolders)
            {
                # Increment Folder Counter
                $CurrentFolderCount++

                # Full Folder Name
                $FullFolderName = $EmptyFolder.FullName

                $Percentage = [math]::Round(($CurrentFolderCount / $EmptyCount) * 100)
        
                If ((($EmptyFolder.GetFiles()).Count + ($EmptyFolder.GetDirectories()).Count) -ne 0)
                {
                    Write-Verbose "$FullFolderName not empty, skipping..."
                    Continue
                }
                Write-Progress -Id 1 -Activity "Removing $Title" -CurrentOperation "Removing Empty Directory: $FullFolderName" -PercentComplete "$Percentage" -Status "Progress: $CurrentFolderCount of $EmptyCount, $Percentage%"
                Write-Verbose "Removing folder $FullFolderName"
                $EmptyFolder | Remove-Item -Force -ErrorAction SilentlyContinue
            }
            Write-Progress -Id 1 -Completed -Activity 'Done'
        }
    }

    End
    {    
        $T1 = Get-Date
        $T2 = New-TimeSpan -Start $T0 -End $T1
        "Operation Completed in {0:d2}:{1:d2}:{2:d2}" -F $T2.Hours,$T2.Minutes,$T2.Seconds

        # Write detailed info to runtime log
        "{0} | {1} empty folders deleted in {2:d2}:{3:d2}:{4:d2}" -F $Global:HostName,$EmptyCount,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$LogPath\runtime-$LogDate.txt" -Append
        ''
        '--------------------------------------------------'
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
        [Parameter(Position = 0, ValueFromPipeLine = $true)] 
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

# Get Local Username
$LocalAdmin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Validate Credentials for later remote PSSession
Do
{
    $AdminCreds = $Null
    $ValidAdmin = $Null
    $AdminCreds = Get-Credential -Credential $LocalAdmin
    If ($AdminCreds -eq $Null)
        {
            "Cancelling"
            "Please login with valid credentials to continue"
            Start-Sleep -Seconds 3
            Exit
        }
    ElseIf (Test-Credential $AdminCreds)
        {
            $ValidAdmin = $True
        }
    Else
        {
            "Invalid username or password"
            Start-Sleep -Seconds 3
        }
}
Until ($ValidAdmin -eq $True)

# Check that user is Help desk admin or higher
#$AdminADObject = $Null
#$AdminMemberships = $Null
#
#$LocalAdmin = $AdminCreds.UserName.Split("\")[1]
#$AdminADObject = Get-ADUser -Filter {SamAccountName -eq $LocalAdmin}
#$AdminMemberships = Get-ADPrincipalGroupMembership $LocalAdmin | Select-Object Name | Sort-Object Name

"Credentials validated, continuing"

# Begin main program
Do
{
# Get current date for logs
$LogDate = (Get-Date).ToString('yyyy-MM-dd')
$DateSelect = $LogDate

Clear-Host
'                  ▄███████▄    ▄████████ ███▄▄▄▄   ███▄▄▄▄   ▄██   ▄     ▄▄▄▄███▄▄▄▄      ▄████████  ▄████████
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
''
'This PowerShell script is designed to perform regular maintainance on domain computers'
'If you encounter any errors, please contact Elliott Berglund x8981'
''

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
    Resolve-Host -HostName $HostEntry
}
Until ($HostIP -as [IPAddress])


''
'-------------------------------------------------------'
"Computer Name: $HostName"
"IP Address: $HostIP"
"Admin Username: $LocalAdmin"
'-------------------------------------------------------'
''

$VerifyHost = Read-Host 'Is this correct? (Y/N)'
}
until ($VerifyHost -eq 'Y')

# Collect info from computer, get active user
''
'-------------------------------------------------------'
"Collecting information from $Global:HostName, please wait..."
'-------------------------------------------------------'
''

If (Test-Path  "\\$Global:HostName\Admin`$\*")
{
    "Admin rights confirmed on $Global:HostName"
}
Else
{
    Write-Warning 'Admin rights not detected on remote machine.'
    $ReRun = Read-Host '(R)etry or press any other key to quit.'
    Continue
}

$ComputerSys =  Get-WmiObject Win32_ComputerSystem -Computer $Global:HostName

# Detect domain name, remove top level domain, convert to uppercase for future Trim operation
$Global:Domain = $ComputerSys.Domain -replace '.com', '' -replace '.net', '' -replace '.org', ''
$Global:Domain = $Global:Domain + "\"
$Global:Domain = $Global:Domain.ToUpper()

# Get logged in username, including domain name
$Global:DomainUser = $Null
$Global:DomainUser = $ComputerSys.UserName

# If no user is logged in, prompt for the assigned user
If ($Global:DomainUser -eq $Null)
{
    # Create blank array (forced)
    $UserArray = $Null
    $UserArray = @()

    # Store all non system profiles
    $AllProfiles = $Null
    $AllProfiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $Global:HostName | Where-Object {($_.LocalPath -notmatch "00") -and ($_.LocalPath -notmatch "Admin") -and ($_.LocalPath -notmatch "Default") -and ($_.LocalPath -notmatch "Public") -and ($_.LocalPath -notmatch "LocalService") -and ($_.LocalPath -notmatch "NetworkService") -and ($_.LocalPath -notmatch "systemprofile") -and ($_.LocalPath -notmatch "MsDts")} | Sort-Object LastUseTime -Descending

    ForEach ($Profile in $AllProfiles)
    {
        $AccountName = $Null
        $SID = ($Profile | Select-Object -ExpandProperty sid)
        $UserFolder = $Profile.LocalPath.Split("\")[-1]
        $AccountName = (Get-ADUser -Filter {SID -eq $SID} | Select-Object SamAccountName).SamAccountName
        If ($AccountName -eq $Null)
        {
            "Folder: '$UserFolder'"
            "SID: '$SID'"
            "Account does not exist in Active Directory. Skipping"
            Continue
        }
        $UserArray += "$AccountName"
    }

    If (($UserArray | Measure-Object).Count -eq 0) {
        "No valid user profiles on $Global:HostName. Please run again on a different computer"
        Break
    }
    # Output it, ask user to select a menu option
    ElseIf (($UserArray | Measure-Object).Count -eq 1)
    {
        ''
        "Only 1 profile was detected, selecting {0}" -F $UserArray[0]
        $SelectedUser = 0
    }
    Else
    {
        $Ok = $Null
        Do
        {
            # Null important variables for loop
            $SelectedUser = $Null

            # Display menu
            ''
            "Profile Listing (Most recently accessed on top)"
            # Sort the hash table and output it
            
            $Number = 0
            ForEach ($User in $UserArray)
            {
                $Number++
                Write-Host "$Number`. $User"
            }

            # Ask user for numeric input
            ''
            $SelectedUser = Read-Host "Please select the assigned user"
            $SelectedUser = $SelectedUser -as [int32]
            If ($SelectedUser -eq $Null -or $SelectedUser -eq "")
            {
                ''
                "You must enter a numeric value"
                Continue
            }
            # Subtract 1 from input for 0 indexed array
            $SelectedUser = $SelectedUser - 1
            If ($SelectedUser -gt (($UserArray | Measure-Object).Count - 1))
            {
                ''
                "You have entered a value out of range, please choose a correct value"
                ''
                Continue
            }
            $ok = $True
        }
        Until ($ok)

    }
    $ShortUser = $UserArray[$SelectedUser]
    "Selected: $ShortUser"
    ''

    # Assume, based on entered information, the active profile
    $ActiveProfile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:HostName | Where-Object {$_.LocalPath -Match "$ShortUser"}
}
Else
{
    $ShortUser = ($Global:DomainUser).Replace("$Global:Domain", '')
        
    # Get the most recently used active profile, store local path as administrative share in variable
    $ActiveProfile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:HostName | Where-Object {$_.LocalPath -Match "$ShortUser"}
}

# If profile status Bit Field includes 8 (corrupt profile), quit.
$Corrupt = 8
$ProfileStatus = $ActiveProfile.Status

If (($Corrupt -band $ProfileStatus) -eq $Corrupt)
{
    Write-Warning "PROFILE CORRUPT! User profile rebuild necessary. Quitting."
    Start-Sleep -Seconds 10
    Exit
}

# Per-admin log path setup
$LogRoot = ($LocalAdmin).Replace("$Global:Domain", '')

# Check for per-user log directory, create if it does not exist
If (! (Test-Path "$PSScriptRoot\Logs\$LogRoot"))
{
    "Created log directory"
    New-Item -ItemType Directory -Path "$PSScriptRoot\Logs\$LogRoot"
    $LogPath = Join-Path -Path "$PSScriptRoot" -ChildPath "Logs\$LogRoot"
}
Else
{
    $LogPath = Join-Path -Path "$PSScriptRoot" -ChildPath "Logs\$LogRoot"
}

If (! (Test-Path "$PSScriptRoot\Logs\$LogRoot\errors"))
{
    "Created log directory"
    New-Item -ItemType Directory -Path "$PSScriptRoot\Logs\$LogRoot\errors"
    $ErrorLogPath = Join-Path -Path "$PSScriptRoot" -ChildPath "Logs\$LogRoot\errors"
}
Else
{
    $ErrorLogPath = Join-Path -Path "$PSScriptRoot" -ChildPath "Logs\$LogRoot\errors"
}

# Log pruning
$LogLimit = (Get-Date).AddDays(-14)
Get-ChildItem -Path $LogPath -Recurse -Force -Attributes !Directory | Where-Object { $_.CreationTime -lt $LogLimit } | Remove-Item -Force

# Grab local path from active profile
$ProfilePath = $ActiveProfile.LocalPath

# Convert to UNC compatible
$ProfileShare = $ProfilePath -replace ':', '$'
$DriveLetter = $ProfilePath.Substring(0,2)

$Path0 = Join-Path -Path "\\$Global:HostName" -ChildPath "$ProfileShare"

# Calculate free space before beginning
''
"Checking Free Space on $Global:HostName, drive $DriveLetter"
''
'-------------------------------------------------------'
Get-FreeSpace Start | Tee-Object -FilePath "$LogPath\bottleneckreport-$LogDate.txt" -Append
'-------------------------------------------------------'

# Cleanup temp files and IE cache
Do
{
    ''
    "Domain: {0}" -F $ComputerSys.Domain
    "Host: {0}" -F $Global:HostName
    "Username: {0}" -F $ShortUser
    "UNC Path: {0}" -F $Path0
    "Log Path: {0}\" -F $LogPath
    ''
    'Choose one of the following options to continue'
    '-------------------------------------------------------'
    '[1] Automated Cleanup'
    "[2] Stale Profile Cleanup ($DelProfPreference)"
    "[3] Logoff $ShortUser"
    "[E] Explore Files on $Global:HostName"
    "[L] Open Logs"
    '[P] Attempt Printer Fix (Not Working)'
    '[O] Options Menu'
    '[D] Do Nothing, Move To Next Computer'
    '[Q] Quit'
    '-------------------------------------------------------'
    $MenuOption = Read-Host 'Choice'

    Switch ($MenuOption)
    {
        1
        {
            # Start cleanup timer
            $StopWatch2 = [System.Diagnostics.Stopwatch]::StartNew()

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
            $Path = Join-Path -Path "\\$Global:Hostname" -ChildPath "c$" | Join-Path -ChildPath "Temp"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Root Temp Files'
            }

            # WINDOWS DIRECTORY TEMP
            $Path = Join-Path -Path "\\$Global:Hostname" -ChildPath "c$" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Temp"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Windows Temp Files'
            }

            # PROPATCHES
            $Path = Join-Path -Path "\\$Global:Hostname" -ChildPath "c$" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "ProPatches" | Join-Path -ChildPath "Patches"
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

            <#
            # MSO CACHE ON C:
            $Path = Join-Path -Path "\\$Global:Hostname" -ChildPath "c$" | Join-Path -ChildPath "MSOCache"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Root Microsoft Office Cache'
            }
            #>

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
            $Path = Join-Path -Path "\\$Global:Hostname" -ChildPath "c$" | Join-Path -ChildPath "`$Recycle.Bin"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Recycle Bin Files on drive C:'
            }

            # D: DRIVE RECYCLE BIN
            $Path = Join-Path -Path "\\$Global:Hostname" -ChildPath "d$" | Join-Path -ChildPath "`$Recycle.Bin"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Recycle Bin Files on drive D:'
            }

            # DELPROF2
            ''
            '--------------------------------------------------'
            Run-DelProf2 Unattended
            '--------------------------------------------------'

            ''
            "Automated Cleanup Completed in {0:d2}:{1:d2}:{2:d2}" -F $StopWatch2.Elapsed.Hours,$StopWatch2.Elapsed.Minutes,$StopWatch2.Elapsed.Seconds

            If ($ManualCleanup)
            {
                Remove-Variable ManualCleanup -Force
            }

            $ManualCleanup = Get-WmiObject Win32_LogicalDisk -ComputerName $Global:HostName | Where-Object { $_.DeviceID -eq "$DriveLetter" -and $_.FreeSpace -lt 1073741824 }
            If ($ManualCleanup -ne $Null)
            {
            "Additional Cleanup needed on $Global:HostName - User ID: $ShortUser | Less than 1GB free after automated cleanup" | Tee-Object -FilePath "$LogPath\manual-$LogDate.txt" -Append
            }
            Get-FreeSpace Automatic Cleanup | Tee-Object -FilePath "$LogPath\bottleneckreport-$LogDate.txt" -Append

            # Log elapsed time

            "Elapsed Time: {0:d2}:{1:d2}:{2:d2}" -F $StopWatch1.Elapsed.Hours,$StopWatch1.Elapsed.Minutes,$StopWatch1.Elapsed.Seconds | Tee-Object -FilePath "$LogPath\runtime-$LogDate.txt" -Append

            Continue
        }
        2
        {
            # DelProf
            Run-DelProf2 $DelProfPreference
            '*******************************************************'
            Get-FreeSpace $DelProfPreference DelProf2 | Tee-Object -FilePath "$LogPath\bottleneckreport-$LogDate.txt" -Append
            '*******************************************************'
            Continue
        }
        3
        {
            $Confirm = $Null
            $Confirm = Read-Host "Are you sure you want to force $ShortUser to log off $Global:HostName`? (Y/N)"

            If ($Confirm -eq "Y")
            {
                # Log user off machine
                $ShortUser
                &reg delete "\\es-srv-0315\HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC
                &reg add "\\es-srv-0315\HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 1
                $UserSession = ((quser /server:$Global:HostName | Where-Object { $_ -match $ShortUser }) -Split ' +')[2]
                &logoff $UserSession /server:$Global:HostName
                &reg add "\\$Global:HostName\HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 0
            }
            Continue
        }
        E
        {
            &explorer "\\$Global:HostName\$ProfileShare\"
        }
        L
        {
            Do
            {
                ''
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

                $MenuOption = Read-Host "Choice"
                Switch ($MenuOption)
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
                    }
                    6
                    {
                    $DateSelect = ([datetime]$DateSelect).AddDays(-1).ToString("yyyy-MM-dd")
                    "Log Date set to $DateSelect"
                    }
                    7
                    {
                    $DateSelect = ([datetime]$DateSelect).AddDays(-7).ToString("yyyy-MM-dd")
                    "Log Date set to $DateSelect"
                    }
                    8
                    {
                    $DateSelect = (Get-Date).ToString('yyyy-MM-dd')
                    "Log Date set to $DateSelect"
                    }
                    B
                    {
                        "Returning to main menu"
                        Break
                    }
                    Default
                    {
                        "Unrecognized input"
                        $MenuOption = $Null
                    }
                }
            }
            While ($MenuOption -ne "B")
        }
        P
        {
            $Code = Read-Host "Do not use unless you know what you are doing. Enter usage code to continue"
            If ($Code -ne 'eckse4alwayswins')
            {
                Continue
            }

            # Log user off machine
            Set-Location "\\pnmac.com\fileserver\Departments\IT\IT Infrastructure\Help Desk\Bottleneck\PSTools"
            $UserSession = (.\PsLoggedOn.exe \\es-srv-0315).Split('\')[1]
            #logoff $UserSession /server:$Global:HostName 
            
            # Hook remote print spooler
#            $RemoteSpooler = Get-Service -ComputerName $Global:HostName -Name Spooler

            # Stop Spooler
#            $RemoteSpooler.Stop()

            $Server = "\\es-srv-0315"
            $EULA = "/accepteula"
            $Args = ""
            $Process = "powershell.exe"
            $Command = "{Get-WMIObject Win32_Printer | where{$_.Network -eq 'true'} | ForEach{$_.Delete()}}"
            $CommandArgs = "-Command $Command"
            & .\PsExec.exe "\\es-srv-0315", "/accepteula", "powershell.exe", "-Command", "{Get-WMIObject Win32_Printer | where{$_.Network -eq 'true'} | ForEach{$_.Delete()}}"
            & .\PsLoggedon.exe /?

            # Delete Registry Keys
            & reg delete "\\$Global:HostName\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider" /F
            & reg add "\\$Global:HostName\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider" /F
            & reg add "\\$Global:HostName\HKLM\Software\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers" /F

            <#
            # Hook WinRM service on remote machine to allow PSSession
            $RemoteWinRM = Get-Service -Name WinRM

            # Start WinRM service on remote machine
            If ($RemoteWinRM.Status -ne "Running")
            {
                $RemoteWinRM.Start()
            }

            # Create a remote PSSession for printer work
            $RemoteSession = New-PSSession -ComputerName $Global:HostName -Credential $AdminCreds
            Invoke-Command -Session $RemoteSession -ScriptBlock `
            {
                # Hook print spooler in PSSession
                $PSSessionSpooler = Get-Service -Name Spooler

                #Stop Spooler
                $PSSessionSpooler.Stop()

                # Remove required registry entries to allow removal of drivers
                If (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers\")
                {
                    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers\" -Force -Recurse
                }
                If (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\")
                {
                    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\" -Force -Recurse
                }
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\" -Force
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers\" -Force
                    
                # Start Spooler for the next steps
                $PSSessionSpooler.Start()

                # Remove all HP and Konica drivers
                Get-PrinterDriver | Where-Object {$_.Manufacturer -eq "HP" -or $_.Manufacturer -eq "KONICA MINOLTA"} | Remove-PrinterDriver

                # Run Logon Script through PSSession
                "$env:LOGONSERVER\NETLOGON\pnmac-logon.vbs"

            }
            Remove-PSSession $RemoteSession
            #>

            # Restart Print Spooler
            $RemoteSpooler.Start()

            # Stop RemoteWinRM service
            $RemoteWinRM.Stop()
            Continue
        }
        O
        {
            Do
            {
                ''
                'Options Menu'
                '-------------------------------------------------------'
                "[1] Verbosity: $VerbosePreference"
                "[2] DelProf Confirmation Level: $DelProfPreference"
                "[B] Return to Main Menu"
                '-------------------------------------------------------'
                $MenuOption = Read-Host "Choice"
                Switch ($MenuOption)
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
                        Continue
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
                        Continue
                    }
                    B
                    {
                        "Returning to main menu"
                    }
                    Default
                    {
                        "Unrecognized input"
                        $MenuOption = $Null
                    }
                }
            }
            While ($MenuOption -ne "B")
        }
    D
        {
            "No further changes will be made to $Global:HostName"
            Get-FreeSpace Finish | Out-File -FilePath "$LogPath\bottleneckreport-$LogDate.txt" -Append
            Start-Sleep -Seconds 1
        }

    Q
        {
            ''
            "Quitting. No further changes will be made to $Global:HostName"
            Get-FreeSpace Finish | Out-File -FilePath "$LogPath\bottleneckreport-$LogDate.txt" -Append
            Start-Sleep -Seconds 1
        }
    Default
        {
            'Unrecognized input'
        }
    }
}
Until ($MenuOption -eq 'D' -or $MenuOption -eq 'Q')

    If ($MenuOption -eq 'D')
    {
        # Clear VARs and break from loop to quit
        $SysVars = Get-Variable | Select-Object -ExpandProperty Name
        $SysVars += 'sysvars'
        Get-Variable | Where-Object {$SysVars -notcontains $_.Name} | ForEach-Object {Remove-Variable $_}
        Continue
    }
}
While ($MenuOption -ne 'Q')
