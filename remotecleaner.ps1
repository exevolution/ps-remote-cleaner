#requires -Version 3.0
#requires -RunAsAdministrator
# This PowerShell script is designed to perform regular maintainance on domain computers
# If you encounter any errors, please contact Elliott Berglund x8981
If (!(Get-Module ActiveDirectory))
{
    Import-Module -Name ActiveDirectory -ErrorAction Stop
}

$Runtime0 = Get-Date

# Declare necessary, or maybe unnecessary global vars for functions
$Global:HostName = $Null
$Global:HostEntry = $Null
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

Function GetFreeSpace
{
    # Define the FreeSpace calculator
    $Global:FreeSpace = Get-WmiObject Win32_LogicalDisk -ComputerName $Global:HostName |
    Where-Object { $_.DeviceID -eq "$DriveLetter" } |
    Select-Object @{Name="Computer Name"; Expression={ $_.SystemName } }, @{Name="Drive"; Expression={ $_.Caption } }, @{Name="Free Space (" + $Args[0..$Args.Length] + ")"; Expression={ "$([math]::round($_.FreeSpace / 1GB,2))GB" } } |
    Format-Table -AutoSize |
    Tee-Object -Append -File "$PSScriptRoot\logs\$AdminLogPath\bottleneckreport-$LogDate.txt"

    # Output it
    "`n"
    '*******************************************************'
    $Global:FreeSpace
    '*******************************************************'
    "`n"
    Return
}

Function RunDelProf2
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
    "`n"
    $Global:DelProf = Start-Process -FilePath "$PSScriptRoot\DelProf2\DelProf2.exe" -ArgumentList "/c:$Global:HostName /ed:$ShortUser /ed:Admin* /ed:00* /ed:Default* /ed:Public* $VarAttend" -Wait -PassThru
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

    "{0} | DelProf2 completed in {1:d2}:{2:d2}:{3:d2}`n" -F $Global:HostName,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append
    Return
}

Function ResolveHost
{
    If ($Global:HostEntry -As [IPAddress])
    {
        $Global:HostIP = $Global:HostEntry
        $Global:HostInfo = [System.Net.Dns]::GetHostEntry($Global:HostIP)
        $Global:HostName = $Global:HostInfo.HostName
    }
    Else
    {
        $Global:HostName = $Global:HostEntry.ToUpper()
        $Global:HostInfo = Resolve-DnsName -Name $Global:HostName
        $Global:HostIP = $Global:HostInfo.IPAddress
    }
    Return
}

Function Remove-WithProgress
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="High")]
    Param
    (
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Path
    )
    # Progress Bar counter
    $CurrentFileCount = 0
    $CurrentFolderCount = 0
    
    "`n"
    '--------------------------------------------------'
    "Enumerating $Title, please wait..."
    
    # Start progress bar
    Write-Progress -Id 0 -Activity "Enumerating $Title from $Global:HostName" -PercentComplete 0

    # Start timer
    $T0 = Get-Date

    # Enumerate files, silence errors
    $Files = @(Get-ChildItem -Force -LiteralPath "$Path" -Recurse -ErrorAction SilentlyContinue -Attributes !Directory) | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
    $T1 = Get-Date
    $T2 = New-TimeSpan -Start $T0 -End $T1
    "Operation Completed in {0:d2}:{1:d2}:{2:d2}" -F $T2.Hours,$T2.Minutes,$T2.Seconds

    # Total file count for progress bar
    $FileCount = $Files.Count
    $TotalSize = ($Files | Measure-Object -Sum Length).Sum
    $TotalSize = [math]::Round($TotalSize / 1GB,3)

    # Write detailed info to runtime log
    "`n{0} | {1} {2} enumerated in {3:d2}:{4:d2}:{5:d2}" -F $Global:HostName,$FileCount,$Title,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append

    "`n"
    "Removing $FileCount $Title... $TotalSize`GB."
    $T0 = Get-Date
    
    $Error.Clear()
    ForEach ($File in $Files)
    {
        $CurrentFileCount++
        $FullFileName = $File.FullName
        $Percentage = [math]::Round(($CurrentFileCount / $FileCount) * 100)
        Write-Progress -Id 0 -Activity "Removing $Title" -CurrentOperation "File: $FullFileName" -PercentComplete $Percentage -Status "Progress: $CurrentFileCount of $FileCount, $Percentage%"
        Write-Verbose $FullFileName
        $File | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Write-Progress -Id 0 -Completed -Activity 'Done'

    # Show error count
    If ($Error.Count -gt 0)
    {
        "{0} errors while removing files in {1}." -f $Error.Count, $Title
        "Check error-$Global:HostName-$LogDate.txt for details."
        $Error | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\error-$Global:HostName-$LogDate.txt" -Append

        # Enumerate remaining files
        $RemainingFiles = @(Get-ChildItem -Force -Path "$Path" -Recurse -ErrorAction SilentlyContinue -Attributes !Directory).Count
        If ($RemainingFiles -gt 0)
        {
            "{0} files were not deleted" -f $RemainingFiles
        }

    }
    

    # Attempt to remove the empty subdirectories after, will not occur if locked files still exist
    $Folders = @(Get-ChildItem -Force -Path "$Path" -Recurse -Attributes Directory) | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
    $EmptyFolders = $Folders | Where-Object {$_.GetFiles().Count -eq 0}

    # Enumerate empty folders
    $EmptyCount = $EmptyFolders.Count

    "Removing $EmptyCount empty folders"
    $Title = 'Removing Empty Directories'

    ForEach ($EmptyFolder in $EmptyFolders)
    {
        # Increment Folder Counter
        $CurrentFolderCount++

        # Full Folder Name
        $FullFolderName = $EmptyFolder.FullName

        $Percentage = [math]::Round(($CurrentFolderCount / $EmptyCount) * 100)
        
        Write-Progress -Id 1 -Activity "Removing $Title" -CurrentOperation "Removing Empty Directory: $FullFolderName" -PercentComplete "$Percentage" -Status "Progress: $CurrentFolderCount of $EmptyCount, $Percentage%"
        Write-Verbose $FullFolderName
        $EmptyFolder | Remove-Item -Force -ErrorAction SilentlyContinue -Recurse
    }
    Write-Progress -Id 1 -Completed -Activity 'Done'
    $T1 = Get-Date
    $T2 = New-TimeSpan -Start $T0 -End $T1
    "Operation Completed in {0:d2}:{1:d2}:{2:d2}" -F $T2.Hours,$T2.Minutes,$T2.Seconds

    # Write detailed info to runtime log
    "{0} | {1} {2} deleted in {3:d2}:{4:d2}:{5:d2} | {6}GB`n" -F $Global:HostName,$FileCount,$Title,$T2.Hours,$T2.Minutes,$T2.Seconds,$TotalSize | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append
    '--------------------------------------------------'
    Return
}

Function Test-Credential 
{ 
    [CmdletBinding()] 
    [OutputType([Bool])] 
    Param 
    ( 
        # Credential, Type PSCredential, The PSCredential Object to test. 
        [Parameter(Position = 0, 
                   ValueFromPipeLine = $true)] 
        [PSCredential] 
        $AdminCreds, 
 
        # Domain, Type String, The domain name to test PSCredetianl Object against. 
        [Parameter(Position = 1)] 
        [String] 
        $Domain = $env:USERDOMAIN 
    ) 
 
    Begin 
    { 
        if (-not($PSBoundParameters.ContainsValue($AdminCreds))) 
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
            Sleep 3
            Exit
        }
    If (Test-Credential $AdminCreds)
        {
            $ValidAdmin = $True
        }
    Else
        {
            "Invalid username or password"
            Sleep 3
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
$LogDate = Get-Date -Format 'yyyyMMdd'

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
"`n"

# Collect Computer Info
Do
{

# If computer name is a blank string, loop
Do
{
    $Global:HostEntry = Read-Host -Prompt 'Enter the computer name or IP address'
}
While ($Global:HostEntry -eq '')

ResolveHost

"`n"
'-------------------------------------------------------'
"Computer Name: $Global:HostName"
"IP Address: $Global:HostIP"
"Admin Username: $LocalAdmin"
'-------------------------------------------------------'
"`n"

$VerifyInfo = Read-Host 'Is this correct? (Y/N)'
}
until ($VerifyInfo -eq 'Y')

# Collect info from computer, get active user
"`n"
'-------------------------------------------------------'
"Collecting information from $Global:HostName, please wait..."
'-------------------------------------------------------'
"`n"
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
$Global:DomainUser = Get-WmiObject Win32_ComputerSystem -Computer $Global:HostName
$Global:DomainUser = $Global:DomainUser.UserName

# If no user is logged in, prompt for the assigned user
If ($Global:DomainUser -eq $Null)
{
    $ProfileCount = 0
    # Store all non system profiles
    $AllProfiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $Global:HostName | Where-Object {($_.LocalPath -notmatch "00") -and ($_.LocalPath -notmatch "Admin") -and ($_.LocalPath -notmatch "Default") -and ($_.LocalPath -notmatch "Public") -and ($_.LocalPath -notmatch "LocalService") -and ($_.LocalPath -notmatch "NetworkService") -and ($_.LocalPath -notmatch "systemprofile")}

    # Store all profile SIDs in an array    
    $SIDs = @($AllProfiles | Select-Object -ExpandProperty sid)

    # Create blank hash table
    $UserHashTable = $Null
    $UserHashTable = @{}

    # Use the SIDs to get the usernames from AD
    ForEach ($SID in $SIDs)
    {
        $AccountName = (Get-ADUser -Filter {SID -eq $SID} | Select-Object SamAccountName).SamAccountName
        If ($AccountName -eq $Null)
        {
            "`n$SID does not exist in Active Directory, skipping"
            Continue
        }
        $ProfileCount++
        $UserHashTable.Add($ProfileCount, $AccountName)
    }

    If ($ProfileCount -eq 0)
    {
        "No valid user profiles on $Global:HostName. Please run again on a different computer"
        Break
    }

    # Sort the hash table
    $UserHashTable = $UserHashTable.GetEnumerator() | Sort-Object Name

    # Output it, ask user to select a menu option
    If ($ProfileCount -ge 2)
    {
        Do
        {
        # Display menu
        "`nProfile Listing"
        $UserHashTable.GetEnumerator()

        # Null important variables for loop
        $ok = $Null
        $SelectedUser = $Null

        # Ask user for numeric input, 
        $SelectedUser = Read-Host "`nPlease select the assigned user"
        $SelectedUser = $SelectedUser -as [int32]
        If ($SelectedUser -eq $Null -or $SelectedUser -eq "")
            {
                "`nYou must enter a numeric value"
                Continue
            }
        # Subtract 1 from input for 0 indexed array
        $SelectedUser = $SelectedUser - 1
        If ($SelectedUser -gt ($ProfileCount - 1))
            {
                "`nYou have entered a value out of range, please choose a correct value`n"
                Continue
            }
        $ok = $True
        }
        Until ($ok)

        $ShortUser = ($UserHashTable[$SelectedUser]).Value
        "You have selected $ShortUser"
    }
    Else
    {
        "`nOnly 1 profile was detected, selecting {0}`n" -F $UserHashTable[0].Value
        $ShortUser = $UserHashTable[0].Value
    }

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
    Sleep 10
    Exit
}

# Per-admin log path setup
$AdminLogPath = ($LocalAdmin).Replace("$Global:Domain", '')

# Check for per-user log directory, create if it does not exist
If (Test-Path "$PSScriptRoot\logs\$AdminLogPath\")
{
    'Log path exists, continuing...'
}
Else
{
    "Created log directory"
    New-Item -ItemType Directory -Path "$PSScriptRoot\logs\$AdminLogPath\"
}

# Grab local path from active profile
$ProfilePath = $ActiveProfile.LocalPath
# Convert 
$ProfileShare = $ProfilePath -replace ':', '$'
$DriveLetter = $ProfilePath.Substring(0,2)

"Active user on $Global:HostName is $ShortUser"
"Administrative share of active user is \\$Global:HostName\$ProfileShare"
"Drive letter - $DriveLetter"

"Checking Free Space on $Global:HostName, drive $DriveLetter"

$WorkingDirectory = "\\$Global:HostName\$ProfileShare"

# Calculate free space before beginning
GetFreeSpace Start

# Cleanup temp files and IE cache
do
{
    'Choose one of the following options to continue'
    '-------------------------------------------------------'
    '[1] Automated Cleanup'
    '[2] Automatic Stale Profile Cleanup'
    '[3] Interactive Stale Profile Cleanup'
    '[4] Attempt Printer Fix (Not Working)'
    '[I] More Information'
    '[D] Do Nothing, Move To Next Computer'
    '[Q] Quit'
    '-------------------------------------------------------'
    $Cleanup = Read-Host 'Choice'

    Switch ($Cleanup)
    {
        1
            {
                # Disable Prompts
                $ConfirmPreference = "High"

                # Start cleanup timer
                $TotalTime0 = Get-Date

                # Working Directory for relative paths
                $Path0 = "$WorkingDirectory"

                # Give the user a chance to cancel before changes are made
                Write-Warning 'This makes permanent changes to the system. Press Ctrl+C now to cancel'
                Sleep 5

                # WINDOWS TEMP
                # Progress Bar Title
                $Title = 'Windows Temp Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Temp'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # IE CACHE
                # Progress Bar Title
                $Title = 'Internet Exploder Cache Files (Windows 7)'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Microsoft\Windows\Temporary Internet Files'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # IE COOKIES
                # Progress Bar Title
                $Title = 'Internet Exploder Cookies (Windows 7)'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Roaming\Microsoft\Windows\Cookies'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # IE CACHE
                # Progress Bar Title
                $Title = 'Internet Exploder Cache Files (Windows 8.1)'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Microsoft\Windows\INetCache'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # IE COOKIES
                # Progress Bar Title
                $Title = 'Internet Exploder Cookies (Windows 8.1)'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Microsoft\Windows\INetCookies'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # CHROME CACHE
                # Progress Bar Title
                $Title = 'Google Chrome Cache Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Google\Chrome\User Data\Default\Cache'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # CHROME MEDIA CACHE
                # Progress Bar Title
                $Title = 'Google Chrome Media Cache Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Google\Chrome\User Data\Default\Media Cache'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # GOOGLE CHROME UPDATES
                # Progress Bar Title
                $Title = 'Google Chrome Update Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Google\Update'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # FIVE9 LOGS
                # Progress Bar Title
                $Title = 'Five9 Log Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Roaming\Five9\Logs'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }
                
                # FIVE9 INSTALLS
                # Progress Bar Title
                $Title = 'Old Five9 Installations'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Roaming\Five9.*'
                $Path = "$Path0\$Path1"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # C: DRIVE RECYCLE BIN
                # Progress Bar Title
                $Title = 'Recycle Bin Files on C: Drive'
                $Path = "\\$Global:Hostname\c$\`$Recycle.Bin"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # D: DRIVE RECYCLE BIN
                # Progress Bar Title
                $Title = 'Recycle Bin Files on D: Drive'
                $Path = "\\$Global:Hostname\d$\`$Recycle.Bin"
                If (Test-Path "$Path")
                {
                    # Call deletion with progress bar
                    Remove-WithProgress -Path "$Path"
                }

                # DELPROF2
                # Run DelProf2
                "`n"
                '--------------------------------------------------'
                RunDelProf2 Unattended
                '--------------------------------------------------'

                $TotalTime1 = Get-Date
                $TotalTime2 = New-TimeSpan -Start $TotalTime0 -End $TotalTime1
                "`n"
                "Automated Cleanup Completed in {0:d2}:{1:d2}:{2:d2}" -F $TotalTime2.Hours,$TotalTime2.Minutes,$TotalTime2.Seconds

                $ManualCleanup = $Null
                $ManualCleanup = Get-WmiObject Win32_LogicalDisk -ComputerName $Global:HostName | Where-Object { $_.DeviceID -eq "$DriveLetter" -and $_.FreeSpace -lt 1073741824 }
                If ($ManualCleanup -ne $Null)
                {
                "Additional Cleanup needed on $Global:HostName - User ID: $ShortUser | Less than 1GB free after automated cleanup" | Tee-Object -File "$PSScriptRoot\logs\$AdminLogPath\manual-$LogDate.txt" -Append
                }

                $Cleanup = 'D'
            }
        2
            {
                RunDelProf2 Unattended
                GetFreeSpace Unattended DelProf2
            }
        3
            {
                RunDelProf2 Prompt
                GetFreeSpace Interactive DelProf2
            }
        4
            {
                # Log user off machine
                $ShortUser
                $UserSession = ((quser /server:$Global:HostName | ? { $_ -match $ShortUser }) -split ' +')[2]
                logoff $UserSession /server:$Global:HostName 
                
                # Hook WinRM service on remote machine to allow PSSession
                $RemoteWinRM = Get-Service -Name WinRM

                # Start WinRM service on remote machine
                If ($RemoteWinRM.Status -ne "Running")
                {
                    $RemoteWinRM.Start()
                }
                # Create a remote PSSession for printer work
                $RemoteSession = New-PSSession -ComputerName $Global:HostName -Credential $AdminCreds
                Invoke-Command -Session $RemoteSession -ScriptBlock {
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

                # Hook remote print spooler
                $RemoteSpooler = Get-Service -ComputerName $Global:HostName -Name Spooler

                # Restart Print Spooler
                $RemoteSpooler.Stop()
                $RemoteSpooler.Start()

                # Check spooler status
                #If ($RemoteSpooler.Status -ne 'Stopped')
                #{
                #    # Stop spooler if it is running
                #    "Stopping Print Spooler on $Global:HostName"
                #    $RemoteSpooler.Stop()
                #    $RemoteSpooler.WaitForStatus('Stopped')
                #}

                $RemoteWinRM.Stop()
            }
        I
            {
                '-------------------------------------------------------'
                '[1] Automated Cleanup - Removes Windows Temp, IE Cache, Chrome Cache, Five9 logs, Five9 old installs, and stale Windows profiles'
                '[2] Automatic Stale Profile Cleanup - Removes stale Windows profiles without confirmation'
                '[3] Interactive Stale Profile Cleanup - Removes stale Windows profiles with confirmation'
                '[I] More Information - This help page'
                '[D] Do Nothing, Move To Next Computer - Makes no changes to the current system and asks for a new machine name'
                '[Q] Quit - Quit the script completely without making changes'
                '-------------------------------------------------------'
            }
        D
            {
                "`n"
                "No further changes will be made to $Global:HostName"
            }
        Q
            {
                "`n"
                "Quit. No further changes will be made to $Global:HostName"
                GetFreeSpace Finish
                Exit
            }
        Default
            {
                'Unrecognized input'
            }
    }
}
until ($Cleanup -eq "D" -or $Cleanup -eq "Q")

GetFreeSpace Finish

# Clean all variables created this session to prevent issues after loop
$SysVars = Get-Variable | Select-Object -ExpandProperty Name
$SysVars += 'sysvars'
Get-Variable | Where-Object {$SysVars -notcontains $_.Name} | ForEach {Remove-Variable $_}

'-------------------------------------------------------'
'[R] Run again on another computer'
'[Q] Quit'
'-------------------------------------------------------'
$Rerun = Read-Host 'Choice'
}
until ($Rerun -eq 'Q')

# Elapsed Time, log to file
$Runtime1 = Get-Date
$Runtime2 = New-TimeSpan -Start $Runtime0 -End $Runtime1

"Elapsed Time: {0:d2}:{1:d2}:{2:d2}" -F $Runtime2.Hours,$Runtime2.Minutes,$Runtime2.Seconds | Tee-Object "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append
