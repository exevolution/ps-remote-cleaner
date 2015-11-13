#requires -Version 3.0
#requires -RunAsAdministrator
# This PowerShell script is designed to perform regular maintainance on domain computers
# If you encounter any errors, please contact Elliott Berglund x8981
# Timer Start
$Runtime0 = Get-Date

$VerbosePreference = "SilentlyContinue"
$DelProfPreference = "Unattended"

# Import required module
If (!(Get-Module ActiveDirectory))
{
    Import-Module -Name ActiveDirectory -ErrorAction Stop
}

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

Function Get-FreeSpace
{
    # Define the FreeSpace calculator
    $Global:FreeSpace = Get-WmiObject Win32_LogicalDisk -ComputerName $Global:HostName |
    Where-Object { $_.DeviceID -eq "$DriveLetter" } |
    Select-Object @{Name="Computer Name"; Expression={ $_.SystemName } }, @{Name="Drive"; Expression={ $_.Caption } }, @{Name="Free Space (" + $Args[0..$Args.Length] + ")"; Expression={ "$([math]::round($_.FreeSpace / 1GB,2))GB" } } |
    Format-Table -AutoSize |
    Tee-Object -Append -File "$LogPath\bottleneckreport-$LogDate.txt"

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

    "{0} | DelProf2 completed in {1:d2}:{2:d2}:{3:d2}`n" -F $Global:HostName,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$LogPath\runtime-$LogDate.txt" -Append
    Return
}

Function Resolve-Host
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
    
        "`n"
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
        $FileCount = $Files.Count
        $TotalSize = ($Files | Measure-Object -Sum Length).Sum
        $TotalSize = [math]::Round($TotalSize / 1GB,3)

        # Write detailed info to runtime log
        "`n{0} | {1} {2} enumerated in {3:d2}:{4:d2}:{5:d2}" -F $Global:HostName,$FileCount,$Title,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$LogPath\runtime-$LogDate.txt" -Append

        "`n"
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
        If ($Error.Count -gt 0)
        {
            "{0} errors while removing files in {1}." -f $Error.Count, $Title
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
        "{0} {1} deleted in {2:d2}:{3:d2}:{4:d2}`n" -F $FileCount,$Title,$T2.Hours,$T2.Minutes,$T2.Seconds

        # Timer Start
        $T0 = Get-Date

        # Enumerate folders with 0 files
        $EmptyFolders = @(Get-ChildItem -Force -Path "$Path" -Recurse -Attributes Directory) | Where-Object {($_.GetFiles()).Count -eq 0} | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
    
        # How many empty folders for progress bars
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

    End
    {    
        $T1 = Get-Date
        $T2 = New-TimeSpan -Start $T0 -End $T1
        "Operation Completed in {0:d2}:{1:d2}:{2:d2}" -F $T2.Hours,$T2.Minutes,$T2.Seconds

        # Write detailed info to runtime log
        "{0} | {1} empty folders deleted in {2:d2}:{3:d2}:{4:d2}`n" -F $Global:HostName,$EmptyCount,$T2.Hours,$T2.Minutes,$T2.Seconds | Out-File -File "$LogPath\runtime-$LogDate.txt" -Append
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
            Sleep 3
            Exit
        }
    ElseIf (Test-Credential $AdminCreds)
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

# If computer name is a blank string, loop
Do
{
    $Global:HostEntry = Read-Host -Prompt 'Enter the computer name or IP address'
}
While ($Global:HostEntry -eq '')

Resolve-Host

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
$Global:DomainUser = $Null
$Global:DomainUser = (Get-WmiObject Win32_ComputerSystem -Computer $Global:HostName).UserName

# If no user is logged in, prompt for the assigned user
If ($Global:DomainUser -eq $Null)
{
    # Create blank array (forced)
    $UserArray = $Null
    $UserArray = @()

    # Store all non system profiles
    $AllProfiles = $Null
    $AllProfiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $Global:HostName | Where-Object {($_.LocalPath -notmatch "00") -and ($_.LocalPath -notmatch "Admin") -and ($_.LocalPath -notmatch "Default") -and ($_.LocalPath -notmatch "Public") -and ($_.LocalPath -notmatch "LocalService") -and ($_.LocalPath -notmatch "NetworkService") -and ($_.LocalPath -notmatch "systemprofile")} | Sort-Object LastUseTime -Descending

<#    
    # Store all profile SIDs in an array
    $SIDs = $Null
    $SIDs = @($AllProfiles | Select-Object -ExpandProperty sid)

    # Use the SIDs to get the usernames from AD
#>
    ForEach ($Profile in $AllProfiles)
    {
        $AccountName = $Null
        $SID = ($Profile | Select-Object -ExpandProperty sid)
        $AccountName = (Get-ADUser -Filter {SID -eq $SID} | Select-Object SamAccountName).SamAccountName
        If ($AccountName -eq $Null)
        {
            "`n$SID does not exist in Active Directory, skipping"
            Continue
        }
        $UserArray += "$AccountName"
    }
<#
    ForEach ($SID in $SIDs)
    {
        $AccountName = $Null
        $AccountName = (Get-ADUser -Filter {SID -eq $SID} | Select-Object SamAccountName).SamAccountName
        If ($AccountName -eq $Null)
        {
            "`n$SID does not exist in Active Directory, skipping"
            Continue
        }
        $UserArray += "$AccountName"
    }
#>
    If ($UserArray.Count -eq 0) {
        "No valid user profiles on $Global:HostName. Please run again on a different computer"
        Break
    }
    # Output it, ask user to select a menu option
    ElseIf ($UserArray.Count -eq 1)
    {
        "`nOnly 1 profile was detected, selecting {0}`n" -F $UserArray[0]
        $SelectedUser = 0
    }
    Else
    {
        $ok = $Null
        Do
        {
            # Null important variables for loop
            $SelectedUser = $Null

            # Display menu
            "`nProfile Listing (Most recently accessed on top)"
            # Sort the hash table and output it
            
            $Number = 0
            ForEach ($User in $UserArray)
            {
                $Number++
                Write-Host "$Number`. $User"
            }

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
            If ($SelectedUser -gt ($UserArray.Count - 1))
            {
                "`nYou have entered a value out of range, please choose a correct value`n"
                Continue
            }
            $ok = $True
        }
        Until ($ok)

    }
    $ShortUser = $UserArray[$SelectedUser]
    "Selected: $ShortUser`n"

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
If (Test-Path "$PSScriptRoot\logs\$AdminLogPath")
{
    'Log path exists, continuing...'
}
Else
{
    "Created log directory"
    New-Item -ItemType Directory -Path "$PSScriptRoot\logs\$AdminLogPath"
}
If (Test-Path "$PSScriptRoot\logs\$AdminLogPath\errors")
{
    'Log path exists, continuing...'
}
Else
{
    "Created log directory"
    New-Item -ItemType Directory -Path "$PSScriptRoot\logs\$AdminLogPath\errors"
}
$LogPath = "$PSScriptRoot\logs\$AdminLogPath"
$ErrorLogPath = "$PSScriptRoot\logs\$AdminLogPath\errors"

# Log pruning
$LogLimit = (Get-Date).AddDays(-14)
Get-ChildItem -Path $LogPath -Recurse -Force -Attributes !Directory | Where-Object { $_.CreationTime -lt $LogLimit } | Remove-Item -Force

# Grab local path from active profile
$ProfilePath = $ActiveProfile.LocalPath

# Convert 
$ProfileShare = $ProfilePath -replace ':', '$'
$DriveLetter = $ProfilePath.Substring(0,2)

$Path0 = "\\$Global:HostName\$ProfileShare"

# Calculate free space before beginning
"Checking Free Space on $Global:HostName, drive $DriveLetter`n"
'--------------------------------------------------'
Get-FreeSpace Start
'--------------------------------------------------'

# Cleanup temp files and IE cache
do
{
    "Domain: " + $ComputerSys.Domain
    "Host: $Global:HostName"
    "Username: $ShortUser"
    "UNC Path: \\$Global:HostName\$ProfileShare"
    "Log Path: $LogPath\"
    ''
    'Choose one of the following options to continue'
    '-------------------------------------------------------'
    '[1] Automated Cleanup'
    "[2] Stale Profile Cleanup ($DelProfPreference)"
    '[3] Attempt Printer Fix (Not Working)'
    "[L] Open Logs"
    '[O] Options Menu'
    '[D] Do Nothing, Move To Next Computer'
    '[Q] Quit'
    '-------------------------------------------------------'
    $Cleanup = Read-Host 'Choice'

    Switch ($Cleanup)
    {
        1
        {
            # Start cleanup timer
            $TotalTime0 = Get-Date

            # Give the user a chance to cancel before changes are made
            Write-Warning 'This makes permanent changes to the system. Press Ctrl+C now to cancel'
            Sleep 5

            # WINDOWS TEMP
            $Path = "$Path0\AppData\Local\Temp"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Windows Temp Files'
            }

            # IE CACHE
            $Path = "$Path0\AppData\Local\Microsoft\Windows\Temporary Internet Files"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 7)'
            }

            # IE COOKIES
            $Path = "$Path0\AppData\Roaming\Microsoft\Windows\Cookies"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cookies (Windows 7)'
            }

            # IE CACHE
            $Path = "$Path0\AppData\Local\Microsoft\Windows\INetCache"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 8.1)'
            }

            # IE COOKIES
            $Path = "$Path0\AppData\Local\Microsoft\Windows\INetCookies"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Internet Exploder Cookies (Windows 8.1)'
            }

            # CHROME CACHE
            $Path = "$Path0\AppData\Local\Google\Chrome\User Data\Default\Cache"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Google Chrome Cache Files'
            }

            # CHROME MEDIA CACHE
            $Path = "$Path0\AppData\Local\Google\Chrome\User Data\Default\Media Cache"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Google Chrome Media Cache Files'
            }

            # GOOGLE CHROME UPDATES
            $Path = "$Path0\AppData\Local\Google\Update"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Google Chrome Update Files'
            }

            # FIVE9 LOGS
            $Path = "$Path0\AppData\Roaming\Five9\Logs"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Five9 Log Files'
            }
                
            # FIVE9 INSTALLS
            $Path = "$Path0\AppData\Roaming\Five9.*"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Old Five9 Installations'
            }

            # C: DRIVE RECYCLE BIN
            $Path = "\\$Global:Hostname\c$\`$Recycle.Bin"
            If (Test-Path "$Path")
            {
                Remove-WithProgress -Path "$Path" -Title 'Recycle Bin Files on drive C:'
            }

            # D: DRIVE RECYCLE BIN
            $Path = "\\$Global:Hostname\d$\`$Recycle.Bin"
            If (Test-Path "$Path")
            {
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path" -Title 'Recycle Bin Files on drive D:'
            }

            # DELPROF2
            "`n"
            '--------------------------------------------------'
            Run-DelProf2 Unattended
            '--------------------------------------------------'

            $TotalTime1 = Get-Date
            $TotalTime2 = New-TimeSpan -Start $TotalTime0 -End $TotalTime1
            "`n"
            "Automated Cleanup Completed in {0:d2}:{1:d2}:{2:d2}" -F $TotalTime2.Hours,$TotalTime2.Minutes,$TotalTime2.Seconds

            $ManualCleanup = $Null
            $ManualCleanup = Get-WmiObject Win32_LogicalDisk -ComputerName $Global:HostName | Where-Object { $_.DeviceID -eq "$DriveLetter" -and $_.FreeSpace -lt 1073741824 }
            If ($ManualCleanup -ne $Null)
            {
            "Additional Cleanup needed on $Global:HostName - User ID: $ShortUser | Less than 1GB free after automated cleanup" | Tee-Object -File "$LogPath\manual-$LogDate.txt" -Append
            }

            $Cleanup = 'D'
        }
        2
        {
            # DelProf
            Run-DelProf2 $DelProfPreference
            '*******************************************************'
            Get-FreeSpace $DelProfPreference DelProf2
            '*******************************************************'
        }
        3
        {
            # Log user off machine
            $ShortUser
            $UserSession = ((quser /server:$Global:HostName | Where-Object { $_ -match $ShortUser }) -Split ' +')[2]
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

            # Hook remote print spooler
            $RemoteSpooler = Get-Service -ComputerName $Global:HostName -Name Spooler

            # Restart Print Spooler
            $RemoteSpooler.Stop()
            $RemoteSpooler.Start()

            # Stop RemoteWinRM service
            $RemoteWinRM.Stop()
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
                            notepad "$LogPath\bottleneckreport-$DateSelect.txt"
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
                            notepad "$LogPath\runtime-$DateSelect.txt"
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
                            notepad "$LogPath\manual-$DateSelect.txt"
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
                            notepad "$LogPath\bottleneckreport-$DateSelect.txt"
                        }
                        Else
                        {
                            "Log file $LogPath\bottleneckreport-$DateSelect.txt does not exist"
                        }
                        If (Test-Path "$LogPath\runtime-$DateSelect.txt")
                        {
                            notepad "$LogPath\runtime-$DateSelect.txt"
                        }
                        Else
                        {
                            "Log file $LogPath\runtime-$DateSelect.txt does not exist"
                        }
                        If (Test-Path "$LogPath\manual-$DateSelect.txt")
                        {
                            notepad "$LogPath\manual-$DateSelect.txt"
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
                        
                }
            
            }
            Until ($MenuOption -eq "B")
        }
        O
        {
            Do
            {
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
                        Break
                    }
                        
                }
            
            }
            Until ($MenuOption -eq "B")
        }
    D
        {
            "`n"
            "No further changes will be made to $Global:HostName"
            Break
        }
    Q
        {
            "`n"
            "Quit. No further changes will be made to $Global:HostName"
            '*******************************************************'
            Get-FreeSpace Finish
            '*******************************************************'
            Exit
        }
    Default
        {
            'Unrecognized input'
        }
    }
}
until ($Cleanup -eq "D" -or $Cleanup -eq "Q")

Get-FreeSpace Finish

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

"Elapsed Time: {0:d2}:{1:d2}:{2:d2}" -F $Runtime2.Hours,$Runtime2.Minutes,$Runtime2.Seconds | Tee-Object "$LogPath\runtime-$LogDate.txt" -Append
