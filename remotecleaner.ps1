#requires -Version 3.0
#requires -RunAsAdministrator
# This PowerShell script is designed to perform regular maintainance on domain computers
# If you encounter any errors, please contact http://www.reddit.com/u/exevolution
$Runtime0 = Get-Date -Format 'HH:mm:ss'

# Declare necessary, or maybe unnecessary global vars for functions
$Global:HostName = $Null
$Global:HostEntry = $Null
$Global:HostIP = $Null
$Global:HostInfo = $Null
$Global:DelProf = $Null

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
    $T0 = Get-Date -Format 'HH:mm:ss'
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
    $T1 = Get-Date -Format 'HH:mm:ss'
    $T2 = New-TimeSpan -Start $T0 -End $T1
    "Operation Completed in {0:c}" -f $T2
    "$Global:HostName | DelProf2 completed in $T2`n" | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append
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
    $CurrentFileNumber = 0
    
    "`n"
    '--------------------------------------------------'
    "Collecting $Title, please wait..."
    
    # Start progress bar
    Write-Progress -Id 0 -Activity 'Collecting' -PercentComplete -1
    # Start timer
    $T0 = Get-Date -Format 'HH:mm:ss'
    # Count files, silence errors
    $Files = Get-ChildItem -Force -Path "$Path\*" -Recurse -File -ErrorAction SilentlyContinue
    $T1 = Get-Date -Format 'HH:mm:ss'
    $T2 = New-TimeSpan -Start $T0 -End $T1
    "Operation completed in {0:c}" -f $T2

    # Total file count for progress bar
    $FileCount = $Files.Count
    $TotalSize = ($Files | Measure-Object -Sum Length).Sum
    $TotalSize = [math]::Round($TotalSize / 1GB,3)

    # Write detailed info to runtime log
    "`n$Global:HostName | $FileCount $Title gathered in $T2" | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append

    "`n"
    "Removing $FileCount $Title... $TotalSize`GB."
    $T0 = Get-Date -Format 'HH:mm:ss'
    ForEach ($File in $Files)
    {
        $CurrentFileNumber++
        $FullFileName = $File.FullName
        $Percentage = [math]::Round(($CurrentFileNumber / $FileCount) * 100)
        Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
        Write-Progress -Id 0 -Activity "Removing $Title" -CurrentOperation "File: $FullFileName" -PercentComplete $Percentage -Status "Progress: $CurrentFileNumber of $FileCount, $Percentage%"
    }
    # Attempt to remove the empty subdirectories after, will not occur if locked files still exist
    Remove-Item "$Path\*\" -Recurse -ErrorAction SilentlyContinue

    $T1 = Get-Date -Format 'HH:mm:ss'
    $T2 = New-TimeSpan -Start $T0 -End $T1
    "Operation Completed in {0:c}" -F $T2

    # Write detailed info to runtime log
    "$Global:HostName | $FileCount $Title deleted in $T2 | $TotalSize`GB`n" | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append
    '--------------------------------------------------'
    Write-Progress -Id 0 'Done' 'Done' -Completed
    Return
}


# ----------------
# End Functions
# ----------------

# Get Local Username
$LocalAdmin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Check that user is an administrator, exit if not. Not necessary anymore, PowerShell has a built in detection #requires -RunAsAdministrator
#If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
#{
#    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
#    Sleep 5
#    Exit 100
#}

# Begin main program
Do
{
# Get current date for logs
$LogDate = Get-Date -Format 'yyyyMMdd'

Clear-Host
# Feel Free to create your own ANSI ascii art for this section
# Mine requires 130 width in your PS window to work properly
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
'If you encounter any errors, please contact http://www.reddit.com/u/ExEvolution'
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
    $ShortUser = Read-Host 'No active user detected. Please enter the assigned username from Horizon View Administrator'

    # Assume, based on entered information, the active profile
    $ActiveProfile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:HostName | Where-Object {$_.LocalPath -Match "$ShortUser"}
}
Else
{
    $ShortUser = $Global:DomainUser.Trim($Global:Domain)
        
    # Get the most recently used active profile, store local path as administrative share in variable
    $ActiveProfile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:HostName | Where-Object {$_.LocalPath -Match "$ShortUser"}

    # Alternative method
    #$ActiveProfile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:HostName | Where-Object {$_.Loaded -eq 1 -and $_.Special -eq 0} | Sort-Object $_.LastUseTime | Select-Object -First 1
}

# Per-user log path setup
$AdminLogPath = $LocalAdmin.Trim($Global:Domain)

# Check for per-user log directory, create if it does not exist
If (Test-Path  "$PSScriptRoot\logs\$AdminLogPath\")
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
                $TotalTime0 = Get-Date -Format 'HH:mm:ss'

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
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path"

                # IE CACHE
                # Progress Bar Title
                $Title = 'Internet Exploder Cache Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Microsoft\Windows\Temporary Internet Files'
                $Path = "$Path0\$Path1"
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path"

                # CHROME CACHE
                # Progress Bar Title
                $Title = 'Google Chrome Cache Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Google\Chrome\User Data\Default\Cache'
                $Path = "$Path0\$Path1"
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path"

                # CHROME MEDIA CACHE
                # Progress Bar Title
                $Title = 'Google Chrome Media Cache Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Local\Google\Chrome\User Data\Default\Media Cache'
                $Path = "$Path0\$Path1"
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path"

                # FIVE9 LOGS
                # Progress Bar Title
                $Title = 'Five9 Log Files'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Roaming\Five9\Logs'
                $Path = "$Path0\$Path1"
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path"
                
                # FIVE9 INSTALLS
                # Progress Bar Title
                $Title = 'Old Five9 Installations'
                # Relative path from user's profile directory
                $Path1 = 'AppData\Roaming\Five9.*'
                $Path = "$Path0\$Path1"
                # Call deletion with progress bar
                Remove-WithProgress -Path "$Path"

                # DELPROF2
                # Run DelProf2
                "`n"
                '--------------------------------------------------'
                RunDelProf2 Unattended
                '--------------------------------------------------'

                Sleep 1
                Write-Progress -Id 0 'Done' 'Done' -Completed

                $TotalTime1 = Get-Date -Format "H:mm:ss"
                $TotalTime2 = New-TimeSpan -Start $TotalTime0 -End $TotalTime1
                "`n"
                "Automated Cleanup Completed in {0:c}" -f $TotalTime2

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
                Sleep 2
            }
        Q
            {
                "`n"
                "Quit. No further changes will be made to $Global:HostName"
                GetFreeSpace Finish
                Sleep 2
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

$Runtime1 = Get-Date -Format 'HH:mm:ss'
$Runtime2 = New-TimeSpan -Start $Runtime0 -End $Runtime1
"Total Runtime: $Runtime2" | Out-File -File "$PSScriptRoot\logs\$AdminLogPath\runtime-$LogDate.txt" -Append
