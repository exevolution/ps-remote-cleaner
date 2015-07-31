#requires -Version 3.0
# This PowerShell script is designed to perform regular maintainance on domain computers
# If you encounter any errors, please contact ExEvolution http://www.reddit.com/user/ExEvolution

# Declare necessary, or maybe unnecessary global vars for functions
$Global:hostname = $null
$Global:hostentry = $null
$Global:hostip = $null
$Global:hostinfo = $null
$Global:delprof = $null
$Global:fakeprogress = 0

# ----------------
# Define Functions
# ----------------

Function GetFreeSpace
{
    "`n*******************************************************`n"
    Get-WmiObject Win32_LogicalDisk -computername $Global:hostname |
    Where-Object { $_.DeviceID -eq "$driveletter" } |
    Select-Object @{Name="Computer Name"; Expression={ $_.SystemName } }, @{Name="Drive"; Expression={ $_.Caption } }, @{Name="Free Space (" + $args[0..$args.Length] + ")"; Expression={ "$([math]::round($_.FreeSpace / 1GB,2))GB" } } |
    Format-Table -AutoSize |
    Tee-Object -Append -File $PSScriptRoot\bottleneckreport-$logdate.txt
    "*******************************************************`n"
}

Function RunDelProf2
{
    Switch ($args[0])
    {
        "Unattended"
            {
            $varattend = '/u'
            }
        "Prompt"
            {
            $varattend = '/p'
            }
        Default
            {
            $varattend = ''
            }
    }
    "`nDeleting Stale User Profiles With DelProf2. Please wait... This may take several minutes."
    $Global:delprof = Start-Process -FilePath "$PSScriptRoot\DelProf2\DelProf2.exe" -ArgumentList "/c:$Global:hostname /ed:$shortuser /ed:Admin* /ed:00* /ed:Default* /ed:Public* $varattend" -Wait -PassThru
}

Function ResolveHost
{
    If ($Global:hostentry -As [IPAddress])
    {
        $Global:hostip = $Global:hostentry
        $Global:hostinfo = [System.Net.Dns]::GetHostEntry($Global:hostip)
        $Global:hostname = $Global:hostinfo.HostName
    }
    Else
    {
        $Global:hostname = $Global:hostentry.ToUpper()
        $Global:hostinfo = Resolve-DnsName -Name $Global:hostname
        $Global:hostip = $Global:hostinfo.IPAddress
    }
}

Function RemoveWithProgress
{
    $currentfilenumber = 0
    "`n--------------------------------------------------"
    "Collecting $title, please wait..."
    $t0 = Get-Date -Format "h:mm:ss"
    Write-Progress -Id 0 -Activity "Collecting" -PercentComplete -1
    $files = Get-ChildItem -Force -Path "$fullprofilepath\$relativepath\*" -Recurse -File -ErrorAction SilentlyContinue
    $t1 = Get-Date -Format "h:mm:ss"
    $t2 = New-TimeSpan -Start $t0 -End $t1
    "Operation completed in {0:c}" -f $t2

    $filecount = $files.Count
    $totalsize = ($files | Measure-Object -Sum Length).Sum
    $totalsize = [math]::Round($totalsize / 1GB,3)
    "`nRemoving $filecount $title... $totalsize`GB."
    $t0 = Get-Date -Format "h:mm:ss"
    ForEach ($file in $files)
    {
        $currentfilenumber++
        $fullfilename = $file.FullName
        $percentage = [math]::Round(($currentfilenumber / $filecount) * 100)
        Remove-Item $file.FullName -ErrorAction SilentlyContinue
        Write-Progress -Id 0 -Activity "Removing $title" -CurrentOperation "File: $fullfilename" -PercentComplete $percentage -Status "Progress: $currentfilenumber of $filecount, $percentage%"
        
        # Show a fake progress bar for total progress, need a new and dynamic method
        If ($Global:fakeprogress -eq 100)
        {
            $Global:fakeprogress = 0
            Write-Progress -Id 1 -Activity "Automated Cleanup" -PercentComplete $Global:fakeprogress -Status "$title"
        }
        Else
        {
            $Global:fakeprogress++
            Write-Progress -Id 1 -Activity "Automated Cleanup" -PercentComplete $Global:fakeprogress -Status "$title"
        }

    }
    # Attempt to remove the empty directory after, will not occur if locked files still exist
    Remove-Item "$fullprofilepath\$relativepath\*" -Recurse -ErrorAction SilentlyContinue

    $t1 = Get-Date -Format "h:mm:ss"
    $t2 = New-TimeSpan -Start $t0 -End $t1
    "Operation Completed in {0:c}" -f $t2
    "--------------------------------------------------"
    Write-Progress -Id 0 "Done" "Done" -Completed
}


# ----------------
# End Functions
# ----------------

# Get Local Username, just in case
$localadmin = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Check that user is an administrator, exit if not 
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Sleep 5
    Exit 100
}

# Begin main program
Do
{
# Get current date for logs
$logdate = Get-Date -Format "yyyyMMdd"

Clear-Host
"This PowerShell script is designed to perform regular maintainance on domain computers`n"
"If you encounter any errors, please contact ExEvolution http://www.reddit.com/user/ExEvolution`n"

# Collect Computer Info
Do
{

# If computer name is a blank string, loop
Do
{
    $Global:hostentry = Read-Host -Prompt "Enter the computer name or IP address"
}
While ($Global:hostentry -eq "")

ResolveHost

"`n-------------------------------------------------------"
"Computer Name: $Global:hostname"
"IP Address: $Global:hostip"
"Admin Username: $localadmin"
"-------------------------------------------------------`n"

$verifyinfo = Read-Host "Is this correct? (Y/N)"
}
until ($verifyinfo -eq "Y")

# Collect info from computer, get active user
"`n-------------------------------------------------------"
"Collecting information from $Global:hostname, please wait..."
"-------------------------------------------------------`n"
If (Test-Path  "\\$Global:hostname\Admin`$\*")
{
    "Admin rights confirmed on $Global:hostname"
}
Else
{
    Write-Warning "Admin rights not detected on remote machine."
    $rerun = Read-Host "(R)etry or press any other key to quit"
    Continue
}

$computersys =  Get-WmiObject Win32_ComputerSystem -Computer $Global:hostname

# Detect domain name, remove top level domain, convert to uppercase for future Trim operation
$Global:domain = $computersys.Domain -replace ".com", "" -replace ".net", "" -replace ".org", ""
$Global:domain = $Global:domain + "\"
$Global:domain = $Global:domain.ToUpper()

# Get logged in username, including domain name
$Global:domainuser = Get-WmiObject Win32_ComputerSystem -Computer $Global:hostname
$Global:domainuser = $Global:domainuser.UserName

# If no user is logged in, prompt for the assigned user
If ($Global:domainuser -eq $null)
{
    $shortuser = Read-Host "No active user detected. Please enter the assigned username from Horizon View Administrator"

    # Assume, based on entered information, the active profile
    $activeprofile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:hostname | Where-Object {$_.LocalPath -Match "$shortuser"}
}
Else
{
    $shortuser = $Global:domainuser.Trim($Global:domain)
        
    # Get the most recently used active profile, store local path as administrative share in variable
    $activeprofile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:hostname | Where-Object {$_.LocalPath -Match "$shortuser"}

    # Alternative method
    #$activeprofile = Get-WmiObject -Class Win32_UserProfile -Computer $Global:hostname | Where-Object {$_.Loaded -eq 1 -and $_.Special -eq 0} | Sort-Object $_.LastUseTime | Select-Object -First 1
}

# Grab local path from active profile
$profilepath = $activeprofile.LocalPath
# Convert 
$profileshare = $profilepath -replace ':', '$'
$driveletter = $profilepath.Substring(0,2)

"Active user on $Global:hostname is $shortuser"
"Administrative share of active user is \\$Global:hostname\$profileshare"
"Drive letter - $driveletter"

"Checking Free Space on $Global:hostname, drive $driveletter."

$fullprofilepath = "\\$Global:hostname\$profileshare"

# Calculate free space before beginning
GetFreeSpace Start

# Cleanup temp files and IE cache
do
{
    "Choose one of the following options to continue"
    "-------------------------------------------------------"
    "[1] Automated Cleanup"
    "[2] Automatic Stale Profile Cleanup"
    "[3] Interactive Stale Profile Cleanup"
    "[D] Do Nothing, Move To Next Computer"
    "[Q] Quit"
    "-------------------------------------------------------"
    $cleanup = Read-Host "Choice"

    Switch ($cleanup)
    {
        1
            {
                $totaltime0 = Get-Date -Format "h:mm:ss"
                # Give the user a chance to cancel before changes are made
                Write-Warning "This makes permanent changes to the system. Press Ctrl+C now to cancel"
                Sleep 5

                # Start the global progress bar
                Write-Progress -Id 1 -Activity "Automated Cleanup" -PercentComplete 0 -Status "Processing"

                # TEMP
                # Progress Bar Title
                $title = "Windows Temp Files"
                # Relative path from user's profile directory
                $relativepath = "AppData\Local\Temp"
                # Call deletion with progress bar
                RemoveWithProgress

                # IE
                # Progress Bar Title
                $title = "Internet Exploder Cache Files"
                # Relative path from user's profile directory
                $relativepath = "AppData\Local\Microsoft\Windows\Temporary Internet Files"
                # Call deletion with progress bar
                RemoveWithProgress

                # CHROME
                # Progress Bar Title
                $title = "Google Chrome Cache Files"
                # Relative path from user's profile directory
                $relativepath = "AppData\Local\Google\Chrome\User Data\Default\Cache"
                # Call deletion with progress bar
                RemoveWithProgress
                # Progress Bar Title
                $title = "Google Chrome Media Cache Files"
                # Relative path from user's profile directory
                $relativepath = "AppData\Local\Google\Chrome\User Data\Default\Media Cache"
                # Call deletion with progress bar
                RemoveWithProgress

                # FIVE9
                # Progress Bar Title
                $title = "Five9 Log Files"
                # Relative path from user's profile directory
                $relativepath = "AppData\Roaming\Five9\Logs"
                # Call deletion with progress bar
                RemoveWithProgress
                # Progress Bar Title
                $title = "Old Five9 Installations"
                # Relative path from user's profile directory
                $relativepath = "AppData\Roaming\Five9.*"
                # Call deletion with progress bar
                RemoveWithProgress

                # DELPROF2
                # Run DelProf2
                Write-Progress -Id 1 -Activity "Automated Cleanup" -PercentComplete 85 -Status "DelProf2"
                $t0 = Get-Date -Format "h:mm:ss"
                RunDelProf2 Unattended
                $t1 = Get-Date -Format "h:mm:ss"
                $t2 = New-TimeSpan -Start $t0 -End $t1
                "Operation Completed in {0:c}" -f $t2

                Write-Progress -Id 1 -Activity "Automated Cleanup" -PercentComplete 100 -Status "Finishing.."
                Sleep 1
                Write-Progress -Id 0 "Done" "Done" -Completed
                Write-Progress -Id 1 "Done" "Done" -Completed

                $totaltime1 = Get-Date -Format "h:mm:ss"
                $totaltime2 = New-TimeSpan -Start $totaltime0 -End $totaltime1
                "Automated Cleanup Completed in {0:c}" -f $totaltime2

                $cleanup = "D"
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
        D
            {
                "`nNo further changes will be made to $Global:hostname"
                Sleep 2
            }
        Q
            {
                "`nQuit. No further changes will be made to $Global:hostname"
                GetFreeSpace Finish
                Sleep 2
                Exit 1
            }
        Default
            {
                "Unrecognized input"
            }
    }
}
until ($cleanup -eq "D" -or $cleanup -eq "Q")

GetFreeSpace Finish

# Clean all variables created this session to prevent issues after loop
$sysvars = Get-Variable | Select-Object -ExpandProperty Name
$sysvars += 'sysvars'
Get-Variable | Where-Object {$sysvars -notcontains $_.Name} | ForEach {Remove-Variable $_}

"-------------------------------------------------------"
"[R] Run again on another computer"
"[Q] Quit"
"-------------------------------------------------------"
$rerun = Read-Host "Choice"
}
until ($rerun -eq "Q")
