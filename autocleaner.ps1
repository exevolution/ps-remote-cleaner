# Autocleaner.ps1
# Contact https://www.reddit.com/user/ExEvolution/ if you have any issues
# Start runtime
Clear-Host
$Runtime0 = Get-Date

# Configuration options
$ReportPrefix = "report" # Report filename prefix. Example report-2015-12-08.csv would be "report". Search finds the most recently modified report*.csv
$eportSuffix = "" # Report filename suffix. Example 2015-12-08-report.csv would be "report". Search finds the most recenetly modified *report.csv
$CSVHeader = "Virtual Object" # Name of the column in the csv file containing the machine name
$VMRegex1 = "(ES)-(SRV|PRD|ACT|COR|CRP|CAP|FAV)-(\d{4}|\d{3})" # Regex to match your environment's naming conventions
$VMRegex2 = "(VDD)-(\w{1,11})" # Same as above, Comment out if not needed. Gives a second naming convention
$VerbosePreference = "Continue" # Toggle Verbosity, "SilentlyContinue" to suppress VERBOSE messages, "Continue" to use full Verbosity

# FUNCTIONS START

Function Get-FreeSpace
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Medium")]

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

    }
    Process
    {
        $FreeSpace = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName |
        Where-Object { $_.DeviceID -eq "$DriveLetter" } |
        Select-Object @{Name="Computer Name"; Expression={ $_.SystemName } }, @{Name="Drive"; Expression={ $_.Caption } }, @{Name="Free Space (GB)"; Expression={ "$([math]::Round($_.FreeSpace / 1GB,2))GB" } } |
        Format-Table -AutoSize
    }
    End
    {
        '**************************************************'
        $FreeSpace
        '**************************************************'
        Return
    }
}

Function Remove-WithProgress
{
    [CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Medium")]

    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]$ComputerName,

        [Parameter(Mandatory=$True, Position=1)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,

        [Parameter(Mandatory=$True, Position=2)]
        [ValidateNotNullOrEmpty()]
        [String]$Title
    )

    Begin
    {
        $Path = Join-Path -Path "\\$ComputerName" -ChildPath "$Path"
    }

    Process
    {
        # Progress Bar counter
        $CurrentFileCount = 0
        $CurrentFolderCount = 0

        # Start progress bar
        Write-Progress -Id 0 -Activity "Enumerating $Title from $ComputerName" -PercentComplete 0

        # Enumerate files (not folders), silence errors
        $Files = @(Get-ChildItem -Force -LiteralPath "$Path" -Recurse -ErrorAction SilentlyContinue -Attributes !Directory) | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending

        # Total file count for progress bar
        $FileCount = ($Files | Measure-Object).Count
        $TotalSize = [math]::Round((($Files | Measure-Object -Sum Length).Sum) / 1GB,3)

        "Removing $FileCount $Title... $TotalSize`GB."

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

            # Enumerate remaining files
            $RemainingFiles = @(Get-ChildItem -Force -Path "$Path" -Recurse -ErrorAction SilentlyContinue -Attributes !Directory).Count
            If ($RemainingFiles -gt 0)
            {
                "{0} files were not deleted" -f $RemainingFiles
            }

        }

        # Enumerate folders with 0 files
        $EmptyFolders = @(Get-ChildItem -Force -Path "$Path" -Recurse -Attributes Directory) | Where-Object {($_.GetFiles()).Count -eq 0} | Sort-Object -Property @{ Expression = {$_.FullName.Split('\').Count} } -Descending
    
        # How many empty folders for progress bars
        $EmptyCount = ($EmptyFolders | Measure-Object).Count

        If ($EmptyCount -gt 0)
        {
            "Removing $EmptyCount empty folders"
            $Title = 'Empty Directories'

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
        "Removing $Title completed"
        Return
    }
}
# FUNCTIONS END

# Import AD Module
If (!(Get-Module ActiveDirectory))
{
    Import-Module -Name ActiveDirectory -ErrorAction Stop
}

# Make log directory if it doesn't exist
If (!(Test-Path -LiteralPath "$PSScriptRoot\autologs\"))
{
    New-Item -ItemType Directory "$PSScriptRoot\autologs\"
}

# Import most recent report csv from local Downloads folder
$DownloadPath = Join-Path -Path $env:HOMEDRIVE -ChildPath $env:HOMEPATH | Join-Path -ChildPath "Downloads"
$RecentReport = Get-ChildItem -LiteralPath $DownloadPath -Filter "$ReportPrefix*$ReportSuffix.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

Do
{
    If (Test-Path "$PSScriptRoot\autologs\resume.csv")
    {
        If ($Resume)
        {
            Remove-Variable Resume
        }
        $Resume = Read-Host -Prompt "Resume previous operation(Y/N)?"
        Switch ($Resume)
        {
            Y
                {
                    "Importing resume.csv"
                    $VMs = Import-CSV "$PSScriptRoot\autologs\resume.csv" -Header "$CSVHeader"
                    "Complete"
                    Remove-Item -LiteralPath "$PSScriptRoot\autologs\resume.csv" -Force
                    Break
                }
            N
                {
                    "Importing {0}" -F $RecentReport.FullName
                    $VMs = Import-CSV $RecentReport.FullName | Where-Object {$_."$CSVHeader" -match "$VMRegex1" -or $_."$CSVHeader" -match "$VMRegex2"}
                    "Complete"
                    Break
                }
            Default
                {
                    "Unrecognized Option"
                    Remove-Variable Resume
                }
        }
    }
    Else
    {
        "Importing {0}" -F $RecentReport.FullName
        $VMs = Import-CSV $RecentReport.FullName -Header "$CSVHeader" | Where-Object {$_."$CSVHeader" -match "$VMRegex1" -or $_."$CSVHeader" -match "$VMRegex2"}
        "Complete"
    }
}
Until ($Resume)

# Copy the array for manipulation
$VMRemaining = {$VMs}.Invoke()

ForEach ($VM in $VMs)
{
    If ($UserName)
    {
        Remove-Variable UserName
    }
    $LogDate = (Get-Date).ToString('yyyy-MM-dd')
    $VMName = Get-WmiObject Win32_ComputerSystem -ComputerName $VM."$CSVHeader"
    $VMServer = $VMName.__SERVER
    $UserName = $VMName.UserName

    If ($UserName)
    {
        $UserName = $VMName.UserName.Split("\")[1]
    }

    $Profiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $VM."$CSVHeader" -Filter "NOT Special='True' AND NOT LocalPath LIKE '%00' AND NOT LocalPath LIKE '%Administrator'"

    If (!$UserName)
    {
        If (($Profiles | Measure-Object).Count -eq 1)
        {
            $SID = $Profiles | Select-Object -ExpandProperty sid
            $UserName = (Get-ADUser -Filter {SID -eq $SID} | Select-Object SamAccountName).SamAccountName
            $DriveLetter = $Profiles.LocalPath.Substring(0,2)
            $DriveLetterUNC = $DriveLetter -replace ':', '$'
            $ProfilePath = $Profiles.LocalPath -replace ':','$'
            $Path0 = $ProfilePath | Where-Object {$_.LocalPath -match $UserName}
            "Active User: {0}\{1} - {2}" -F $VMServer, $Path0, $UserName
        }
        If (($Profiles | Measure-Object).Count -gt 1)
        {
            "Unable to detect assigned user on {0}, logging to skipped-{1}.csv moving to next object." -F $VMServer, $LogDate
            $VMName | Export-Csv -Path "$PSScriptRoot\autologs\skipped-$LogDate.csv" -Append
            Continue
        }
        Else
        {
            "No profiles, skipping"
            $VMName | Export-Csv -Path "$PSScriptRoot\autologs\skipped-$LogDate.csv" -Append
            Continue
        }
    }
    Else
    {
        $ProfilePath = $Profiles.LocalPath | Where-Object {$_ -match $UserName}
        $DriveLetter = $ProfilePath.Substring(0,2)
        $DriveLetterUNC = $DriveLetter -replace ':','$'
        $Path0 = $ProfilePath -replace ':', '$'
    }

<#    $StaleProfiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $VM."$CSVHeader" -Filter "NOT Special='True' AND NOT LocalPath LIKE '%00' AND NOT LocalPath LIKE '%Administrator' AND NOT LocalPath LIKE '%$UserName' AND NOT RoamingPath LIKE '%$UserName.V2'"
    ForEach ($Prof in $StaleProfiles)
    {
        "Deleting stale profile $ProfPath"
        $ProfPath = $Prof.LocalPath -replace ':','$'
        Remove-WithProgress -ComputerName $VMServer -Path $ProfPath -Title "Stale Profile $ProfPath"
        $Prof.Delete()
    }
#>

    # If profile status Bit Field includes 8 (corrupt profile), quit.
    $Corrupt = 8
    $ProfileStatus = $Profiles.Status | Where-Object {$_.LocalPath -match $UserName}

    If (($Corrupt -band $ProfileStatus) -eq $Corrupt)
    {
        Write-Warning "PROFILE CORRUPT! User profile rebuild necessary. Writing to corrupt.csv and skipping!"
        $VMName | Export-Csv -Path "$PSScriptRoot\autologs\corrupt.csv" -Append -NoTypeInformation
        Continue
    }
    Get-FreeSpace -ComputerName $VMServer -DriveLetter $DriveLetter | Tee-Object -FilePath "$PSScriptRoot\autologs\bottleneck-$LogDate.log" -Append
    "Performing cleanup on $VMServer..."

    $AppDataPath = Join-Path -Path "$Path0" -ChildPath "AppData"
    $AppDataLocal = Join-Path -Path "$AppDataPath" -ChildPath "Local"
    $AppDataRoaming = Join-Path -Path "$AppDataPath" -ChildPath "Roaming"

    # WINDOWS TEMP
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Temp"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Windows Temp Files'
    }

    # IE CACHE W7
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Temporary Internet Files"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 7)'
    }

    # IE COOKIES W7
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Cookies"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cookies (Windows 7)'
    }

    # IE CACHE W8.1
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCache"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 8.1)'
    }

    # IE COOKIES w8.1
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCookies"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cookies (Windows 8.1)'
    }

    # CHROME CACHE
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Cache"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Google Chrome Cache Files'
    }

    # CHROME MEDIA CACHE
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Media Cache"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Google Chrome Media Cache Files'
    }

    # GOOGLE CHROME UPDATES
    $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "Update"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Google Chrome Update Files'
    }

    # FIVE9 LOGS
    $Path = Join-Path -Path "$AppDataRoaming" -ChildPath "Five9" | Join-Path -ChildPath "Logs"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Five9 Log Files'
    }
                
    # FIVE9 INSTALLS
    $Path = Join-Path -Path "$AppDataRoaming" -ChildPath "Five9.*"
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Old Five9 Installations'
    }

    # C: DRIVE RECYCLE BIN
    $Path = Join-Path -Path "c$" -ChildPath '$Recycle.Bin'
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Recycle Bin Files on drive C:'
    }

    # D: DRIVE RECYCLE BIN
    $Path = Join-Path -Path "d$" -ChildPath '$Recycle.Bin'
    $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
    If (Test-Path "$TestPath")
    {
        # Call deletion with progress bar
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Recycle Bin Files on drive D:'
    }

    # DelProf 2
    If ($DelProf)
    {
        Remove-Variable DelProf
    }
    $DelProf = Start-Process -FilePath "$PSScriptRoot\Bin\DelProf2 1.6.0\DelProf2.exe" -ArgumentList "/c:$VMServer /ed:$UserName /ed:Admin* /ed:00* /ed:Default* /ed:Public* /u /ntuserini" -Wait -PassThru
    $DelProf.WaitForExit()

    If ($DelProf.ExitCode -eq "0")
    {
        'DelProf2 completed successfully'
    }
    ElseIf ($DelProf.ExitCode -eq $Null)
    {
        'DelProf2 exited but the error code was lost'
    }
    Else
    {
        "DelProf2 encountered an error. Exit code {0}" -F $DelProf.ExitCode
    }

    Get-FreeSpace -ComputerName $VMServer -DriveLetter $DriveLetter | Tee-Object -FilePath "$PSScriptRoot\autologs\bottleneck-$LogDate.log" -Append

    "Cleanup completed on $VMServer, moving to next system"

    $VMRemaining.Remove($VM)
    $VMRemaining | Export-Csv -LiteralPath "$PSScriptRoot\autologs\resume.csv" -NoTypeInformation

    Start-Sleep -Seconds 5
    Clear-Host
}
Remove-Item -LiteralPath "$PSScriptRoot\autologs\resume.csv" -Force

$Runtime1 = Get-Date
$Runtime2 = New-TimeSpan -Start $Runtime0 -End $Runtime1
"Total Runtime: {0:d2}:{1:d2}:{2:d2}" -F $Runtime2.Hours,$Runtime2.Minutes,$Runtime2.Seconds | Tee-Object -FilePath "$PSScriptRoot\autologs\runtime-$LogDate.log" -Append
