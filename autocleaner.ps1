# Autocleaner.ps1
# Contact https://www.reddit.com/user/ExEvolution/ if you have any issues

# Configuration options
$ReportPrefix = "report" # Report filename prefix. Example report-2015-12-08.csv would be "report". Search finds the most recently modified report*.csv
$eportSuffix = "" # Report filename suffix. Example 2015-12-08-report.csv would be "report". Search finds the most recenetly modified *report.csv
$CSVHeader = "Virtual Object" # Name of the column in the csv file containing the machine name
$VMRegex1 = "(ES)-(SRV|PRD|ACT|COR|CRP|CAP|FAV)-(\d{4}|\d{3})" # Regex to match your environment's naming conventions
$VMRegex2 = "(VDD)-(\w{1,11})" # Same as above, Comment out if not needed. Gives a second naming convention
$VerbosePreference = "Continue" # Toggle Verbosity, "SilentlyContinue" to suppress VERBOSE messages, "Continue" to use full Verbosity

# FUNCTIONS START
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

# Remove previous list of skipped VMs
If (Test-Path -LiteralPath "$PSScriptRoot\autologs\list.csv")
{
    Remove-Item -LiteralPath "$PSScriptRoot\autologs\list.csv" -Force
}

# Import most recent report csv from local Downloads folder
$DownloadPath = Join-Path -Path $env:HOMEDRIVE -ChildPath $env:HOMEPATH | Join-Path -ChildPath "Downloads"
$RecentReport = Get-ChildItem -LiteralPath $DownloadPath -Filter "$ReportPrefix*$ReportSuffix.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
"Importing {0}" -F $RecentReport.FullName

$VMs = Import-CSV $RecentReport.FullName -Header "$CSVHeader" | Where-Object {$_."$CSVHeader" -match "$VMRegex1" -or $_."$CSVHeader" -match "$VMRegex2"}

ForEach ($VM in $VMs)
{
    If ($UserName)
    {
        Remove-Variable UserName
    }

    $VMName = Get-WmiObject Win32_ComputerSystem -ComputerName $VM."$CSVHeader"
    $VMServer = $VMName.__SERVER
    $UserName = $VMName.UserName.Split("\")[1]

    $Profiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $VM."$CSVHeader" | Where-Object {($_.LocalPath -notmatch "00") -and ($_.LocalPath -notmatch "Admin") -and ($_.LocalPath -notmatch "Default") -and ($_.LocalPath -notmatch "Public") -and ($_.LocalPath -notmatch "LocalService") -and ($_.LocalPath -notmatch "NetworkService") -and ($_.LocalPath -notmatch "systemprofile")}

    If ($UserName -eq $Null)
    {
        If (($Profiles | Measure-Object).Count -eq 1)
        {
            $SID = $Profiles | Select-Object -ExpandProperty sid
            $UserName = (Get-ADUser -Filter {SID -eq $SID} | Select-Object SamAccountName).SamAccountName
            $DriveLetter = $Profiles.LocalPath.Substring(0,2)
            $ProfilePath = $Profiles.LocalPath -replace ':','$'
            $Path0 = $ProfilePath | Where-Object {$_.LocalPath -match $UserName}
            "Active User: {0}\{1} - {2}" -F $VMServer, $Path0, $UserName
        }
        If (($Profiles | Measure-Object).Count -gt 1)
        {
            "Unable to detect assigned user on {0}, logging to list.csv and skipping" -F $VMServer
            $VMName | Export-Csv -Path "$PSScriptRoot\autologs\list.csv" -Append
            Continue
        }
        Else
        {
            "No profiles, skipping"
            $VMName | Export-Csv -Path "$PSScriptRoot\autologs\list.csv" -Append
            Continue
        }
    }
    Else
    {
        $ProfilePath = $Profiles.LocalPath | Where-Object {$_ -match $UserName}
        $DriveLetter = $ProfilePath.Substring(0,2) -replace ':','$'
        $Path0 = $ProfilePath -replace ':', '$'
    }

    # If profile status Bit Field includes 8 (corrupt profile), quit.
    $Corrupt = 8
    $ProfileStatus = $Profiles.Status | Where-Object {$_.LocalPath -match $UserName}

    If (($Corrupt -band $ProfileStatus) -eq $Corrupt)
    {
        Write-Warning "PROFILE CORRUPT! User profile rebuild necessary. Writing to corrupt.csv and skipping!"
        $VMName | Export-Csv -Path "$PSScriptRoot\autologs\corrupt.csv" -Append
        Continue
    }

    "Performing cleanup on $VMServer..."

    # WINDOWS TEMP
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Temp"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Windows Temp Files'
    }

    # IE CACHE W7
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Temporary Internet Files"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 7)'
    }

    # IE COOKIES W7
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Cookies"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cookies (Windows 7)'
    }

    # IE CACHE W8.1
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCache"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cache Files (Windows 8.1)'
    }

    # IE COOKIES w8.1
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCookies"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Internet Exploder Cookies (Windows 8.1)'
    }

    # CHROME CACHE
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Cache"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Google Chrome Cache Files'
    }

    # CHROME MEDIA CACHE
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Media Cache"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Google Chrome Media Cache Files'
    }

    # GOOGLE CHROME UPDATES
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Local" | Join-Path -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "Update"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Google Chrome Update Files'
    }

    # FIVE9 LOGS
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Roaming" | Join-Path -ChildPath "Five9" | Join-Path -ChildPath "Logs"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Five9 Log Files'
    }
                
    # FIVE9 INSTALLS
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "$Path0" | Join-Path -ChildPath "AppData" | Join-Path -ChildPath "Roaming" | Join-Path -ChildPath "Five9.*"
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Old Five9 Installations'
    }

    # C: DRIVE RECYCLE BIN
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "c$" | Join-Path -ChildPath '$Recycle.Bin'
    If (Test-Path "$Path")
    {
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Recycle Bin Files on drive C:'
    }

    # D: DRIVE RECYCLE BIN
    $Path = Join-Path -Path "\\$VMServer" -ChildPath "d$" | Join-Path -ChildPath '$Recycle.Bin'
    If (Test-Path "$Path")
    {
        # Call deletion with progress bar
        Remove-WithProgress -ComputerName $VMServer -Path "$Path" -Title 'Recycle Bin Files on drive D:'
    }

    # DelProf 2
    If ($DelProf)
    {
        Remove-Variable DelProf
    }
    $DelProf = Start-Process -FilePath "$PSScriptRoot\Bin\DelProf2 1.6.0\DelProf2.exe" -ArgumentList "/c:$VMServer /ed:$UserName /ed:Admin* /ed:00* /ed:Default* /ed:Public* /u" -Wait -PassThru
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
    "Cleanup completed on $VMServer, moving to next system"
}
