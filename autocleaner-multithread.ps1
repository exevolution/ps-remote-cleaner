# Autocleaner.ps1
# Contact https://www.reddit.com/user/ExEvolution/ if you have any issues
Clear-Host
$ScriptRoot = $PSScriptRoot

# Start runtime
$Runtime0 = Get-Date

# Import AD Module
If (!(Get-Module ActiveDirectory))
{
    Import-Module -Name ActiveDirectory -ErrorAction Stop
}

# Make log directory if it doesn't exist
If (!(Test-Path -LiteralPath "$ScriptRoot\autologs\"))
{
    New-Item -ItemType Directory "$ScriptRoot\autologs\"
}
If (!(Test-Path -LiteralPath "$ScriptRoot\configs\"))
{
    New-Item -ItemType Directory "$ScriptRoot\configs\"
}

# Create default configuration file per user, load it and import its values if it exists
If (Test-Path -LiteralPath "$ScriptRoot\configs\$Env:UserName-config.ps1")
{
    "Loading configuration file {0}\configs\{1}-config.ps1" -F $ScriptRoot, $Env:UserName
    . "$ScriptRoot\configs\$Env:UserName-config.ps1"
}
Else
{
    "Creating default configuration file"
    New-Item -ItemType File "$ScriptRoot\configs\$Env:UserName-config.ps1"
    '
    # Default Configuration options
    $ReportPrefix = "report" # Report filename prefix. Example report-2015-12-08.csv would be "report". Search finds the most recently modified report*.csv
    $ReportSuffix = "" # Report filename suffix. Example 2015-12-08-report.csv would be "report". Search finds the most recenetly modified *report.csv
    $DownloadPath = "" # Location of report file, blank for default (local downloads folder)
    $CSVHeader = "Virtual Object" # Name of the column in the csv file containing the machines DNS name or IP address
    $VMRegex1 = "(ES)-(SRV|PRD|ACT|COR|CRP|CAP|FAV)-(\d{4}|\d{3})" # Regex to match your environments naming conventions
    $VMRegex2 = "(VDD)-(\w{1,11})" # Same as above, Comment out if not needed. Gives a second naming convention
    $VerbosePreference = "SilentlyContinue" # Toggle Verbosity, "SilentlyContinue" to suppress VERBOSE messages, "Continue" to use full Verbosity
    $MaxThreads = "" # Maximum Number of Threads. Blank for default (Logical Processors + 1). Invalid values will auto configure to the default value' |
    Out-File -FilePath "$ScriptRoot\configs\$Env:UserName-config.ps1"
    Invoke-Item "$ScriptRoot\configs\$Env:UserName-config.ps1"
    ''
    Read-Host -Prompt "Modify configuration as needed, then press Enter to continue and import the changes"
    "New configuration file created and imported"
    Get-Content "$ScriptRoot\configs\$Env:UserName-config.ps1" -Raw
    . "$ScriptRoot\configs\$Env:UserName-config.ps1"
}

# Import most recent report csv from local Downloads folder
If ($DownloadPath -eq "")
{
    $DownloadPath = Join-Path -Path $env:HOMEDRIVE -ChildPath $env:HOMEPATH | Join-Path -ChildPath "Downloads"
}
$RecentReport = Get-ChildItem -LiteralPath $DownloadPath -Filter "$ReportPrefix*$ReportSuffix.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

Do
{
    If ($Resume)
    {
        Remove-Variable Resume
    }

    If (Test-Path "$ScriptRoot\autologs\resume.csv")
    {
        $Resume = Read-Host -Prompt "Resume previous operation(Y/N)?"
        Switch ($Resume)
        {
            Y
                {
                    "Importing resume.csv"
                    $VMs = Import-CSV "$ScriptRoot\autologs\resume.csv" -Header "$CSVHeader"
                    "Complete"
                    Remove-Item -LiteralPath "$ScriptRoot\autologs\resume.csv" -Force
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
        Break
    }
}
Until ($Resume)

# Copy the array for manipulation
$VMRemaining = {$VMs}.Invoke()
$VMs = $VMs.$CSVHeader

# Set max concurrent threads if not configured
If (($MaxThreads -eq "") -or !($MaxThreads -as [int32]))
{
    $MaxThreads = Get-WmiObject Win32_Processor | Select-Object -ExpandProperty NumberOfLogicalProcessors
    $MaxThreads++
    "Autoconfigured Max Threads: $MaxThreads"
}

ForEach ($VM in $VMs)
{
    While (@(Get-Job | Where-Object { $_.State -eq "Running" }).Count -ge $MaxThreads)
    {
        Write-Verbose "Waiting for available thread... ($MaxThreads Maximum)"
        Start-Sleep -Seconds 5
    }

    $ScriptBlock = {
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
        # FUNCTIONS END

        $LogDate = (Get-Date).ToString('yyyy-MM-dd')

        If ($UserName)
        {
            Remove-Variable UserName
        }

        If (Test-Connection $Using:VM)
        {
            $VMName = Get-WmiObject Win32_ComputerSystem -ComputerName $Using:VM
            $VMServer = $VMName.__SERVER
            $UserName = $VMName.UserName
        }
        Else
        {
            Write-Warning "$VMServer not responding, skipping"
            Continue
        }

        If ($UserName)
        {
            $UserName = $VMName.UserName.Split("\")[1]
        }

        $Profiles = Get-WmiObject -Class Win32_UserProfile -ComputerName $Using:VM -Filter "NOT Special='True' AND NOT LocalPath LIKE '%00' AND NOT LocalPath LIKE '%Administrator'"

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
                $VMName | Export-Csv -Path "$Using:ScriptRoot\autologs\skipped-$LogDate.csv" -Append
                Continue
            }
            Else
            {
                "No profiles, skipping"
                $VMName | Export-Csv -Path "$Using:ScriptRoot\autologs\skipped-$LogDate.csv" -Append
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

        # If profile status Bit Field includes 8 (corrupt profile), quit.
        $Corrupt = 8
        $ProfileStatus = $Profiles.Status | Where-Object {$_.LocalPath -match $UserName}

        If (($Corrupt -band $ProfileStatus) -eq $Corrupt)
        {
            Write-Warning "PROFILE CORRUPT! User profile rebuild necessary. Writing to corrupt.csv and skipping!"
            $VMName | Export-Csv -Path "$Using:ScriptRoot\autologs\corrupt.csv" -Append -NoTypeInformation
            Continue
        }
        Get-FreeSpace -ComputerName $VMServer -DriveLetter $DriveLetter | Tee-Object -FilePath "$Using:ScriptRoot\autologs\bottleneck-$LogDate.log" -Append
        "Performing cleanup on $VMServer..."

        $AppDataPath = Join-Path -Path "$Path0" -ChildPath "AppData"
        $AppDataLocal = Join-Path -Path "$AppDataPath" -ChildPath "Local"
        $AppDataRoaming = Join-Path -Path "$AppDataPath" -ChildPath "Roaming"

        # WINDOWS TEMP
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Temp"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # IE CACHE W7
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Temporary Internet Files"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # IE COOKIES W7
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "Cookies"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # IE CACHE W8.1
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCache"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # IE COOKIES w8.1
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Microsoft" | Join-Path -ChildPath "Windows" | Join-Path -ChildPath "INetCookies"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # CHROME CACHE
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Cache"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # CHROME MEDIA CACHE
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "User Data" | Join-Path -ChildPath "Default" | Join-Path -ChildPath "Media Cache"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # GOOGLE CHROME UPDATES
        $Path = Join-Path -Path "$AppDataLocal" -ChildPath "Google" | Join-Path -ChildPath "Chrome" | Join-Path -ChildPath "Update"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # FIVE9 LOGS
        $Path = Join-Path -Path "$AppDataRoaming" -ChildPath "Five9" | Join-Path -ChildPath "Logs"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }
                
        # FIVE9 INSTALLS
        $Path = Join-Path -Path "$AppDataRoaming" -ChildPath "Five9.*"
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # C: DRIVE RECYCLE BIN
        $Path = Join-Path -Path "c$" -ChildPath '$Recycle.Bin'
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # D: DRIVE RECYCLE BIN
        $Path = Join-Path -Path "d$" -ChildPath '$Recycle.Bin'
        $TestPath = Join-Path -Path "\\$VMServer" -ChildPath "$Path"
        If (Test-Path "$TestPath")
        {
            Remove-Item -LiteralPath $TestPath -Recurse
        }

        # DelProf 2
        If ($DelProf)
        {
            Remove-Variable DelProf
        }
        $DelProf = Start-Process -FilePath "$Using:ScriptRoot\Bin\DelProf2 1.6.0\DelProf2.exe" -ArgumentList "/c:$VMServer /ed:$UserName /ed:Admin* /ed:00* /ed:Default* /ed:Public* /u /ntuserini" -Wait -PassThru -WindowStyle Minimized
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

        Get-FreeSpace -ComputerName $VMServer -DriveLetter $DriveLetter | Tee-Object -FilePath "$Using:ScriptRoot\autologs\bottleneck-$LogDate.log" -Append

        "Cleanup completed on $VMServer, moving to next system"

        $VMRemaining.Remove($VM)
        $VMRemaining | Export-Csv -LiteralPath "$Using:ScriptRoot\autologs\resume.csv" -NoTypeInformation

        #Start-Sleep -Seconds 5
    }
    Start-Job -ScriptBlock $ScriptBlock -ArgumentList $VM -Name $VM
}

While (@(Get-Job | Where-Object {$_.State -eq "Running" }).Count -ne 0)
{
    Write-Host "Waiting for background jobs..."
    Get-Job | Receive-Job
    Start-Sleep -Seconds 5
}

Get-Job
$Data = ForEach ($Job in (Get-Job))
{
    Receive-Job $Job
    Remove-Job $Job
}

$Data | Tee-Object -FilePath "$ScriptRoot\autologs\jobdata-$LogDate.log"

Remove-Item -LiteralPath "$ScriptRoot\autologs\resume.csv" -Force

$Runtime1 = Get-Date
$Runtime2 = New-TimeSpan -Start $Runtime0 -End $Runtime1
"Total Runtime: {0:d2}:{1:d2}:{2:d2}" -F $Runtime2.Hours,$Runtime2.Minutes,$Runtime2.Seconds | Tee-Object -FilePath "$ScriptRoot\autologs\runtime-$LogDate.log" -Append
