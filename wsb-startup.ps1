# Variable to control logging (set to false by default)
$enableLogging = $false

# Configure verbose output
$VerbosePreference = 'Continue'

# Start logging to the mapped folder if enabled
if ($enableLogging) {
    try {
        Start-Transcript -Path "C:\Users\WDAGUtilityAccount\Desktop\USB\setup-log.txt" -Append -ErrorAction Stop
        Write-Verbose "Logging started."
    } catch {
        Write-Error "Failed to start transcript: $_"
    }
}

# Set execution policy
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# --- Install Chocolatey ---
Write-Verbose "Installing Chocolatey..."
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
choco feature disable -n autoUninstaller
choco feature disable -n checksumFiles

# --- Install Tailscale First ---
Write-Verbose "Installing Tailscale..."
$tailscaleJob = Start-Job -Name "TailscaleInstall" -ScriptBlock {
    try {
        choco install -y --ignorechecksum --no-progress -q tailscale
        Write-Output "Tailscale installed successfully."
        $tailscaleConfig = "C:\Users\WDAGUtilityAccount\Desktop\USB\tailscale-config.txt"
        if (Test-Path $tailscaleConfig) {
            $authKey = Get-Content -Path $tailscaleConfig -Raw -ErrorAction Stop
            if ($authKey) {
                & "C:\Program Files\Tailscale\tailscale.exe" up --authkey "$authKey" --accept-routes --accept-dns
                $maxAttempts = 5
                $attempt = 1
                $connected = $false
                while ($attempt -le $maxAttempts -and -not $connected) {
                    Start-Sleep -Seconds 10
                    $tailscaleStatus = & "C:\Program Files\Tailscale\tailscale.exe" status
                    if ($tailscaleStatus -match "\d+\.\d+\.\d+\.\d+") {
                        $connected = $true
                        Write-Output "Tailscale connected."
                    }
                    $attempt++
                }
                if (-not $connected) { Write-Warning "Tailscale failed to connect." }
            } else {
                Write-Warning "Tailscale config empty."
            }
        } else {
            Write-Warning "Tailscale config not found."
        }
    } catch {
        Write-Error "Tailscale installation or connection failed: $_"
    }
}

# Check Tailscale job
Wait-Job -Job $tailscaleJob
Receive-Job -Job $tailscaleJob
Remove-Job -Job $tailscaleJob

# --- Install and Start Tor Browser ---
Write-Verbose "Installing Tor Browser via Chocolatey..."
$torBrowserSuccess = $false
try {
    choco install -y --ignorechecksum --no-progress -q tor-browser
    $torBrowserSuccess = $true
    Write-Output "Tor Browser installed successfully."
} catch {
    Write-Error "Error during Tor Browser install: $_"
}

# Launch Tor Browser in a parallel job
$torBrowserPath = "C:\ProgramData\chocolatey\lib\tor-browser\tools\tor-browser\Browser\firefox.exe"
if ($torBrowserSuccess -and (Test-Path $torBrowserPath)) {
    Write-Verbose "Starting Tor Browser in parallel with URLs..."
    $torBrowserJob = Start-Job -Name "TorBrowserLaunch" -ScriptBlock {
        param($path, $url1, $url2, $url3)
        try {
            Start-Process -FilePath $path -ArgumentList "-url `"$url1`" `"$url2`" `"$url3`"" -ErrorAction Stop
            Write-Output "Tor Browser launched successfully."
        } catch {
            Write-Error "Failed to launch Tor Browser: $_"
        }
    } -ArgumentList $torBrowserPath, "http://robosatsy56bwqn56qyadmcxkx767hnabg4mihxlmgyt6if5gnuxvzad.onion/", "http://tormarksq5pj5sbdxilm24xpjupsn6t5ntz2gsiiy4xufukna5eno7id.onion/counter.php?view", "http://tp7mtouwvggdlm73vimqkuq7727a4ebrv4vf4cnk6lfg4fatxa6p2ryd.onion/inbox"
} else {
    Write-Warning "Tor Browser executable not found at $torBrowserPath or installation failed."
}

# --- Parallel Task Blocks ---
Write-Verbose "Running parallel tasks..."

# Task 1: Suppress Windows Updates
$updateSuppressionJob = Start-Job -Name "UpdateSuppression" -ScriptBlock {
    Write-Verbose "Suppressing Windows Updates..."
    try {
        Stop-Service -Name "wuauserv" -Force -ErrorAction Stop
        Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction Stop
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $wuPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 1 -Type DWord -Force -ErrorAction Stop
        $storePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        if (-not (Test-Path $storePath)) { New-Item -Path $storePath -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $storePath -Name "AutoDownload" -Value 2 -Type DWord -Force -ErrorAction Stop
        Write-Output "Windows Updates suppressed."
    } catch {
        Write-Error "Failed to suppress updates: $_"
    }
}

# Task 2: Windows Activation with TSforge
$activationJob = Start-Job -Name "WindowsActivation" -ScriptBlock {
    $tsforgePath = "C:\Users\WDAGUtilityAccount\Desktop\USB\TSforge.exe"
    Write-Verbose "Checking Windows activation..."
    if (Test-Path $tsforgePath) {
        $sppsvcStatus = sc query sppsvc | Select-String "STATE"
        if ($sppsvcStatus -match "RUNNING") {
            Write-Verbose "sppsvc running. Attempting activation..."
            try {
                Start-Process -FilePath $tsforgePath -ArgumentList "/kms4k" -NoNewWindow -Wait -ErrorAction Stop
                $activationStatus = cscript //nologo "C:\Windows\System32\slmgr.vbs" /xpr
                Write-Output "Activation Status: $activationStatus"
            } catch {
                Write-Error "Activation failed: $_"
            }
        } else {
            Write-Warning "sppsvc stopped. Skipping activation."
        }
    } else {
        Write-Warning "TSforge.exe not found at $tsforgePath."
    }
}

# Task 3: Debloat Windows Sandbox
$debloatJob = Start-Job -Name "Debloat" -ScriptBlock {
    Write-Verbose "Debloating Windows Sandbox..."
    $appsToRemove = @(
        "Microsoft.WindowsAlarms", "Microsoft.WindowsCalculator", "Microsoft.WindowsCamera",
        "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal", "Microsoft.People", "Microsoft.SkypeApp",
        "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo"
    )
    foreach ($app in $appsToRemove) {
        try {
            Get-AppxPackage -Name $app -AllUsers -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
            Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction Stop
        } catch {
            Write-Warning "Failed to remove app ${app}: $_"
        }
    }
    $featuresToDisable = @("WindowsMediaPlayer", "MediaPlayback")
    foreach ($feature in $featuresToDisable) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop
        } catch {
            Write-Warning "Failed to disable feature ${feature}: $_"
        }
    }
    Write-Output "Debloat complete!"
}

# Task 4: Install Remaining Chocolatey Packages
$chocoPackagesJob = Start-Job -Name "ChocoPackages" -ScriptBlock {
    Write-Verbose "Installing additional Chocolatey packages..."
    $packages = @(
        "Windows-Optimize-Debloat",
        "Windows-Optimize-Harden-Debloat",
        "veracrypt",
        "open-shell",
        "notepadplusplus",
        "qbittorrent",
        "7zip",
        "keepassxc",
        "sysinternals"
    )
    Write-Verbose "Packages to install: $packages"
    foreach ($package in $packages) {
        try {
            Write-Verbose "Installing package: $package"
            $arguments = "install -y --ignorechecksum --force --no-progress $package"
            $process = Start-Process -FilePath "choco" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
            Write-Output "Installed $package successfully."
            } else {
                Write-Error "Failed to install ${package}. Exit code: $($process.ExitCode)"
            }
        } catch {
            Write-Error "Failed to install ${package}: $_"
        }
    }
}

# --- Sequential Tasks (Dependent on Prior Installs) ---

# Configure Open-Shell (depends on chocoPackagesJob)
Wait-Job $chocoPackagesJob
Write-Verbose "Configuring Open-Shell..."
$openShellPath = "C:\Program Files\Open-Shell"
$explorerSettingsXml = "C:\Users\WDAGUtilityAccount\Desktop\USB\Open-Shell Explorer settings.xml"
$menuSettingsXml = "C:\Users\WDAGUtilityAccount\Desktop\USB\Open-Shell Menu Settings.xml"
if (Test-Path $explorerSettingsXml) {
    try {
        Start-Process -FilePath "$openShellPath\ClassicExplorerSettings.exe" -ArgumentList "-xml `"$explorerSettingsXml`"" -NoNewWindow -Wait -ErrorAction Stop
        Write-Output "Open-Shell Explorer settings applied."
    } catch {
        Write-Error "Failed to apply Explorer settings: $_"
    }
}
if (Test-Path $menuSettingsXml) {
    try {
        Start-Process -FilePath "$openShellPath\StartMenu.exe" -ArgumentList "-xml `"$menuSettingsXml`"" -NoNewWindow -Wait -ErrorAction Stop
        Stop-Process -Name "StartMenu" -Force -ErrorAction Ignore
        Start-Sleep -Seconds 2
        Start-Process -FilePath "$openShellPath\StartMenu.exe" -NoNewWindow -ErrorAction Stop
        Write-Output "Open-Shell configured and restarted."
    } catch {
        Write-Error "Failed to configure Open-Shell: $_"
    }
}

# Configure Process Explorer (depends on chocoPackagesJob)
Write-Verbose "Configuring Process Explorer..."
try {
    $procExpPath = "C:\ProgramData\chocolatey\lib\procexp\tools\procexp64.exe"
    if (Test-Path $procExpPath) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\TaskManager" -Name "Debugger" -Value $procExpPath -Force -ErrorAction Stop
        Write-Output "Process Explorer set to replace Task Manager."
    }
} catch {
    Write-Error "Failed to configure Process Explorer: $_"
}

# Configure Taskbar, Explorer, and Remove Watermark
Write-Verbose "Configuring taskbar, Explorer, and removing watermark..."
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force -ErrorAction Stop
    $feedsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
    if (-not (Test-Path $feedsPath)) { New-Item -Path $feedsPath -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $feedsPath -Name "ShellFeedsTaskbarViewMode" -Value 2 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path $feedsPath -Name "IsFeedsAvailable" -Value 0 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -Type DWord -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_MinMFU" -Value 0 -Type DWord -Force -ErrorAction Stop
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\Defaults" -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags" -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\Shell\BagMRU" -Recurse -Force -ErrorAction Ignore
    $streamsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams"
    if (-not (Test-Path $streamsPath)) { New-Item -Path $streamsPath -Force -ErrorAction Stop | Out-Null }
    Set-ItemProperty -Path $streamsPath -Name "Settings" -Value ([byte[]](0x08,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00)) -Type Binary -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation" -Name "Manual" -Value 1 -Force -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Value 0 -Force -ErrorAction Stop
    Write-Output "Taskbar, Explorer, and watermark configured."
} catch {
    Write-Error "Failed to configure settings: $_"
}

# Restart Explorer
Write-Verbose "Restarting Explorer..."
try {
    Stop-Process -Name "explorer" -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    Start-Process -FilePath "explorer.exe" -Verb RunAs -ErrorAction Stop
    Write-Output "Explorer restarted."
} catch {
    Write-Error "Failed to restart Explorer: $_"
}

# --- Mount VeraCrypt Container ---
Write-Verbose "Checking for VeraCrypt container..."
$usbFolder = "C:\Users\WDAGUtilityAccount\Desktop\USB"
$containerPath = Join-Path $usbFolder "container"
$keyFilePath = Join-Path $usbFolder "KeypassXC.keyx"
$veraCryptPath = "C:\Program Files\VeraCrypt\VeraCrypt.exe"

if (Test-Path $containerPath) {
    if (Test-Path $veraCryptPath) {
        try {
            $arguments = "/volume $containerPath /letter Q /quit"
            if (Test-Path $keyFilePath) {
                $arguments = "/volume $containerPath /letter Q /keyfile $keyFilePath /quit"
                Write-Verbose "Mounting VeraCrypt container with key file..."
            } else {
                Write-Warning "Key file KeypassXC.keyx not found at $keyFilePath. Mounting without key file."
            }
            Start-Process -FilePath $veraCryptPath -ArgumentList $arguments -NoNewWindow -Wait -ErrorAction Stop
            Write-Output "VeraCrypt container mounted successfully on Q:."
        } catch {
            Write-Error "Failed to mount VeraCrypt container: $_"
        }
    } else {
        Write-Warning "VeraCrypt not found at $veraCryptPath."
    }
} else {
    Write-Warning "Container file not found at $containerPath."
}

# --- Install Programs from Installs Folder (Parallelized) ---
Write-Verbose "Installing programs from Installs folder in parallel..."
$installsFolder = "C:\Users\WDAGUtilityAccount\Desktop\USB\Installs"
$installJobs = @()

if (Test-Path $installsFolder) {
    $installers = Get-ChildItem -Path $installsFolder -File | Where-Object { $_.Extension -eq ".exe" -or $_.Extension -eq ".msi" }
    $maxConcurrentJobs = 4

    foreach ($installer in $installers) {
        $installerPath = $installer.FullName
        $installJobs += Start-Job -Name "Install_$($installer.BaseName)" -ScriptBlock {
            param($path, $ext)
            try {
                if ($ext -eq ".exe") {
                    $silentSwitches = @("/silent", "/S", "/quiet", "/q")
                    $success = $false
                    foreach ($switch in $silentSwitches) {
                        $process = Start-Process -FilePath $path -ArgumentList $switch -NoNewWindow -Wait -PassThru -ErrorAction Stop
                        if ($process.ExitCode -eq 0) {
                            $success = $true
                            Write-Output "Installed $(Split-Path $path -Leaf) successfully."
                            break
                        }
                    }
                    if (-not $success) { Write-Error "Failed to install $(Split-Path $path -Leaf) silently." }
                } elseif ($ext -eq ".msi") {
                    $arguments = "/i `"$path`" /quiet /norestart"
                    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -ErrorAction Stop
                    if ($process.ExitCode -ne 0) { Write-Error "Failed to install $(Split-Path $path -Leaf). Exit code: $($process.ExitCode)" }
                    Write-Output "Installed $(Split-Path $path -Leaf) successfully."
                }
            } catch {
                Write-Error "Error installing $(Split-Path $path -Leaf): $_"
            }
        } -ArgumentList $installerPath, $installer.Extension

        while ((Get-Job -State Running).Count -ge $maxConcurrentJobs) {
            Start-Sleep -Seconds 1
        }
    }
} else {
    Write-Warning "Installs folder not found."
}

# Wait for installation jobs
if ($installJobs) {
    Write-Verbose "Waiting for installations to complete..."
    Wait-Job -Job $installJobs
    foreach ($job in $installJobs) {
        Receive-Job -Job $job
    }
    Remove-Job -Job $installJobs
}

# Wait for other background jobs
Write-Verbose "Waiting for remaining background tasks to complete..."
$backgroundJobs = @($updateSuppressionJob, $activationJob, $debloatJob, $chocoPackagesJob, $torBrowserJob)
foreach ($job in $backgroundJobs) {
    if ($job) {
        Wait-Job -Job $job
        Receive-Job -Job $job
        Remove-Job -Job $job
    }
}

Write-Output "Setup complete!"

# Keep the window open
pause

# Stop transcription if enabled
if ($enableLogging -and (Get-Command Stop-Transcript -ErrorAction SilentlyContinue)) {
    try {
        Stop-Transcript -ErrorAction Stop
        Write-Verbose "Logging stopped."
    } catch {
        Write-Error "Failed to stop transcript: $_"
    }
}