# Variable to control logging (set to false by default)
$enableLogging = $false

# Start logging to the mapped folder if enabled
if ($enableLogging) {
    try {
        Start-Transcript -Path "C:\Users\WDAGUtilityAccount\Desktop\USB\setup-log.txt" -Append -ErrorAction Stop
    } catch {
        Write-Host "Failed to start transcript: $_"
    }
}

# Set execution policy
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# --- Install Chocolatey ---
Write-Host "Installing Chocolatey..."
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
choco feature disable -n autoUninstaller
choco feature disable -n checksumFiles

# --- Install and connect Tailscale ---
Write-Host "Installing Tailscale..."
try {
    choco install -y --ignorechecksum --no-progress -q tailscale
    $tailscaleConfig = "C:\Users\WDAGUtilityAccount\Desktop\USB\tailscale-config.txt"
    if (Test-Path $tailscaleConfig) {
        $authKey = Get-Content -Path $tailscaleConfig -Raw -ErrorAction Stop
        if ($authKey) {
            Write-Host "Tailscale config found. Attempting to connect..."
            & "C:\Program Files\Tailscale\tailscale.exe" up --authkey "$authKey" --accept-routes --accept-dns
            $maxAttempts = 3
            $attempt = 1
            $connected = $false
            while ($attempt -le $maxAttempts -and -not $connected) {
                Start-Sleep -Seconds 10
                $tailscaleStatus = & "C:\Program Files\Tailscale\tailscale.exe" status
                if ($tailscaleStatus -match "\d+\.\d+\.\d+\.\d+") {
                    $connected = $true
                    Write-Host "Tailscale connected."
                }
                $attempt++
            }
            if (-not $connected) { Write-Host "Tailscale failed to connect after $maxAttempts attempts." }
        } else {
            Write-Host "Tailscale config file is empty."
        }
    } else {
        Write-Host "Tailscale config file not found at $tailscaleConfig. Skipping automatic connection."
    }
} catch {
    Write-Host "Error during Tailscale installation or connection: $_"
}

# --- Install and Start Tor Browser ---
Write-Host "Installing Tor Browser via Chocolatey..."
$torBrowserSuccess = $false
try {
    choco install -y --ignorechecksum --no-progress -q tor-browser
    if ($LASTEXITCODE -eq 0) {
        $torBrowserSuccess = $true
        Write-Host "Tor Browser installed successfully via Chocolatey."
    } else {
        Write-Host "Chocolatey Tor Browser install failed (Exit Code: $LASTEXITCODE)."
    }
} catch {
    Write-Host "Error during Tor Browser install: $_"
}

# Launch Tor Browser in a parallel job to avoid blocking
$torBrowserPath = "C:\ProgramData\chocolatey\lib\tor-browser\tools\tor-browser\Browser\firefox.exe"
if ($torBrowserSuccess -and (Test-Path $torBrowserPath)) {
    Write-Host "Starting Tor Browser in parallel with URLs..."
    $torBrowserJob = Start-Job -ScriptBlock {
        param($path, $url1, $url2)
        try {
            Start-Process -FilePath $path -ArgumentList "-url `"$url1`" `"$url2`"" -ErrorAction Ignore
            Write-Output "Tor Browser launched successfully."
        } catch {
            Write-Output "Failed to launch Tor Browser: $_"
        }
    } -ArgumentList $torBrowserPath, "http://robosatsy56bwqn56qyadmcxkx767hnabg4mihxlmgyt6if5gnuxvzad.onion/", "http://tormarksq5pj5sbdxilm24xpjupsn6t5ntz2gsiiy4xufukna5eno7id.onion/counter.php?view"
} else {
    Write-Host "Tor Browser executable not found at $torBrowserPath or installation failed."
}

# --- Parallel Task Blocks ---
Write-Host "Running Parallel Tasks... please be patient as there is no immediate output..."

# Task 1: Suppress Windows Updates
$updateSuppressionJob = Start-Job -ScriptBlock {
    Write-Host "Suppressing Windows Updates..."
    try {
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
        Set-ItemProperty -Path $wuPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 1 -Type DWord -Force
        $storePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
        if (-not (Test-Path $storePath)) { New-Item -Path $storePath -Force | Out-Null }
        Set-ItemProperty -Path $storePath -Name "AutoDownload" -Value 2 -Type DWord -Force
        Write-Host "Windows Updates suppressed."
    } catch {
        Write-Host "Failed to suppress updates: $_"
    }
}

# Task 2: Windows Activation with TSforge (only if TSforge.exe exists)
$activationJob = Start-Job -ScriptBlock {
    $tsforgePath = "C:\Users\WDAGUtilityAccount\Desktop\USB\TSforge.exe"
    if (Test-Path $tsforgePath) {
        Write-Host "TSforge.exe found. Checking Windows activation..."
        $sppsvcStatus = sc query sppsvc | Select-String "STATE"
        if ($sppsvcStatus -match "RUNNING") {
            Write-Host "sppsvc running. Attempting activation..."
            try {
                Start-Process -FilePath $tsforgePath -ArgumentList "/kms4k" -NoNewWindow -Wait -ErrorAction Stop
                $activationStatus = cscript //nologo "C:\Windows\System32\slmgr.vbs" /xpr
                Write-Host "Activation Status: $activationStatus"
            } catch {
                Write-Host "Activation failed: $_"
            }
        } else {
            Write-Host "sppsvc stopped. Skipping activation."
        }
    } else {
        Write-Host "TSforge.exe not found at $tsforgePath. Skipping activation."
    }
}

# Task 3: Debloat Windows Sandbox
$debloatJob = Start-Job -ScriptBlock {
    Write-Host "Debloating Windows Sandbox..."
    $appsToRemove = @(
        "Microsoft.WindowsAlarms", "Microsoft.WindowsCalculator", "Microsoft.WindowsCamera",
        "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging",
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal", "Microsoft.People", "Microsoft.SkypeApp",
        "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo"
    )
    foreach ($app in $appsToRemove) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    $featuresToDisable = @("WindowsMediaPlayer", "MediaPlayback")
    foreach ($feature in $featuresToDisable) {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
    }
    Write-Host "Debloat complete!"
}

# Task 4: Install Remaining Chocolatey Packages
$chocoPackagesJob = Start-Job -ScriptBlock {
    Write-Host "Installing additional Chocolatey packages..."
    choco install -y --ignorechecksum --force --no-progress Windows-Optimize-Debloat
    choco install -y --ignorechecksum --force --no-progress Windows-Optimize-Harden-Debloat
    choco install -y --ignorechecksum --no-progress veracrypt open-shell notepadplusplus qbittorrent 7zip keepassxc sysinternals
}

# --- Sequential Tasks (Dependent on Prior Installs) ---

# Configure Open-Shell (depends on chocoPackagesJob)
Wait-Job $chocoPackagesJob
Write-Host "Configuring Open-Shell..."
$openShellPath = "C:\Program Files\Open-Shell"
$explorerSettingsXml = "C:\Users\WDAGUtilityAccount\Desktop\USB\Open-Shell Explorer settings.xml"
$menuSettingsXml = "C:\Users\WDAGUtilityAccount\Desktop\USB\Open-Shell Menu Settings.xml"
if (Test-Path $explorerSettingsXml) {
    Start-Process -FilePath "$openShellPath\ClassicExplorerSettings.exe" -ArgumentList "-xml `"$explorerSettingsXml`"" -NoNewWindow -Wait
}
if (Test-Path $menuSettingsXml) {
    Start-Process -FilePath "$openShellPath\StartMenu.exe" -ArgumentList "-xml `"$menuSettingsXml`"" -NoNewWindow -Wait
    Stop-Process -Name "StartMenu" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process -FilePath "$openShellPath\StartMenu.exe" -NoNewWindow
    Write-Host "Open-Shell configured and restarted."
}

# Configure Process Explorer (depends on chocoPackagesJob)
Write-Host "Configuring Process Explorer..."
try {
    $procExpPath = "C:\ProgramData\chocolatey\lib\procexp\tools\procexp64.exe"
    if (Test-Path $procExpPath) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\TaskManager" -Name "Debugger" -Value $procExpPath -Force
        Write-Host "Process Explorer set to replace Task Manager."
    }
} catch {
    Write-Host "Failed to configure Process Explorer: $_"
}

# Configure Taskbar, Explorer, and Remove Watermark
Write-Host "Configuring taskbar, Explorer, and removing watermark..."
try {
    # Taskbar and Search settings
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0 -Force

    # Feeds settings with permission check
    $feedsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"
    if (-not (Test-Path $feedsPath)) { 
        New-Item -Path $feedsPath -Force | Out-Null 
    }
    # Test write access to feedsPath
    try {
        # Attempt to create a temporary test property to verify write access
        Set-ItemProperty -Path $feedsPath -Name "TestPermission" -Value 0 -Type DWord -ErrorAction Stop
        Remove-ItemProperty -Path $feedsPath -Name "TestPermission" -ErrorAction SilentlyContinue
        # If write access is confirmed, apply feeds settings
    Set-ItemProperty -Path $feedsPath -Name "ShellFeedsTaskbarViewMode" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $feedsPath -Name "IsFeedsAvailable" -Value 0 -Type DWord -Force
    } catch {
        Write-Host "Warning: Insufficient permissions to modify taskbar feeds settings. Skipping feeds configuration."
    }

    # Explorer settings
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_MinMFU" -Value 0 -Type DWord -Force

    # Clean up Explorer streams and bags
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\Defaults" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\Shell\Bags" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\Shell\BagMRU" -Recurse -Force -ErrorAction SilentlyContinue
    $streamsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams"
    if (-not (Test-Path $streamsPath)) { New-Item -Path $streamsPath -Force | Out-Null }
    Set-ItemProperty -Path $streamsPath -Name "Settings" -Value ([byte[]](0x08,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00)) -Type Binary -Force

    # Activation and watermark settings
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Activation" -Name "Manual" -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Value 0 -Force
    Write-Host "Taskbar, Explorer, and watermark configured."
} catch {
    Write-Host "Failed to configure some settings: $_"
}

# Restart Explorer
Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process -FilePath "explorer.exe" -Verb RunAs -ErrorAction SilentlyContinue
Write-Host "Explorer restarted."

# --- Mount VeraCrypt Container (only if container exists) ---
Write-Host "Checking for VeraCrypt container..."
$usbFolder = "C:\Users\WDAGUtilityAccount\Desktop\USB"
$containerPath = Join-Path $usbFolder "container"
$keyFilePath = Join-Path $usbFolder "KeypassXC.keyx"
$veraCryptPath = "C:\Program Files\VeraCrypt\VeraCrypt.exe"

if (Test-Path $containerPath) {
    if (Test-Path $veraCryptPath) {
        try {
            Write-Host "Mounting VeraCrypt container to O:..."
            $arguments = "/volume $containerPath /letter O /quit"
            if (Test-Path $keyFilePath) {
                $arguments += " /keyfile $keyFilePath"
                Write-Host "Using key file $keyFilePath for mounting."
            } else {
                Write-Host "Key file not found at $keyFilePath. Attempting to mount without key file."
            }
            Start-Process -FilePath $veraCryptPath -ArgumentList $arguments -NoNewWindow -Wait -ErrorAction Stop
            Write-Host "VeraCrypt container mounted successfully on O:."
        } catch {
            Write-Host "Failed to mount VeraCrypt container: $_"
        }
    } else {
        Write-Host "VeraCrypt not found at $veraCryptPath."
    }
} else {
    Write-Host "Container file not found at $containerPath. Skipping VeraCrypt mounting."
}

# --- Install programs from installs folder (parallelized) ---
Write-Host "Installing programs from Installs folder in parallel..."
$installsFolder = "C:\Users\WDAGUtilityAccount\Desktop\USB\Installs"
$installJobs = @()

if (Test-Path $installsFolder) {
    $installers = Get-ChildItem -Path $installsFolder -File | Where-Object { $_.Extension -eq ".exe" -or $_.Extension -eq ".msi" }
    $maxConcurrentJobs = 4
    foreach ($installer in $installers) {
        $installerPath = $installer.FullName
        $installJobs += Start-Job -ScriptBlock {
            param($path, $ext)
            try {
                if ($ext -eq ".exe") {
                    $silentSwitches = @("/silent", "/S", "/quiet", "/q")
                    $success = $false
                    foreach ($switch in $silentSwitches) {
                        $process = Start-Process -FilePath $path -ArgumentList $switch -NoNewWindow -Wait -PassThru -ErrorAction Stop
                        if ($process.ExitCode -eq 0) {
                            $success = $true
                            break
                        }
                    }
                    if (-not $success) { Write-Output "Failed to install $(Split-Path $path -Leaf) silently." }
                } elseif ($ext -eq ".msi") {
                    $arguments = "/i `"$path`" /quiet /norestart"
                    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -ErrorAction Stop
                    if ($process.ExitCode -ne 0) { Write-Output "Failed to install $(Split-Path $path -Leaf). Exit code: $($process.ExitCode)" }
                }
            } catch {
                Write-Output "Error installing $(Split-Path $path -Leaf): $_"
            }
        } -ArgumentList $installerPath, $installer.Extension
        while ((Get-Job -State Running).Count -ge $maxConcurrentJobs) {
            Start-Sleep -Seconds 1
        }
    }
} else {
    Write-Host "Installs folder not found. Skipping."
}

# Wait for all installation jobs to complete
if ($installJobs) {
    Write-Host "Waiting for installations to complete..."
    Wait-Job -Job $installJobs
    foreach ($job in $installJobs) {
        Receive-Job -Job $job
    }
    Remove-Job -Job $installJobs
}

# Wait for other background jobs to complete
Write-Host "Waiting for remaining background tasks to complete..."
Wait-Job -Job $updateSuppressionJob, $activationJob, $debloatJob, $chocoPackagesJob, $torBrowserJob
Get-Job | Receive-Job

Write-Host "Setup complete! Press any key to close this window."

# Keep the window open
pause

# Stop transcription if enabled
if ($enableLogging -and (Get-Command Stop-Transcript -ErrorAction SilentlyContinue)) { Stop-Transcript }