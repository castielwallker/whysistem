$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
$global:maadVersion = "2.5"

$sysConfig = @{
    SystemName       = "Maad"
    WorkgroupName    = "MaadGroup"
    SystemComment    = "Sistema otimizado"
    CPUModel         = "Intel Quantum 9999X Turbo"
    BIOSVersion      = "v9999.ROM"
    ComputerModel    = "UltimateX-2025"
    RegisteredOwner  = "Maad"
    Organization     = "Maad Corp"
    WallpaperURL     = "https://i.imgur.com/BxYaE1e.jpeg"
    WallpaperPath    = "$env:SystemRoot\Web\Wallpaper\Windows\wallpaper_custom.jpg"
    FakeAppName      = "NVIDIA Shader Cache Optimizer"
    FakePublisher    = "NVIDIA Corporation"
    UninstallKey     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NVIDIA_Cache_Optimizer"
    OSName           = "Windows 10 Professional Workstation"
    SupportPhone     = "+1 800-555-0101"
    SupportHours     = "24/7"
}

function Set-SystemWallpaper {
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($sysConfig.WallpaperURL, $sysConfig.WallpaperPath)
        
        if (Test-Path $sysConfig.WallpaperPath) {
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $sysConfig.WallpaperPath -Force
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Force  # 10 = Preencher (Stretch)
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Force
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Force  # 100% qualidade
            Start-Process -WindowStyle Hidden -FilePath "rundll32.exe" -ArgumentList "user32.dll,UpdatePerUserSystemParameters 1, True"
        }
    } catch {
        Write-Verbose "Wallpaper configuration skipped" -Verbose
    }
}

function Set-OemLogo {
    param (
        [string]$logoUrl = "https://i.imgur.com/49Uet4M.png",
        [string]$outputPath = "C:\Windows\System32\oobe\info\maad_logo.bmp"
    )
    try {
        $logoDir = Split-Path -Path $outputPath -Parent
        if (-not (Test-Path $logoDir)) {
            $null = New-Item -Path $logoDir -ItemType Directory -Force
        }
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0")
        $webClient.DownloadFile($logoUrl, $outputPath)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" `
                         -Name "Logo" `
                         -Value $outputPath `
                         -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Invoke-SystemCustomization {
    try {
        Rename-Computer -NewName $sysConfig.SystemName -Force -ErrorAction Stop
    } catch {}
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value $sysConfig.SystemComment -Force
    $wmiSystem = Get-WmiObject Win32_ComputerSystem
    $wmiSystem.Manufacturer = $sysConfig.SystemName
    $wmiSystem.Model = $sysConfig.ComputerModel
    $wmiSystem.Put() | Out-Null
    if ([Environment]::Is64BitOperatingSystem) {
        Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString" -Value $sysConfig.CPUModel
    }
    Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System" -Name "SystemBiosVersion" -Value $sysConfig.BIOSVersion -Force
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Set-ItemProperty -Path $regPath -Name "RegisteredOwner" -Value $sysConfig.RegisteredOwner
    Set-ItemProperty -Path $regPath -Name "RegisteredOrganization" -Value $sysConfig.Organization
    Set-ItemProperty -Path $regPath -Name "ProductName" -Value $sysConfig.OSName
    if (-not (Test-Path $sysConfig.UninstallKey)) {
        $null = New-Item -Path $sysConfig.UninstallKey -Force
        $installDate = (Get-Date).ToString("yyyyMMdd")
        
        $uninstallValues = @{
            "DisplayName"    = $sysConfig.FakeAppName
            "Publisher"      = $sysConfig.FakePublisher
            "InstallDate"    = $installDate
            "DisplayVersion" = "9.9.9." + (Get-Random -Minimum 1000 -Maximum 9999)
            "UninstallString" = "`"C:\Program Files\NVIDIA\ShaderCache\uninstall.exe`" /S"
            "NoModify"       = 1
            "NoRepair"       = 1
        }

        foreach ($key in $uninstallValues.Keys) {
            Set-ItemProperty -Path $sysConfig.UninstallKey -Name $key -Value $uninstallValues[$key]
        }
    }

    $oemInfo = @{
        "Manufacturer" = $sysConfig.SystemName
        "Model" = $sysConfig.ComputerModel
        "SupportHours" = $sysConfig.SupportHours
        "SupportPhone" = $sysConfig.SupportPhone
        "SupportURL" = "https://support.maad.com"
    }

    Set-OemLogo | Out-Null
    foreach ($key in $oemInfo.Keys) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name $key -Value $oemInfo[$key]
    }
}

function Test-AdminPrivileges {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

if (Test-AdminPrivileges) {
    try {
        Invoke-SystemCustomization
        Set-SystemWallpaper
        exit 0
    } catch {
        exit 1
    }
} else {
    exit 1
}
