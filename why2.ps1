$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
$global:maadVersion = "2.5"

# Variáveis personalizáveis com nomes menos óbvios
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

function Show-MaadBanner {
    Write-Host @"

    ███╗   ███╗ █████╗  █████╗ ██████╗     ██████╗ ██████╗ ██████╗ 
    ████╗ ████║██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔══██╗
    ██╔████╔██║███████║███████║██║  ██║    ██████╔╝██████╔╝██████╔╝
    ██║╚██╔╝██║██╔══██║██╔══██║██║  ██║    ██╔══██╗██╔══██╗██╔══██╗
    ██║ ╚═╝ ██║██║  ██║██║  ██║██████╔╝    ██║  ██║██║  ██║██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
    •          SYSTEM OPTIMIZATION TOOL v$maadVersion             •  
    ______________________________________________________________
"@ -ForegroundColor Cyan
}

function Set-SystemWallpaper {
    try {
        # Download assíncrono do wallpaper
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFileAsync([Uri]$sysConfig., $sysConfig.WallpaperPath)
        
        # Configurações do wallpaper (mais discreto)
        $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value $sysConfig.WallpaperPath -Force
        $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WallpaperStyle" -Value "10" -Force
        $null = New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "TileWallpaper" -Value "0" -Force
        
        # Atualização silenciosa
        Start-Process -WindowStyle Hidden -FilePath "rundll32.exe" -ArgumentList "user32.dll,UpdatePerUserSystemParameters"
    } catch {
        Write-Verbose "Wallpaper configuration skipped" -Verbose
    }
}

function Invoke-SystemCustomization {
    # 1. Computer Renaming (mais robusto)
    try {
        Rename-Computer -NewName $sysConfig.SystemName -Force -ErrorAction Stop
    } catch {
        Write-Verbose "Computer rename operation failed" -Verbose
    }

    # 2. System Description
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value $sysConfig.SystemComment -Force

    # 3. WMI Properties (mais discreto)
    $wmiSystem = Get-WmiObject Win32_ComputerSystem
    $wmiSystem.Manufacturer = $sysConfig.SystemName
    $wmiSystem.Model = $sysConfig.ComputerModel
    $wmiSystem.Put() | Out-Null

    # 4. CPU Model (compatibilidade com sistemas de 64-bit)
    if ([Environment]::Is64BitOperatingSystem) {
        $cpuPath = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        Set-ItemProperty -Path $cpuPath -Name "ProcessorNameString" -Value $sysConfig.CPUModel
    }

    # 5. BIOS Information
    Set-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System" -Name "SystemBiosVersion" -Value $sysConfig.BIOSVersion -Force

    # 6. Windows Registration Information
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Set-ItemProperty -Path $regPath -Name "RegisteredOwner" -Value $sysConfig.RegisteredOwner
    Set-ItemProperty -Path $regPath -Name "RegisteredOrganization" -Value $sysConfig.Organization
    Set-ItemProperty -Path $regPath -Name "ProductName" -Value $sysConfig.OSName

    # 7. Fake Installed Application
    if (-not (Test-Path $sysConfig.UninstallKey)) {
        $null = New-Item -Path $sysConfig.UninstallKey -Force
        $installDate = (Get-Date).AddDays(-(Get-Random -Minimum 1 -Maximum 30)).ToString("yyyyMMdd")
        
        $uninstallValues = @{
            "DisplayName"    = $sysConfig.FakeAppName
            "Publisher"      = $sysConfig.FakePublisher
            "InstallDate"    = $installDate
            "InstallLocation" = "C:\Program Files\NVIDIA\ShaderCache"
            "DisplayVersion" = "9.9.9." + (Get-Random -Minimum 1000 -Maximum 9999)
            "UninstallString" = "`"C:\Program Files\NVIDIA\ShaderCache\uninstall.exe`" /S"
            "NoModify"       = 1
            "NoRepair"       = 1
            "EstimatedSize" = 1024 * (Get-Random -Minimum 50 -Maximum 200)
        }

        foreach ($key in $uninstallValues.Keys) {
            Set-ItemProperty -Path $sysConfig.UninstallKey -Name $key -Value $uninstallValues[$key]
        }
    }

    # 8. Network Adapter Renaming (apenas adaptadores físicos)
    Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        try {
            Rename-NetAdapter -Name $_.Name -NewName "MaadNet-$((Get-Random -Maximum 999))" -ErrorAction SilentlyContinue
        } catch {}
    }

    # 9. Workgroup Join (se não estiver em domínio)
    if (-not (Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Add-Computer -WorkgroupName $sysConfig.WorkgroupName -Force -ErrorAction SilentlyContinue
    }

    # 10. OEM Information
    $oemInfo = @{
        "Manufacturer" = $sysConfig.SystemName
        "Model" = $sysConfig.ComputerModel
        "SupportHours" = $sysConfig.SupportHours
        "SupportPhone" = $sysConfig.SupportPhone
        "SupportURL" = "https://support.maad.com"
        "Logo" = "C:\Windows\System32\oobe\info\maad_logo.bmp"
    }

    foreach ($key in $oemInfo.Keys) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name $key -Value $oemInfo[$key] -ErrorAction SilentlyContinue
    }

function Set-OemLogo {
    param (
        [string]$logoUrl = "https://i.imgur.com/49Uet4M.png",  # Substitua pela URL real do Imgur
        [string]$outputPath = "C:\Windows\System32\oobe\info\maad_logo.bmp"
    )

    try {
        # Verificar/Criar diretório
        $logoDir = Split-Path -Path $outputPath -Parent
        if (-not (Test-Path $logoDir)) {
            $null = New-Item -Path $logoDir -ItemType Directory -Force -ErrorAction Stop
        }

        # Download da imagem
        Write-Verbose "Downloading OEM logo from Imgur..."
        $tempFile = [System.IO.Path]::GetTempFileName() + ".bmp"
        
        # Usando WebClient para melhor controle
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0")
        $webClient.DownloadFile($logoUrl, $tempFile)

        # Verificar se o download foi bem-sucedido
        if (-not (Test-Path $tempFile -PathType Leaf)) {
            throw "Failed to download logo file"
        }

        # Verificar se é uma imagem válida (mínima verificação)
        if ((Get-Item $tempFile).Length -lt 1KB) {
            throw "Downloaded file is too small to be a valid image"
        }

        # Converter para BMP se necessário (simplificado)
        if ((Get-Item $tempFile).Extension -ne ".bmp") {
            Write-Verbose "Converting image to BMP format..."
            $bitmap = [System.Drawing.Image]::FromFile($tempFile)
            $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
            $bitmap.Dispose()
            Remove-Item $tempFile -Force
        } else {
            Move-Item $tempFile $outputPath -Force
        }

        # Verificar permissões
        $acl = Get-Acl $outputPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Everyone", 
            "Read", 
            "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl -Path $outputPath -AclObject $acl

        # Registrar no registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" `
                         -Name "Logo" `
                         -Value $outputPath `
                         -ErrorAction SilentlyContinue

        Write-Verbose "OEM logo configured successfully"
        return $true
    }
    catch {
        Write-Verbose "Error configuring OEM logo: $_"
        # Fallback para logo padrão se disponível
        if (Test-Path "$env:SystemRoot\System32\oobe\info\logo.bmp") {
            Copy-Item "$env:SystemRoot\System32\oobe\info\logo.bmp" $outputPath -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
    finally {
        # Limpeza de arquivos temporários
        if ($tempFile -and (Test-Path $tempFile)) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# Como usar na sua função Invoke-SystemCustomization:
# Substitua a linha do Logo por:
$oemInfo = @{
    "Logo" = "C:\Windows\System32\oobe\info\maad_logo.bmp"
}
# E adicione ANTES do foreach:
$logoResult = Set-OemLogo -logoUrl "https://i.imgur.com/49Uet4M.png"  # URL real da sua imagem
if (-not $logoResult) {
    $oemInfo.Remove("Logo")  # Remove a entrada se falhar
}
    # 11. User Account Renaming (se possível)
    try {
        $currentUser = $env:USERNAME
        if ($currentUser -ne $sysConfig.SystemName) {
            Rename-LocalUser -Name $currentUser -NewName $sysConfig.SystemName -ErrorAction Stop
        }
    } catch {
        Write-Verbose "User rename operation failed" -Verbose
    }
}

function Show-CustomizationResults {
    Write-Host "`n• System customization completed successfully!" -ForegroundColor Green
    Write-Host "`n• Computer Name: $($sysConfig.SystemName)"
    Write-Host "• System Model: $($sysConfig.ComputerModel)"
    Write-Host "• Processor: $($sysConfig.CPUModel)"
    Write-Host "• BIOS Version: $($sysConfig.BIOSVersion)"
    Write-Host "• Registered Owner: $($sysConfig.RegisteredOwner)"
    Write-Host "`nSome changes may require reboot to take full effect." -ForegroundColor Yellow
}

# Verificação de admin com método mais robusto
function Test-AdminPrivileges {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# Execução principal com tratamento melhorado
if (Test-AdminPrivileges) {
    Clear-Host
    Show-MaadBanner
    
    Write-Host "`nThis script will apply system customizations." -ForegroundColor Yellow
    Write-Host "Do you want to continue? (Y/N)" -ForegroundColor Yellow
    $confirmation = Read-Host

    if ($confirmation -match '^[Yy]') {
        try {
            Invoke-SystemCustomization
            Set-SystemWallpaper
            Show-CustomizationResults
        } catch {
            Write-Host "Error during customization: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Operation cancelled by user." -ForegroundColor Red
        exit 0
    }
} else {
    Write-Host "This script requires Administrator privileges!" -ForegroundColor Red
    Start-Sleep -Seconds 3
    exit 1
}

# Saída melhorada
Write-Host "`nPress any key to exit..."
[Console]::ReadKey($true) | Out-Null
