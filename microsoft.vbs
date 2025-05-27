On Error Resume Next
Set fso = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")
Set reg = GetObject("winmgmts:\\.\root\default:StdRegProv")

' Caminhos dos arquivos de status
desktop = WshShell.SpecialFolders("Desktop")
successFile = desktop & "\successfull.ini"
failFile = desktop & "\fail.ini"

' Apaga os arquivos antigos se existirem
If fso.FileExists(successFile) Then fso.DeleteFile successFile, True
If fso.FileExists(failFile) Then fso.DeleteFile failFile, True

erro = False

' --- LIMPA REGISTROS ---
keys = Array( _
    "HKCU\Software\WinRAR\ArcHistory", _
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePid1MRU", _
    "HKLM\SYSTEM\ControlSet001\Services\bam\State\UserSettings", _
    "HKLM\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", _
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers", _
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU", _
    "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist", _
    "HKCU\Software\Microsoft\Windows\ShellNoRoam", _
    "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU", _
    "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags", _
    "HKCU\Software\Microsoft\Windows\Shell\BagMRU", _
    "HKCU\Software\Microsoft\Windows\Shell\Bags", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", _
    "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}", _
    "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR", _
    "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", _
    "HKCR\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", _
    "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", _
    "HKU\.DEFAULT\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", _
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", _
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU", _
    "HKCU\Software\WinRAR\DialogEditHistory\ExtrPath", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch", _
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UFH\SHC", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll\OpenWithList", _
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView", _
    "HKLM\SYSTEM\ControlSet001\Services\bam", _
    "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU", _
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\dll", _
    "HKCU\SOFTWARE\WinRAR\ArcHistory", _
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll", _
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}", _
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}", _
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}", _
    "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}", _
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" _
)

For Each key In keys
    If Not DeleteRegistryKey(key) Then erro = True
Next

Function DeleteRegistryKey(keyPath)
    On Error Resume Next
    regHive = Split(keyPath, "\")(0)
    regPath = Replace(keyPath, regHive & "\", "")
    
    Select Case UCase(regHive)
        Case "HKCU": root = &H80000001
        Case "HKLM": root = &H80000002
        Case "HKCR": root = &H80000000
        Case "HKU" : root = &H80000003
        Case Else: Exit Function
    End Select

    reg.DeleteKey root, regPath
    If Err.Number <> 0 Then
        DeleteRegistryKey = False
        Err.Clear
    Else
        DeleteRegistryKey = True
    End If
End Function

' --- LIMPA JOURNAL ---
WshShell.Run "cmd /c fsutil usn deletejournal /D C:", 0, True

' --- FEEDBACK ---
If erro = False Then
    Set file = fso.CreateTextFile(successFile, True)
    file.WriteLine("[status]")
    file.WriteLine("result=success")
    file.Close
Else
    Set file = fso.CreateTextFile(failFile, True)
    file.WriteLine("[status]")
    file.WriteLine("result=fail")
    file.Close
End If

' --- AUTO DELETE ---
scriptPath = WScript.ScriptFullName
Set deleteSelf = fso.CreateTextFile(WScript.ScriptName & ".cmd", True)
deleteSelf.WriteLine ":Repeat"
deleteSelf.WriteLine "del """ & scriptPath & """ >nul 2>&1"
deleteSelf.WriteLine "if exist """ & scriptPath & """ goto Repeat"
deleteSelf.WriteLine "del %0"
deleteSelf.Close
WshShell.Run WScript.ScriptName & ".cmd", 0, False
