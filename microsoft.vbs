On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set reg = GetObject("winmgmts:\\.\root\default:StdRegProv")

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
    DeleteRegistryKey key
Next

Sub DeleteRegistryKey(keyPath)
    On Error Resume Next
    regHive = Split(keyPath, "\")(0)
    regPath = Replace(keyPath, regHive & "\", "")
    
    Select Case UCase(regHive)
        Case "HKCU": root = &H80000001
        Case "HKLM": root = &H80000002
        Case "HKCR": root = &H80000000
        Case "HKU" : root = &H80000003
        Case Else: Exit Sub
    End Select

    reg.DeleteKey root, regPath
End Sub

' --- LIMPA JOURNAL ---
WshShell.Run "cmd /c fsutil usn deletejournal /D C:", 0, True
