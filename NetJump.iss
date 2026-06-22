; NetJump installer (Inno Setup 6).
; Build with:  ISCC.exe NetJump.iss
; Output:      .\Installer\NetJump-Setup-<version>.exe
;
; Inno Setup automatically creates unins000.exe inside {app} at install time and registers it in
; Apps & Features. The single Setup.exe IS the distributable; the uninstaller is deposited during
; install. No separate uninstaller .exe to ship.

#define MyAppName        "NetJump"
#define MyAppVersion     "1.0.1"
#define MyAppPublisher   "NetJump"
#define MyAppURL         "https://github.com/thecontentstudios/NetJump"
#define MyAppExeName     "Run-NetJump.bat"
#define MyAppIcon        "netjump.ico"

[Setup]
; Stable AppId so upgrades replace prior installs (DO NOT regenerate per build).
AppId={{3E31C26F-EF10-4474-BBD6-F0E42805E2D0}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
AppContact=
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
; Per-user by default so no UAC at install time; user can pick per-machine at install via the
; PrivilegesRequiredOverridesAllowed dialog. {autopf} resolves to %LocalAppData%\Programs\NetJump
; (per-user) OR %ProgramFiles%\NetJump (per-machine) based on the elevation choice.
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
DisableProgramGroupPage=yes
LicenseFile=
InfoBeforeFile=
InfoAfterFile=
OutputDir=Installer
OutputBaseFilename=NetJump-Setup-{#MyAppVersion}
; Icons: the installer .exe itself uses netjump.ico; Apps & Features shows the same icon for
; the uninstall entry; shortcuts use the bundled .ico (no system-file dependency).
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppIcon}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Windows 10 1809+ (minimum supported by the WPF + pktmon parts NetJump relies on).
MinVersion=10.0.17763
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Restart Manager: if NetJump is running during install or uninstall, ask it to close cleanly.
CloseApplications=force
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Desktop shortcut is opt-in (matches the Chrome / Discord / VS Code convention).
; Start Menu shortcut is NOT a Task - it's unconditional (every installed program should have one).
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; Core
Source: "NetJump-Dashboard.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "Run-NetJump.bat";       DestDir: "{app}"; Flags: ignoreversion
Source: "README.md";             DestDir: "{app}"; Flags: ignoreversion
Source: "{#MyAppIcon}";          DestDir: "{app}"; Flags: ignoreversion
; Legacy scripts (kept for reference per README; superseded by NetJump-Dashboard.ps1)
Source: "NetJump-Scan.ps1";      DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "NetJump-Monitor.ps1";   DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
; Start Menu - unconditional. Every installed program should have a Start Menu entry.
Name: "{group}\{#MyAppName}";              Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "Network + security diagnostic HUD"; IconFilename: "{app}\{#MyAppIcon}"
Name: "{group}\{#MyAppName} README";       Filename: "{app}\README.md";       WorkingDir: "{app}"; Comment: "Open the NetJump README in your default Markdown viewer"
Name: "{group}\Uninstall {#MyAppName}";    Filename: "{uninstallexe}";        Comment: "Remove NetJump from this computer"
; Desktop - opt-in via Tasks.
Name: "{autodesktop}\{#MyAppName}";        Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "Network + security diagnostic HUD"; IconFilename: "{app}\{#MyAppIcon}"; Tasks: desktopicon

[Run]
; Offer to launch NetJump immediately after install.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; WorkingDir: "{app}"; Flags: postinstall shellexec nowait skipifsilent

[Code]
// Block install on systems without Windows PowerShell 5.1+ (every Win10 1607+ has it).
function InitializeSetup(): Boolean;
var
  PsPath: String;
begin
  PsPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Result := FileExists(PsPath);
  if not Result then
    MsgBox('Windows PowerShell 5.1 was not found at the expected location:'#13#10 +
           PsPath + #13#10#13#10 +
           'NetJump requires Windows PowerShell 5.1 (ships with Windows 10 1607+ / 11).' + #13#10 +
           'Install cannot continue.', mbCriticalError, MB_OK);
end;

// After uninstall finishes removing files, ask whether to also delete the Reports\ data folder.
// Reports\ contains the audit log, ledger, threat-intel cache, session history, flap dossiers -
// destroying it by accident would lose forensic evidence, so we ALWAYS prompt and default to No.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ReportsPath: String;
  AppRoot: String;
  Response: Integer;
begin
  if CurUninstallStep = usPostUninstall then begin
    ReportsPath := ExpandConstant('{app}\Reports');
    AppRoot     := ExpandConstant('{app}');
    if DirExists(ReportsPath) then begin
      Response := MsgBox(
        'Also delete the NetJump data folder?' + #13#10 + #13#10 +
        ReportsPath + #13#10 + #13#10 +
        'It contains:' + #13#10 +
        '  - Audit log (every fix that ran, with timestamps)' + #13#10 +
        '  - Session history and flap dossiers' + #13#10 +
        '  - Threat-intel cache (IPv4 + IPv6 ranges)' + #13#10 +
        '  - Vulnerable-driver list cache' + #13#10 +
        '  - Scheduled-scan digests' + #13#10 + #13#10 +
        'Click No to keep it for forensic / archival purposes - you can delete it manually later.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2);
      if Response = IDYES then begin
        DelTree(ReportsPath, True, True, True);
        // Now that Reports\ is gone, try to remove {app} itself if it's empty (Inno usually
        // leaves it because Reports\ kept it populated). DelTree on an empty dir is fine.
        if DirExists(AppRoot) then
          RemoveDir(AppRoot);
      end;
    end;
  end;
end;
