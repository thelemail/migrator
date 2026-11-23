#ifndef AppVersion
  #error Pass /DAppVersion=<version>
#endif
#ifndef SourceDir
  #error Pass /DSourceDir=<folder with thelemail-migrator.exe and migrator-engine.exe>
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif

[Setup]
AppId={{7FAC705E-A533-4FEF-A7D5-3062E03F1DB3}
AppName=Thelemail Migrator
AppVersion={#AppVersion}
AppVerName=Thelemail Migrator {#AppVersion}
AppPublisher=Thelemail
AppPublisherURL=https://thelemail.com
AppSupportURL=https://github.com/thelemail/migrator
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Thelemail Migrator
DefaultGroupName=Thelemail Migrator
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=Thelemail-Migrator-{#AppVersion}-windows-x86_64-setup
UninstallDisplayName=Thelemail Migrator
UninstallDisplayIcon={app}\thelemail-migrator.exe
CloseApplications=yes
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\thelemail-migrator.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\migrator-engine.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Thelemail Migrator"; Filename: "{app}\thelemail-migrator.exe"
Name: "{autodesktop}\Thelemail Migrator"; Filename: "{app}\thelemail-migrator.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\thelemail-migrator.exe"; Description: "{cm:LaunchProgram,Thelemail Migrator}"; Flags: nowait postinstall skipifsilent
