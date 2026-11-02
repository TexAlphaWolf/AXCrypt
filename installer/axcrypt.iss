; Inno Setup script per AXCrypt.
; Compila con Inno Setup 6: apri questo file e premi "Compile", oppure da
; terminale:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\axcrypt.iss
;
; Prima di compilare, costruisci i binari:  cargo build --release
; L'output è  installer\Output\AXCrypt-Setup.exe

#define AppName "AXCrypt"
#define AppVersion "0.5.0"
#define Publisher "Tex"
#define CliExe "axcrypt.exe"
#define GuiExe "axcrypt-gui.exe"

[Setup]
AppId={{B8F2B1A4-5C3D-4E9A-9F21-AX0CRYPT0005}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Installa per l'utente corrente se non è admin, altrimenti per tutti.
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=Output
OutputBaseFilename=AXCrypt-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes

[Languages]
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Crea un'icona sul desktop (GUI)"; GroupDescription: "Icone:"
Name: "addtopath"; Description: "Aggiungi 'axcrypt' al PATH (per usarlo da terminale)"; GroupDescription: "Opzioni:"

[Files]
; I binari di release. Il percorso è relativo a questo .iss (cartella installer\),
; quindi risale alla radice del progetto e scende in target\release.
Source: "..\target\release\{#CliExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\{#GuiExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\FORMAT_SPEC.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\ARCHITECTURE.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#GuiExe}"
Name: "{group}\Disinstalla {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#GuiExe}"; Tasks: desktopicon

[Registry]
; Aggiunge {app} al PATH utente, solo se l'utente ha scelto il task e se non c'è già.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
Description: "Avvia {#AppName}"; Filename: "{app}\{#GuiExe}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
  Expanded: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Expanded := ExpandConstant(Param);
  // vero (= aggiungi) solo se il percorso non è già presente nel PATH
  Result := Pos(';' + Lowercase(Expanded) + ';', ';' + Lowercase(OrigPath) + ';') = 0;
end;
