program NexusClient;

{
  Cliente desktop de referência do Nexus Defense AI (FMX).
  Consome a API REST do motor Python (ver docs/api.md). Abra este .dpr no
  Delphi (10.x+) — o IDE gera o .dproj e o NexusClient.res automaticamente.
}

uses
  System.StartUpCopy,
  FMX.Forms,
  uMainForm in 'uMainForm.pas',
  uNexusApi in 'uNexusApi.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
