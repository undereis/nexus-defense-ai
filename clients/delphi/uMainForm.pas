unit uMainForm;

{
  Cliente de referência (FMX) do Nexus Defense AI.

  UI construída EM CÓDIGO (sem .fmx) de propósito: fica num arquivo só, fácil de
  revisar e compilar sem o designer. É um exemplo mínimo e honesto do padrão
  "GUI Delphi como cliente fino sobre a REST API do motor Python" — uma tela
  com conexão (URL + token), botões de consulta e de ação, e um log. Um app de
  produção trocaria o Memo por grids/telas dedicadas, mas o caminho de dados
  (uNexusApi) é o mesmo.
}

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.UITypes, System.Types,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.StdCtrls, FMX.Edit,
  FMX.Memo, FMX.Layouts, FMX.Controls.Presentation, FMX.ScrollBox,
  uNexusApi;

type
  TfrmMain = class(TForm)
  private
    FBaseUrlEdit: TEdit;
    FTokenEdit: TEdit;
    FSubIdEdit: TEdit;
    FOutput: TMemo;
    FApi: TNexusApi;
    procedure BuildUi;
    function MakeButton(AParent: TFmxObject; const ACaption: string;
      AHandler: TNotifyEvent): TButton;
    function MakeLabel(AParent: TFmxObject; const AText: string): TLabel;
    procedure SyncApi;
    procedure Log(const S: string);
    // handlers
    procedure DoOverview(Sender: TObject);
    procedure DoSubscribers(Sender: TObject);
    procedure DoDevices(Sender: TObject);
    procedure DoOutages(Sender: TObject);
    procedure DoEvents(Sender: TObject);
    procedure DoHealth(Sender: TObject);
    procedure DoBlock(Sender: TObject);
    procedure DoUnblock(Sender: TObject);
    procedure DoBillingDry(Sender: TObject);
    procedure DoCheckDevices(Sender: TObject);
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

var
  frmMain: TfrmMain;

implementation

constructor TfrmMain.Create(AOwner: TComponent);
begin
  inherited CreateNew(AOwner);   // forma sem .fmx
  FApi := TNexusApi.Create('http://127.0.0.1:8000', '');
  BuildUi;
end;

destructor TfrmMain.Destroy;
begin
  FApi.Free;
  inherited;
end;

function TfrmMain.MakeButton(AParent: TFmxObject; const ACaption: string;
  AHandler: TNotifyEvent): TButton;
begin
  Result := TButton.Create(Self);
  Result.Parent := AParent;
  Result.Align := TAlignLayout.Left;
  Result.Width := 130;
  Result.Margins.Rect := RectF(4, 4, 4, 4);
  Result.Text := ACaption;
  Result.OnClick := AHandler;
end;

function TfrmMain.MakeLabel(AParent: TFmxObject; const AText: string): TLabel;
begin
  Result := TLabel.Create(Self);
  Result.Parent := AParent;
  Result.Align := TAlignLayout.Left;
  Result.Margins.Rect := RectF(6, 4, 2, 4);
  Result.Text := AText;
  Result.AutoSize := True;
end;

procedure TfrmMain.BuildUi;
var
  RowConn, RowQuery, RowAction: TLayout;
begin
  Caption := 'Nexus Defense AI — Cliente';
  Width := 980;
  Height := 640;

  // --- linha de conexão (URL + token) ---
  RowConn := TLayout.Create(Self);
  RowConn.Parent := Self;
  RowConn.Align := TAlignLayout.Top;
  RowConn.Height := 38;

  MakeLabel(RowConn, 'API:');
  FBaseUrlEdit := TEdit.Create(Self);
  FBaseUrlEdit.Parent := RowConn;
  FBaseUrlEdit.Align := TAlignLayout.Left;
  FBaseUrlEdit.Width := 280;
  FBaseUrlEdit.Margins.Rect := RectF(2, 4, 8, 4);
  FBaseUrlEdit.Text := 'http://127.0.0.1:8000';

  MakeLabel(RowConn, 'Token:');
  FTokenEdit := TEdit.Create(Self);
  FTokenEdit.Parent := RowConn;
  FTokenEdit.Align := TAlignLayout.Left;
  FTokenEdit.Width := 280;
  FTokenEdit.Margins.Rect := RectF(2, 4, 8, 4);
  FTokenEdit.Password := True;
  FTokenEdit.TextPrompt := 'NEXUS_API_TOKEN';

  // --- linha de consultas ---
  RowQuery := TLayout.Create(Self);
  RowQuery.Parent := Self;
  RowQuery.Align := TAlignLayout.Top;
  RowQuery.Height := 38;
  MakeButton(RowQuery, 'Visão geral', DoOverview);
  MakeButton(RowQuery, 'Assinantes', DoSubscribers);
  MakeButton(RowQuery, 'Equipamentos', DoDevices);
  MakeButton(RowQuery, 'Quedas', DoOutages);
  MakeButton(RowQuery, 'Eventos', DoEvents);
  MakeButton(RowQuery, 'Autodiagnóstico', DoHealth);

  // --- linha de ações ---
  RowAction := TLayout.Create(Self);
  RowAction.Parent := Self;
  RowAction.Align := TAlignLayout.Top;
  RowAction.Height := 38;
  MakeLabel(RowAction, 'Assinante:');
  FSubIdEdit := TEdit.Create(Self);
  FSubIdEdit.Parent := RowAction;
  FSubIdEdit.Align := TAlignLayout.Left;
  FSubIdEdit.Width := 120;
  FSubIdEdit.Margins.Rect := RectF(2, 4, 8, 4);
  FSubIdEdit.TextPrompt := 'id';
  MakeButton(RowAction, 'Bloquear', DoBlock);
  MakeButton(RowAction, 'Desbloquear', DoUnblock);
  MakeButton(RowAction, 'Cobrança (dry-run)', DoBillingDry);
  MakeButton(RowAction, 'Checar equip.', DoCheckDevices);

  // --- saída ---
  FOutput := TMemo.Create(Self);
  FOutput.Parent := Self;
  FOutput.Align := TAlignLayout.Client;
  FOutput.Margins.Rect := RectF(6, 6, 6, 6);
  FOutput.ReadOnly := True;
  Log('Pronto. Informe a URL da API e o token, e use os botões.');
end;

procedure TfrmMain.SyncApi;
begin
  FApi.BaseUrl := FBaseUrlEdit.Text;
  FApi.Token := FTokenEdit.Text;
end;

procedure TfrmMain.Log(const S: string);
begin
  FOutput.Lines.Add(S);
  FOutput.GoToTextEnd;
end;

procedure TfrmMain.DoOverview(Sender: TObject);
var
  O: TJSONObject;
begin
  SyncApi;
  try
    O := FApi.GetJson('/api/overview');
    try
      Log('=== Visão geral ===');
      Log(O.Format(2));
    finally
      O.Free;
    end;
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoSubscribers(Sender: TObject);
var
  O: TJSONObject;
  A: TJSONArray;
  V: TJSONValue;
  S: TJSONObject;
begin
  SyncApi;
  try
    O := FApi.GetJson('/api/subscribers');
    try
      A := O.GetValue('subscribers') as TJSONArray;
      Log(Format('=== Assinantes (%d) ===', [A.Count]));
      for V in A do
      begin
        S := V as TJSONObject;
        Log(Format('  [%s] %s  %s  conexao=%s  fatura=%s (%dd)',
          [S.GetValue<string>('id'), S.GetValue<string>('name'),
           S.GetValue<string>('ip'), S.GetValue<string>('status'),
           S.GetValue<string>('invoice_status'),
           S.GetValue<Integer>('days_overdue')]));
      end;
    finally
      O.Free;
    end;
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoDevices(Sender: TObject);
var
  O: TJSONObject;
  A: TJSONArray;
  V: TJSONValue;
  D: TJSONObject;
begin
  SyncApi;
  try
    O := FApi.GetJson('/api/devices');
    try
      A := O.GetValue('devices') as TJSONArray;
      Log(Format('=== Equipamentos (%d) ===', [A.Count]));
      for V in A do
      begin
        D := V as TJSONObject;
        Log(Format('  [%s] %s  %s  (%s)  estado=%s',
          [D.GetValue<string>('id'), D.GetValue<string>('name'),
           D.GetValue<string>('ip'), D.GetValue<string>('type'),
           D.GetValue<string>('status')]));
      end;
    finally
      O.Free;
    end;
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoOutages(Sender: TObject);
var
  O: TJSONObject;
  A: TJSONArray;
  V: TJSONValue;
  Q: TJSONObject;
begin
  SyncApi;
  try
    O := FApi.GetJson('/api/outages');
    try
      A := O.GetValue('outages') as TJSONArray;
      Log(Format('=== Quedas abertas (%d) ===', [A.Count]));
      for V in A do
      begin
        Q := V as TJSONObject;
        Log(Format('  %s  %s  - %s  (desde %s)',
          [Q.GetValue<string>('name'), Q.GetValue<string>('ip'),
           Q.GetValue<string>('reason'), Q.GetValue<string>('opened_at')]));
      end;
    finally
      O.Free;
    end;
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoEvents(Sender: TObject);
var
  O: TJSONObject;
  A: TJSONArray;
  V: TJSONValue;
  Ev: TJSONObject;
begin
  SyncApi;
  try
    O := FApi.GetJson('/api/events?hours=24');
    try
      A := O.GetValue('events') as TJSONArray;
      Log(Format('=== Eventos 24h (%d) ===', [A.Count]));
      for V in A do
      begin
        Ev := V as TJSONObject;
        Log(Format('  %s  %s  %s  %s',
          [Ev.GetValue<string>('time'), Ev.GetValue<string>('type'),
           Ev.GetValue<string>('ip'), Ev.GetValue<string>('detail')]));
      end;
    finally
      O.Free;
    end;
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoHealth(Sender: TObject);
begin
  SyncApi;
  try
    Log('=== Autodiagnóstico ===');
    Log(FApi.HealthReport);
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoBlock(Sender: TObject);
begin
  SyncApi;
  try
    Log('> ' + FApi.BlockSubscriber(FSubIdEdit.Text, 'bloqueio via cliente Delphi'));
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoUnblock(Sender: TObject);
begin
  SyncApi;
  try
    Log('> ' + FApi.UnblockSubscriber(FSubIdEdit.Text, 'desbloqueio via cliente Delphi'));
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoBillingDry(Sender: TObject);
begin
  SyncApi;
  try
    Log('=== Ciclo de cobrança (DRY-RUN) ===');
    Log(FApi.RunBilling(True));
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

procedure TfrmMain.DoCheckDevices(Sender: TObject);
var
  O: TJSONObject;
  A: TJSONArray;
  V: TJSONValue;
begin
  SyncApi;
  try
    O := FApi.PostJson('/api/devices/check');
    try
      A := O.GetValue('transitions') as TJSONArray;
      if A.Count = 0 then
        Log('Checagem de equipamentos: sem transições.')
      else
      begin
        Log('=== Transições ===');
        for V in A do
          Log('  ' + V.Value);
      end;
    finally
      O.Free;
    end;
  except
    on E: Exception do Log('ERRO: ' + E.Message);
  end;
end;

end.
