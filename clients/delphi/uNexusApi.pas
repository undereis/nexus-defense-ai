unit uNexusApi;

{
  Cliente REST do Nexus Defense AI (motor Python) para Delphi/FMX.

  Encapsula o acesso HTTP autenticado por token (Bearer) e a desserialização
  JSON. Contrato completo da API em docs/api.md do repositório.

  Uso:
    Api := TNexusApi.Create('http://127.0.0.1:8000', 'meu_token');
    Obj := Api.GetJson('/api/subscribers');   // chamador libera (Obj.Free)
    Msg := Api.RunBilling(True);              // ação -> string de resultado

  Compatível com Delphi 10.x+ (System.Net.HttpClient + System.JSON). Sem
  dependências externas.
}

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.NetEncoding,
  System.Net.URLClient, System.Net.HttpClient;

type
  ENexusApiError = class(Exception);

  TNexusApi = class
  private
    FBaseUrl: string;
    FToken: string;
    FHttp: THTTPClient;
    function Request(const AMethod, APath: string): TJSONObject;
  public
    constructor Create(const ABaseUrl, AToken: string);
    destructor Destroy; override;

    property BaseUrl: string read FBaseUrl write FBaseUrl;
    property Token: string read FToken write FToken;

    // Respostas como objeto JSON — o CHAMADOR é dono e deve liberar (.Free).
    function GetJson(const APath: string): TJSONObject;
    function PostJson(const APath: string): TJSONObject;

    // Ações: devolvem a string "message" da resposta.
    function BlockSubscriber(const AId, AReason: string): string;
    function UnblockSubscriber(const AId, AReason: string): string;
    function RunBilling(ADryRun: Boolean): string;
    function HealthReport: string;
  end;

implementation

constructor TNexusApi.Create(const ABaseUrl, AToken: string);
begin
  inherited Create;
  FBaseUrl := ABaseUrl;
  FToken := AToken;
  FHttp := THTTPClient.Create;
  FHttp.ConnectionTimeout := 10000;
  FHttp.ResponseTimeout := 30000;
end;

destructor TNexusApi.Destroy;
begin
  FHttp.Free;
  inherited;
end;

function TNexusApi.Request(const AMethod, APath: string): TJSONObject;
var
  LUrl: string;
  LHeaders: TNetHeaders;
  LResp: IHTTPResponse;
  LBody: string;
  LVal: TJSONValue;
begin
  LUrl := FBaseUrl.TrimRight(['/']) + APath;
  LHeaders := [TNameValuePair.Create('Authorization', 'Bearer ' + FToken)];

  if SameText(AMethod, 'GET') then
    LResp := FHttp.Get(LUrl, nil, LHeaders)
  else
    LResp := FHttp.Post(LUrl, TStream(nil), nil, LHeaders);

  LBody := LResp.ContentAsString(TEncoding.UTF8);

  if (LResp.StatusCode = 401) then
    raise ENexusApiError.Create('Token inválido ou ausente (HTTP 401).');
  if (LResp.StatusCode < 200) or (LResp.StatusCode >= 300) then
    raise ENexusApiError.CreateFmt('HTTP %d: %s',
      [LResp.StatusCode, Copy(LBody, 1, 300)]);

  LVal := TJSONObject.ParseJSONValue(LBody);
  if not (LVal is TJSONObject) then
  begin
    LVal.Free;
    raise ENexusApiError.Create('Resposta inesperada (não é objeto JSON).');
  end;
  Result := TJSONObject(LVal);
end;

function TNexusApi.GetJson(const APath: string): TJSONObject;
begin
  Result := Request('GET', APath);
end;

function TNexusApi.PostJson(const APath: string): TJSONObject;
begin
  Result := Request('POST', APath);
end;

function TNexusApi.BlockSubscriber(const AId, AReason: string): string;
var
  O: TJSONObject;
begin
  O := PostJson(Format('/api/subscribers/%s/block?reason=%s',
    [TNetEncoding.URL.Encode(AId), TNetEncoding.URL.Encode(AReason)]));
  try
    Result := O.GetValue<string>('message');
  finally
    O.Free;
  end;
end;

function TNexusApi.UnblockSubscriber(const AId, AReason: string): string;
var
  O: TJSONObject;
begin
  O := PostJson(Format('/api/subscribers/%s/unblock?reason=%s',
    [TNetEncoding.URL.Encode(AId), TNetEncoding.URL.Encode(AReason)]));
  try
    Result := O.GetValue<string>('message');
  finally
    O.Free;
  end;
end;

function TNexusApi.RunBilling(ADryRun: Boolean): string;
var
  O: TJSONObject;
  LFlag: string;
begin
  if ADryRun then LFlag := 'true' else LFlag := 'false';
  O := PostJson('/api/billing/run?dry_run=' + LFlag);
  try
    Result := O.GetValue<string>('message');
  finally
    O.Free;
  end;
end;

function TNexusApi.HealthReport: string;
var
  O: TJSONObject;
begin
  O := GetJson('/api/health');
  try
    Result := O.GetValue<string>('report');
  finally
    O.Free;
  end;
end;

end.
