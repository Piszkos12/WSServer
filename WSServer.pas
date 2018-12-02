unit WSServer;

interface

uses Windows, SysUtils, ScktComp, StrUtils, EncdDecd, Hash;

const
  ctOpenedForHTTP = 0;
  ctOpenedForWS = 1;

  HTTP_EOL = #13#10;

  WebSocketMagicString = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

type
  TConnectionData = class(TObject)
    ConnectionType: Integer;
    Buffer: AnsiString;
    SecWebSocketAcceptKey: AnsiString;
    SecWebSocketKey: AnsiString;
    SecWebSocketVersion: AnsiString;
    Constructor Create;
  end;

  TOnClientConnect = Procedure(var Socket: TCustomWinSocket) of object;
  TOnClientDisconnect = Procedure(var Socket: TCustomWinSocket) of object;
  TOnClientSwitchProtocol = Procedure(var Socket: TCustomWinSocket;
      SecWebSocketAcceptKey, SecWebSocketKey, SecWebSocketVersion: AnsiString) of object;
  TOnClientFrameReceived = Procedure(var Socket: TCustomWinSocket; Frame: AnsiString) of object;

  TWSServer = class(TObject)
  private
    fPort: Integer;
    fSocket: TServerSocket;
    fOnClientFrameReceived: TOnClientFrameReceived;
    fOnClientConnect: TOnClientConnect;
    fOnClientDisconnect: TOnClientDisconnect;
    fOnClientSwitchProtocol: TOnClientSwitchProtocol;
    Procedure ClientSocketConnect(Sender: TObject; Socket: TCustomWinSocket);
    Procedure ClientSocketDisconnect(Sender: TObject; Socket: TCustomWinSocket);
    Procedure ClientSocketRead(Sender: TObject; Socket: TCustomWinSocket);
    Procedure CheckForData(var Socket: TCustomWinSocket);
    Procedure ProcessHTTPRequest(var Socket: TCustomWinSocket);
    Procedure ProcessWSFrame(var Socket: TCustomWinSocket);
    Function HexToString(s: AnsiString): TBytes;
    Function Seal(str: AnsiString): AnsiString;
  public
    Constructor Create;
    Destructor Destroy; Override;
    Procedure SetPort(aPort: Integer);
    Procedure StartServer;
    Procedure StopServer;
    Procedure Send(var Socket: TCustomWinSocket; FrameText: AnsiString);
    Property OnClientConnect: TOnClientConnect read fOnClientConnect write fOnClientConnect;
    Property OnClientDisconnect: TOnClientDisconnect read fOnClientDisconnect write fOnClientDisconnect;
    Property OnClientSwitchProtocol: TOnClientSwitchProtocol read fOnClientSwitchProtocol write fOnClientSwitchProtocol;
    Property OnClientFrameReceived: TOnClientFrameReceived read fOnClientFrameReceived write fOnClientFrameReceived;
  end;

implementation

Constructor TConnectionData.Create;
begin
  ConnectionType := ctOpenedForHTTP;
  Buffer := '';
end;

Constructor TWSServer.Create;
begin
  fSocket := TServerSocket.Create(nil);
  fSocket.OnClientConnect := ClientSocketConnect;
  fSocket.OnClientDisconnect := ClientSocketDisconnect;
  fSocket.OnClientRead := ClientSocketRead;
  OutputDebugString('WSSERVER:Created');
end;

Destructor TWSServer.Destroy;
begin
  OutputDebugString('WSSERVER:Destroy');
  StopServer;
  fSocket.Free;
  Inherited;
end;

procedure TWSServer.SetPort(aPort: Integer);
begin
  OutputDebugString(PWideChar('WSSERVER:Port set to ' + fPort.ToString));
  if aPort <= 0 then
    raise Exception.Create('Websocket error: Wrong port number.');
  if fSocket.Active then
    raise Exception.Create('Websocket error: Cannot change port when server is active.');
  fPort := aPort;
end;

procedure TWSServer.StartServer;
begin
  OutputDebugString('WSSERVER:StartServer');
  if fPort <= 0 then
    raise Exception.Create('Websocket error: Port was not set.');
  fSocket.Port := fPort;
  fSocket.Active := True;
end;

procedure TWSServer.StopServer;
begin
  OutputDebugString('WSSERVER:StopServer');
  fSocket.Active := False;
end;

procedure TWSServer.ClientSocketConnect(Sender: TObject; Socket: TCustomWinSocket);
var
  Connection: TConnectionData;
begin
  OutputDebugString('WSSERVER:ClientSocketConnect');
  Connection := TConnectionData.Create;
  Connection.ConnectionType := ctOpenedForHTTP;
  Socket.Data := Connection;
  if Assigned(OnClientConnect) then
    OnClientConnect(Socket);
end;

procedure TWSServer.ClientSocketDisconnect(Sender: TObject; Socket: TCustomWinSocket);
begin
  OutputDebugString('WSSERVER:ClientSocketDisconnect');
  if Assigned(OnClientDisconnect) then
    OnClientDisconnect(Socket);
  TConnectionData(Socket.Data).Free;
end;

procedure TWSServer.ClientSocketRead(Sender: TObject; Socket: TCustomWinSocket);
begin
  OutputDebugString('WSSERVER:ClientSocketRead');
  TConnectionData(Socket.Data).Buffer := TConnectionData(Socket.Data).Buffer + Socket.ReceiveText;
  CheckForData(Socket);
end;

Procedure TWSServer.CheckForData(var Socket: TCustomWinSocket);
begin
  OutputDebugString('WSSERVER:CheckForData');
  if TConnectionData(Socket.Data).ConnectionType = ctOpenedForHTTP then
    ProcessHTTPRequest(Socket)
  else // ctOpenedForWS
    ProcessWSFrame(Socket)
end;

Procedure TWSServer.ProcessHTTPRequest(var Socket: TCustomWinSocket);
var
  line: AnsiString;
begin
  while pos(HTTP_EOL, TConnectionData(Socket.Data).Buffer) > 0 do
  begin
    line := LeftStr(TConnectionData(Socket.Data).Buffer, pos(HTTP_EOL, TConnectionData(Socket.Data).Buffer) - 1);
    TConnectionData(Socket.Data).Buffer := RightStr(TConnectionData(Socket.Data).Buffer,
        Length(TConnectionData(Socket.Data).Buffer) - pos(HTTP_EOL, TConnectionData(Socket.Data).Buffer) - 1);
    OutputDebugString(PWideChar('WSSERVER:HTTPParser:' + line));
    if LeftStr(line, 18) = 'Sec-WebSocket-Key:' then
    begin
      TConnectionData(Socket.Data).SecWebSocketKey := RightStr(line, Length(line) - 19);
      OutputDebugString(PWideChar('WSSERVER:Sec-WebSocket-Key:' + TConnectionData(Socket.Data).SecWebSocketKey));
    end;
    if LeftStr(line, 22) = 'Sec-WebSocket-Version:' then
    begin
      TConnectionData(Socket.Data).SecWebSocketVersion := RightStr(line, Length(line) - 23);
      OutputDebugString(PWideChar('WSSERVER:Sec-WebSocket-Version:' + TConnectionData(Socket.Data)
          .SecWebSocketVersion));
    end;
    if line = '' then
    begin
      TConnectionData(Socket.Data).Buffer := '';
      TConnectionData(Socket.Data).ConnectionType := ctOpenedForWS;

      TConnectionData(Socket.Data).SecWebSocketAcceptKey :=
          EncodeBase64(HexToString(THashSHA1.GetHashString(TConnectionData(Socket.Data).SecWebSocketKey +
          WebSocketMagicString)),
          Length(HexToString(THashSHA1.GetHashString(TConnectionData(Socket.Data).SecWebSocketKey +
          WebSocketMagicString))));

      Socket.SendText('HTTP/1.1 101 Switching Protocols' + HTTP_EOL);
      Socket.SendText('Upgrade: websocket' + HTTP_EOL);
      Socket.SendText('Connection: Upgrade' + HTTP_EOL);
      Socket.SendText('Sec-WebSocket-Accept: ' + TConnectionData(Socket.Data).SecWebSocketAcceptKey + HTTP_EOL);
      Socket.SendText(HTTP_EOL);

      if Assigned(fOnClientSwitchProtocol) then
        fOnClientSwitchProtocol(Socket, TConnectionData(Socket.Data).SecWebSocketAcceptKey,
            TConnectionData(Socket.Data).SecWebSocketKey, TConnectionData(Socket.Data).SecWebSocketVersion);

      OutputDebugString('WSSERVER:Socket mode activated');
    end;
  end;
end;

Procedure TWSServer.ProcessWSFrame(var Socket: TCustomWinSocket);
const
  _fin: Byte = $80;
  _opcode_TextFrame = $01;
  _opcode_Close = $08;
  _masked: Byte = $80;
  transformed_octet: Byte = 7;
  masking_key_octet: Byte = 3;
  unmasked_octec: Byte = 3;
var
  FrameSize: Integer;
  LastFrame: Boolean;
  OPCODE: Byte;
  Masked: Boolean;
  Mask: LongWord;
  Frame: AnsiString;
  i: Integer;
begin
  if Length(TConnectionData(Socket.Data).Buffer) < 2 then
  begin
    raise Exception.Create('Websocket error: Invalid frame size:' +
        IntToStr(Length(TConnectionData(Socket.Data).Buffer)));
    Exit;
  end;
  LastFrame := ((Byte(TConnectionData(Socket.Data).Buffer[1]) and _fin) = _fin);
  OPCODE := Byte(TConnectionData(Socket.Data).Buffer[1]) and $0F;
  FrameSize := Byte(TConnectionData(Socket.Data).Buffer[2]) and $7F;
  if OPCODE = _opcode_Close then
  begin
    Socket.Close;
    Exit;
  end;
  if OPCODE = _opcode_TextFrame then
  begin
    Masked := ((Byte(TConnectionData(Socket.Data).Buffer[2]) and _masked) = _masked);
    Frame := '';
    if Masked then
    begin
      Mask := LongWord(TConnectionData(Socket.Data).Buffer[masking_key_octet]);
      for i := 0 to FrameSize - 1 do
        Frame := Frame + AnsiChar(Byte(TConnectionData(Socket.Data).Buffer[transformed_octet + i])
            xor Byte(TConnectionData(Socket.Data).Buffer[masking_key_octet + i mod 4]));
    end
    else
    begin
      for i := 0 to FrameSize - 1 do
        Frame := Frame + TConnectionData(Socket.Data).Buffer[unmasked_octec + i];
    end;
    OutputDebugString(PWideChar('WSSERVER:Frame:' + Frame));
    if Assigned(OnClientFrameReceived) then
      OnClientFrameReceived(Socket, Frame);
  end;
end;

Function TWSServer.HexToString(s: AnsiString): TBytes;
var
  i: Integer;
  astr: Array of AnsiString;
  abyte: Array of Byte;
begin
  SetLength(Result, Length(s) div 2);
  SetLength(astr, Length(s) div 2);
  SetLength(abyte, Length(s) div 2);
  for i := 0 to Length(s) div 2 - 1 do
    astr[i] := '$' + s[i * 2 + 1] + s[i * 2 + 2];
  for i := 0 to Length(astr) - 1 do
    abyte[i] := StrToInt(astr[i]);
  for i := 0 to Length(astr) - 1 do
    Result[i] := abyte[i];
  SetLength(abyte, 0);
  SetLength(astr, 0);
end;

Function TWSServer.Seal(str: AnsiString): AnsiString;
var
  Mask: LongWord;
  i: Integer;
begin
  Mask := Random(high(Mask));
  SetLength(Result, Length(str) + 2);
  Result[1] := #$81;
  Result[2] := AnsiChar(Byte(Length(str)));
  for i := 0 to Length(str) - 1 do
    Result[3 + i] := str[i + 1];
end;

Procedure TWSServer.Send(var Socket: TCustomWinSocket; FrameText: AnsiString);
begin
  Socket.SendText(Seal(FrameText));
end;

end.
