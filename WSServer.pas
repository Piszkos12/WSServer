unit WSServer;

interface

uses Windows, SysUtils, ScktComp, StrUtils, EncdDecd, Hash;

const
  ctOpenedForHTTP = 0;
  ctOpenedForWS = 1;

  HTTP_EOL: AnsiString = #13#10;

  WebSocketMagicString = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

type
  TConnectionData = class(TObject)
    Constructor Create;
  private
    Data: Pointer;
    ConnectionType: Integer;
    Buffer: AnsiString;
    SecWebSocketAcceptKey: AnsiString;
    SecWebSocketKey: AnsiString;
    SecWebSocketVersion: AnsiString;
  end;

  TOnClientConnect = Procedure(var Socket: TCustomWinSocket) of object;
  TOnClientDisconnect = Procedure(var Socket: TCustomWinSocket) of object;
  TOnClientSwitchProtocol = Procedure(var Socket: TCustomWinSocket; SecWebSocketAcceptKey, SecWebSocketKey, SecWebSocketVersion: AnsiString) of object;
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
    Procedure Broadcast(FrameText: AnsiString);
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
end;

Destructor TWSServer.Destroy;
begin
  StopServer;
  fSocket.Free;
  Inherited;
end;

procedure TWSServer.SetPort(aPort: Integer);
begin
  if aPort <= 0 then
    raise Exception.Create('Websocket error: Wrong port number.');
  if fSocket.Active then
    raise Exception.Create('Websocket error: Cannot change port when server is active.');
  fPort := aPort;
end;

procedure TWSServer.StartServer;
begin
  if fPort <= 0 then
    raise Exception.Create('Websocket error: Port was not set.');
  fSocket.Port := fPort;
  fSocket.Active := True;
end;

procedure TWSServer.StopServer;
begin
  fSocket.Active := False;
end;

procedure TWSServer.ClientSocketConnect(Sender: TObject; Socket: TCustomWinSocket);
var
  Connection: TConnectionData;
begin
  Connection := TConnectionData.Create;
  Connection.ConnectionType := ctOpenedForHTTP;
  Socket.Data := Connection;
  if Assigned(OnClientConnect) then
    OnClientConnect(Socket);
end;

procedure TWSServer.ClientSocketDisconnect(Sender: TObject; Socket: TCustomWinSocket);
begin
  if Assigned(OnClientDisconnect) then
    OnClientDisconnect(Socket);
  TConnectionData(Socket.Data).Free;
end;

procedure TWSServer.ClientSocketRead(Sender: TObject; Socket: TCustomWinSocket);
begin
  TConnectionData(Socket.Data).Buffer := TConnectionData(Socket.Data).Buffer + Socket.ReceiveText;
  CheckForData(Socket);
end;

Procedure TWSServer.CheckForData(var Socket: TCustomWinSocket);
begin
  if TConnectionData(Socket.Data).ConnectionType = ctOpenedForHTTP then
    ProcessHTTPRequest(Socket)
  else // ctOpenedForWS
    ProcessWSFrame(Socket)
end;

Procedure TWSServer.ProcessHTTPRequest(var Socket: TCustomWinSocket);
var
  line: AnsiString;
begin
  while AnsiPos(HTTP_EOL, TConnectionData(Socket.Data).Buffer) > 0 do
  begin
    line := LeftStr(TConnectionData(Socket.Data).Buffer, pos(HTTP_EOL, TConnectionData(Socket.Data).Buffer) - 1);
    TConnectionData(Socket.Data).Buffer := RightStr(TConnectionData(Socket.Data).Buffer, Length(TConnectionData(Socket.Data).Buffer) - pos(HTTP_EOL,
      TConnectionData(Socket.Data).Buffer) - 1);
    if LeftStr(line, 18) = 'Sec-WebSocket-Key:' then
    begin
      TConnectionData(Socket.Data).SecWebSocketKey := RightStr(line, Length(line) - 19);
    end;
    if LeftStr(line, 22) = 'Sec-WebSocket-Version:' then
    begin
      TConnectionData(Socket.Data).SecWebSocketVersion := RightStr(line, Length(line) - 23);
    end;
    if line = '' then
    begin
      TConnectionData(Socket.Data).Buffer := '';
      TConnectionData(Socket.Data).ConnectionType := ctOpenedForWS;

      TConnectionData(Socket.Data).SecWebSocketAcceptKey :=
        EncodeBase64(HexToString(THashSHA1.GetHashString(TConnectionData(Socket.Data).SecWebSocketKey + WebSocketMagicString)),
        Length(HexToString(THashSHA1.GetHashString(TConnectionData(Socket.Data).SecWebSocketKey + WebSocketMagicString))));

      Socket.SendText('HTTP/1.1 101 Switching Protocols' + HTTP_EOL);
      Socket.SendText('Upgrade: websocket' + HTTP_EOL);
      Socket.SendText('Connection: Upgrade' + HTTP_EOL);
      Socket.SendText('Sec-WebSocket-Accept: ' + TConnectionData(Socket.Data).SecWebSocketAcceptKey + HTTP_EOL);
      Socket.SendText(HTTP_EOL);

      if Assigned(fOnClientSwitchProtocol) then
        fOnClientSwitchProtocol(Socket, TConnectionData(Socket.Data).SecWebSocketAcceptKey, TConnectionData(Socket.Data).SecWebSocketKey,
          TConnectionData(Socket.Data).SecWebSocketVersion);
    end;
  end;
end;

Procedure TWSServer.ProcessWSFrame(var Socket: TCustomWinSocket);
const
  _opcode_FinalFrame: Byte = $80;
  _opcode_TextFrame = $01;
  _opcode_BinaryFrame = $02;
  _opcode_Close = $08;
  _opcode_Ping = $09;
  _opcode_Pong = $0A;
  _masked: Byte = $80;

var
  OPCODE: Byte;
  LastFrame: Boolean;
  _FrameSizeBits: Byte;
  FrameSize: LongInt;
  PayLoadAddress: Integer;
  MaskAddress: Integer;
  Mask: AnsiString;
  Masked: Boolean;
  FrameText: String;
  i: Integer;
  HeaderSize: Integer;

begin
  PayLoadAddress := 7;
  MaskAddress := 3;
  HeaderSize := 2;

  if Length(TConnectionData(Socket.Data).Buffer) < 2 then
    // Too short chunk - waiting for other data
    Exit;

  LastFrame := ((Byte(TConnectionData(Socket.Data).Buffer[1]) and _opcode_FinalFrame) = _opcode_FinalFrame);
  OPCODE := Byte(TConnectionData(Socket.Data).Buffer[1]) and $0F;

  _FrameSizeBits := Byte(TConnectionData(Socket.Data).Buffer[2]) and $7F;
  if _FrameSizeBits = 126 then
  begin
    FrameSize := Word(Byte(TConnectionData(Socket.Data).Buffer[3]) * 256 + Byte(TConnectionData(Socket.Data).Buffer[4]));
    inc(MaskAddress, 2);
    inc(PayLoadAddress, 2);
    inc(HeaderSize, 2);
  end
  else if _FrameSizeBits = 127 then
  begin
    FrameSize := LongWord(Byte(TConnectionData(Socket.Data).Buffer[3]) * 256 * 256 * 256 * 256 * 256 * 256 * 256 + Byte(TConnectionData(Socket.Data).Buffer[4])
      * 256 * 256 * 256 * 256 * 256 * 256 + Byte(TConnectionData(Socket.Data).Buffer[5]) * 256 * 256 * 256 * 256 * 256 +
      Byte(TConnectionData(Socket.Data).Buffer[6]) * 256 * 256 * 256 * 256 + Byte(TConnectionData(Socket.Data).Buffer[7]) * 256 * 256 * 256 +
      Byte(TConnectionData(Socket.Data).Buffer[8]) * 256 * 256 + Byte(TConnectionData(Socket.Data).Buffer[9]) * 256 +
      Byte(TConnectionData(Socket.Data).Buffer[10]));
    inc(MaskAddress, 8);
    inc(PayLoadAddress, 8);
    inc(HeaderSize, 8);
  end
  else
    FrameSize := _FrameSizeBits;

  // if FrameSize < _HeaderShift + (TConnectionData(Socket.Data).Buffer) + 2 then
  // exit;

  if OPCODE = _opcode_Close then
  begin
    Socket.Close;
    Exit;
  end;

  if OPCODE = _opcode_Ping then
  begin
    // Socket.SendText();
    Exit;
  end;

  Masked := ((Byte(TConnectionData(Socket.Data).Buffer[2]) and _masked) = _masked);
  if Masked then
  begin
    Mask := AnsiMidStr(TConnectionData(Socket.Data).Buffer, MaskAddress, 4);
    inc(HeaderSize, 4);
  end;

  if OPCODE = _opcode_TextFrame then
  begin
    FrameText := '';
    if Masked then
    begin
      for i := 0 to FrameSize - 1 do
        FrameText := FrameText + AnsiChar(Byte(TConnectionData(Socket.Data).Buffer[PayLoadAddress + i]) xor Byte(Mask[1 + i mod 4]));

      TConnectionData(Socket.Data).Buffer := RightStr(TConnectionData(Socket.Data).Buffer, Length(TConnectionData(Socket.Data).Buffer) - FrameSize -
        HeaderSize);
    end;
    if Assigned(OnClientFrameReceived) then
      OnClientFrameReceived(Socket, FrameText);
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
  PayLoadLengthWord: Word;
  PayLoadLengthLongWord: LongWord;
  PayLoadBytes: Array [1 .. 8] of AnsiChar;
begin
  Mask := Random(high(Mask));
  if Length(str) < 126 then
  begin
    SetLength(Result, Length(str) + 2);
    Result[1] := #$81;
    Result[2] := AnsiChar(Byte(Length(str)));
    for i := 0 to Length(str) - 1 do
      Result[3 + i] := str[i + 1];
  end
  else if Length(str) < 65536 then
  begin
    SetLength(Result, Length(str) + 2 + 2);
    Result[1] := #$81;
    Result[2] := #$7E; // 126
    PayLoadLengthWord := Length(str);
    Result[3] := AnsiChar(hi(PayLoadLengthWord));
    Result[4] := AnsiChar(lo(PayLoadLengthWord));
    for i := 0 to Length(str) - 1 do
      Result[3 + 2 + i] := str[i + 1];
  end
  else
  begin
    SetLength(Result, Length(str) + 2 + 8);
    Result[1] := #$81;
    Result[2] := #$7F; // 127
    PayLoadLengthLongWord := Length(str);
    move(PayLoadLengthLongWord, PayLoadBytes, 8);
    Result[3] := PayLoadBytes[8];
    Result[4] := PayLoadBytes[7];
    Result[5] := PayLoadBytes[6];
    Result[6] := PayLoadBytes[5];
    Result[7] := PayLoadBytes[4];
    Result[8] := PayLoadBytes[3];
    Result[9] := PayLoadBytes[2];
    Result[10] := PayLoadBytes[1];
    for i := 0 to Length(str) - 1 do
      Result[3 + 8 + i] := str[i + 1];
  end;
end;

Procedure TWSServer.Send(var Socket: TCustomWinSocket; FrameText: AnsiString);
begin
  Socket.SendText(Seal(FrameText));
end;

Procedure TWSServer.Broadcast(FrameText: AnsiString);
var
  i: Integer;
begin
  fSocket.Socket.Lock;
  for i := 0 to fSocket.Socket.ActiveConnections - 1 do
  begin
    try
      fSocket.Socket.Connections[i].SendText(Seal(FrameText));
    except
      ; // Már nem van a socket mire ideértünk.
    end;
  end;
  fSocket.Socket.Lock;
end;

end.
