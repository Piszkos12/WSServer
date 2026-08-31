unit WSServer;

interface

uses
  System.SysUtils, System.StrUtils, System.Hash, System.NetEncoding, System.Win.ScktComp;

const
  ctOpenedForHTTP = 0;
  ctOpenedForWS = 1;

  HTTP_EOL: string = #13#10;

  WebSocketMagicString = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

  wsFIN: Byte = $80;
  wsMASKED: Byte = $80;

  wsOpcodeContinuation = $00;
  wsOpcodeText = $01;
  wsOpcodeBinary = $02;
  wsOpcodeClose = $08;
  wsOpcodePing = $09;
  wsOpcodePong = $0A;

  DefaultMaxFrameSize: Int64 = 16 * 1024 * 1024; // 16 MB safety cap

type
  TConnectionData = class(TObject)
    Constructor Create;
  private
    Data: Pointer;
    ConnectionType: Integer;
    Buffer: TBytes;
    FragmentBuffer: TBytes;
    FragmentIsText: Boolean;
    SecWebSocketAcceptKey: string;
    SecWebSocketKey: string;
    SecWebSocketVersion: string;
    HttpMethod: string;
    Path: string;
    GotRequestLine: Boolean;
    HasUpgradeHeader: Boolean;
    HasConnectionUpgrade: Boolean;
  end;

  TOnClientConnect = Procedure(var Socket: TCustomWinSocket) of object;
  TOnClientDisconnect = Procedure(var Socket: TCustomWinSocket) of object;
  TOnClientSwitchProtocol = Procedure(var Socket: TCustomWinSocket; SecWebSocketAcceptKey, SecWebSocketKey,
    SecWebSocketVersion, Path: string) of object;
  TOnClientFrameReceived = Procedure(var Socket: TCustomWinSocket; Frame: string) of object;
  TOnClientBinaryFrameReceived = Procedure(var Socket: TCustomWinSocket; Data: TBytes) of object;

  TWSServer = class(TObject)
  private
    fPort: Integer;
    fSocket: TServerSocket;
    fMaxFrameSize: Int64;
    fOnClientFrameReceived: TOnClientFrameReceived;
    fOnClientBinaryFrameReceived: TOnClientBinaryFrameReceived;
    fOnClientConnect: TOnClientConnect;
    fOnClientDisconnect: TOnClientDisconnect;
    fOnClientSwitchProtocol: TOnClientSwitchProtocol;
    Procedure ClientSocketConnect(Sender: TObject; Socket: TCustomWinSocket);
    Procedure ClientSocketDisconnect(Sender: TObject; Socket: TCustomWinSocket);
    Procedure ClientSocketRead(Sender: TObject; Socket: TCustomWinSocket);
    Procedure CheckForData(var Socket: TCustomWinSocket);
    Procedure ProcessHTTPRequest(var Socket: TCustomWinSocket);
    Procedure ProcessWSFrame(var Socket: TCustomWinSocket);
    Procedure BroadcastRaw(const Sealed: AnsiString);
    Function Seal(const Payload: TBytes; OpCode: Byte): TBytes;
  public
    Constructor Create;
    Destructor Destroy; Override;
    Procedure SetPort(aPort: Integer);
    Procedure StartServer;
    Procedure StopServer;
    Procedure Send(var Socket: TCustomWinSocket; FrameText: string); overload;
    Procedure Send(var Socket: TCustomWinSocket; Data: TBytes); overload;
    Procedure Broadcast(FrameText: string); overload;
    Procedure Broadcast(Data: TBytes); overload;
    Property OnClientConnect: TOnClientConnect read fOnClientConnect write fOnClientConnect;
    Property OnClientDisconnect: TOnClientDisconnect read fOnClientDisconnect write fOnClientDisconnect;
    Property OnClientSwitchProtocol: TOnClientSwitchProtocol read fOnClientSwitchProtocol write fOnClientSwitchProtocol;
    Property OnClientFrameReceived: TOnClientFrameReceived read fOnClientFrameReceived write fOnClientFrameReceived;
    Property OnClientBinaryFrameReceived: TOnClientBinaryFrameReceived read fOnClientBinaryFrameReceived
      write fOnClientBinaryFrameReceived;
    Property MaxFrameSize: Int64 read fMaxFrameSize write fMaxFrameSize;
  end;

implementation

// Raw byte-for-byte conversions for the ScktComp wire boundary (SendText/ReceiveText are AnsiString-typed
// there because the component predates Unicode Delphi - it never interprets the bytes as text).
function BytesToRawAnsiString(const B: TBytes): AnsiString;
begin
  SetLength(Result, Length(B));
  if Length(B) > 0 then
    Move(B[0], Result[1], Length(B));
end;

function RawAnsiStringToBytes(const S: AnsiString): TBytes;
begin
  SetLength(Result, Length(S));
  if Length(S) > 0 then
    Move(S[1], Result[0], Length(S));
end;

function ConcatBytes(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

// Returns the 0-based index of the CR in the next CRLF sequence, or -1 if none is buffered yet.
function FindCRLF(const B: TBytes): Integer;
var
  i: Integer;
begin
  Result := -1;
  for i := 0 to Length(B) - 2 do
    if (B[i] = 13) and (B[i + 1] = 10) then
    begin
      Result := i;
      Exit;
    end;
end;

Constructor TConnectionData.Create;
begin
  ConnectionType := ctOpenedForHTTP;
end;

Constructor TWSServer.Create;
begin
  fSocket := TServerSocket.Create(nil);
  fSocket.OnClientConnect := ClientSocketConnect;
  fSocket.OnClientDisconnect := ClientSocketDisconnect;
  fSocket.OnClientRead := ClientSocketRead;
  fMaxFrameSize := DefaultMaxFrameSize;
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
var
  Conn: TConnectionData;
begin
  Conn := TConnectionData(Socket.Data);
  Conn.Buffer := ConcatBytes(Conn.Buffer, RawAnsiStringToBytes(Socket.ReceiveText));
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
  Conn: TConnectionData;
  line: string;
  eolPos: Integer;
begin
  Conn := TConnectionData(Socket.Data);
  while True do
  begin
    eolPos := FindCRLF(Conn.Buffer);
    if eolPos < 0 then
      Exit; // wait for more data to arrive

    line := TEncoding.ASCII.GetString(Conn.Buffer, 0, eolPos);
    Conn.Buffer := Copy(Conn.Buffer, eolPos + 2, Length(Conn.Buffer) - eolPos - 2);

    if not Conn.GotRequestLine then
    begin
      Conn.GotRequestLine := True;
      Conn.HttpMethod := UpperCase(Trim(ExtractWord(1, line, [' '])));
      Conn.Path := Trim(ExtractWord(2, line, [' ']));
      Continue;
    end;

    if SameText(Copy(line, 1, 8), 'Upgrade:') and ContainsText(line, 'websocket') then
      Conn.HasUpgradeHeader := True;

    if SameText(Copy(line, 1, 11), 'Connection:') and ContainsText(line, 'Upgrade') then
      Conn.HasConnectionUpgrade := True;

    if SameText(Copy(line, 1, 18), 'Sec-WebSocket-Key:') then
      Conn.SecWebSocketKey := Trim(Copy(line, 19, MaxInt));

    if SameText(Copy(line, 1, 22), 'Sec-WebSocket-Version:') then
      Conn.SecWebSocketVersion := Trim(Copy(line, 23, MaxInt));

    if line = '' then
    begin
      // Blank line -> end of headers. Validate this is really a websocket upgrade request.
      if (Conn.HttpMethod <> 'GET') or (not Conn.HasUpgradeHeader) or (not Conn.HasConnectionUpgrade) or
        (Conn.SecWebSocketKey = '') then
      begin
        Socket.SendText(AnsiString('HTTP/1.1 400 Bad Request' + HTTP_EOL + HTTP_EOL));
        Socket.Close;
        Exit;
      end;

      Conn.ConnectionType := ctOpenedForWS;

      Conn.SecWebSocketAcceptKey := TNetEncoding.Base64String.EncodeBytesToString(
        THashSHA1.GetHashBytes(Conn.SecWebSocketKey + WebSocketMagicString));

      Socket.SendText(AnsiString('HTTP/1.1 101 Switching Protocols' + HTTP_EOL + 'Upgrade: websocket' + HTTP_EOL +
        'Connection: Upgrade' + HTTP_EOL + 'Sec-WebSocket-Accept: ' + Conn.SecWebSocketAcceptKey + HTTP_EOL +
        HTTP_EOL));

      if Assigned(fOnClientSwitchProtocol) then
        fOnClientSwitchProtocol(Socket, Conn.SecWebSocketAcceptKey, Conn.SecWebSocketKey, Conn.SecWebSocketVersion,
          Conn.Path);

      // The client may have pipelined a WS frame right after the handshake in the same packet.
      if Length(Conn.Buffer) > 0 then
        ProcessWSFrame(Socket);
      Exit;
    end;
  end;
end;

Procedure TWSServer.ProcessWSFrame(var Socket: TCustomWinSocket);
var
  Conn: TConnectionData;
  OPCODE: Byte;
  LastFrame, Masked: Boolean;
  FrameSizeBits: Byte;
  FrameSize64: Int64;
  PayloadLen, BaseHeaderSize, TotalHeaderSize, MaskOffset, PayloadOffset: Integer;
  Mask: array [0 .. 3] of Byte;
  Payload: TBytes;
  i: Integer;
begin
  Conn := TConnectionData(Socket.Data);

  while Length(Conn.Buffer) >= 2 do
  begin
    LastFrame := ((Conn.Buffer[0] and wsFIN) = wsFIN);
    OPCODE := Conn.Buffer[0] and $0F;
    Masked := ((Conn.Buffer[1] and wsMASKED) = wsMASKED);
    FrameSizeBits := Conn.Buffer[1] and $7F;

    BaseHeaderSize := 2;
    if FrameSizeBits = 126 then
    begin
      if Length(Conn.Buffer) < 4 then
        Exit; // wait for the length bytes to arrive
      FrameSize64 := (Conn.Buffer[2] shl 8) or Conn.Buffer[3];
      BaseHeaderSize := 4;
    end
    else if FrameSizeBits = 127 then
    begin
      if Length(Conn.Buffer) < 10 then
        Exit; // wait for the length bytes to arrive
      FrameSize64 := 0;
      for i := 2 to 9 do
        FrameSize64 := (FrameSize64 shl 8) or Int64(Conn.Buffer[i]);
      BaseHeaderSize := 10;
    end
    else
      FrameSize64 := FrameSizeBits;

    if (FrameSize64 < 0) or (FrameSize64 > fMaxFrameSize) then
    begin
      // Bogus or oversized frame - refuse to allocate for it
      Socket.Close;
      Exit;
    end;
    PayloadLen := Integer(FrameSize64);

    MaskOffset := BaseHeaderSize;
    TotalHeaderSize := BaseHeaderSize;
    if Masked then
      Inc(TotalHeaderSize, 4);
    PayloadOffset := TotalHeaderSize;

    if Length(Conn.Buffer) < TotalHeaderSize + PayloadLen then
      Exit; // frame not fully received yet, wait for more data

    if not Masked then
    begin
      // RFC 6455: all client-to-server frames MUST be masked
      Socket.Close;
      Exit;
    end;

    for i := 0 to 3 do
      Mask[i] := Conn.Buffer[MaskOffset + i];

    SetLength(Payload, PayloadLen);
    for i := 0 to PayloadLen - 1 do
      Payload[i] := Conn.Buffer[PayloadOffset + i] xor Mask[i mod 4];

    Conn.Buffer := Copy(Conn.Buffer, TotalHeaderSize + PayloadLen, Length(Conn.Buffer) - TotalHeaderSize - PayloadLen);

    case OPCODE of
      wsOpcodeContinuation:
        begin
          Conn.FragmentBuffer := ConcatBytes(Conn.FragmentBuffer, Payload);
          if LastFrame then
          begin
            if Conn.FragmentIsText then
            begin
              if Assigned(OnClientFrameReceived) then
                OnClientFrameReceived(Socket, TEncoding.UTF8.GetString(Conn.FragmentBuffer));
            end
            else if Assigned(OnClientBinaryFrameReceived) then
              OnClientBinaryFrameReceived(Socket, Conn.FragmentBuffer);
            Conn.FragmentBuffer := nil;
          end;
        end;
      wsOpcodeText:
        begin
          if LastFrame then
          begin
            if Assigned(OnClientFrameReceived) then
              OnClientFrameReceived(Socket, TEncoding.UTF8.GetString(Payload));
          end
          else
          begin
            Conn.FragmentIsText := True;
            Conn.FragmentBuffer := Payload;
          end;
        end;
      wsOpcodeBinary:
        begin
          if LastFrame then
          begin
            if Assigned(OnClientBinaryFrameReceived) then
              OnClientBinaryFrameReceived(Socket, Payload);
          end
          else
          begin
            Conn.FragmentIsText := False;
            Conn.FragmentBuffer := Payload;
          end;
        end;
      wsOpcodeClose:
        begin
          try
            Socket.SendText(BytesToRawAnsiString(Seal(nil, wsOpcodeClose)));
          except
            ;
          end;
          Socket.Close;
          Exit;
        end;
      wsOpcodePing:
        begin
          try
            Socket.SendText(BytesToRawAnsiString(Seal(Payload, wsOpcodePong)));
          except
            ;
          end;
        end;
      wsOpcodePong:
        ; // keepalive acknowledgement, nothing to do
    end;
  end;
end;

Function TWSServer.Seal(const Payload: TBytes; OpCode: Byte): TBytes;
var
  HeaderLen, PayloadLen: Integer;
  PayloadLengthWord: Word;
  PayloadLength64: UInt64;
  i: Integer;
begin
  PayloadLen := Length(Payload);
  if PayloadLen < 126 then
  begin
    HeaderLen := 2;
    SetLength(Result, HeaderLen + PayloadLen);
    Result[0] := wsFIN or OpCode;
    Result[1] := Byte(PayloadLen);
  end
  else if PayloadLen < 65536 then
  begin
    HeaderLen := 4;
    SetLength(Result, HeaderLen + PayloadLen);
    Result[0] := wsFIN or OpCode;
    Result[1] := $7E; // 126 -> 16 bit extended length follows
    PayloadLengthWord := PayloadLen;
    Result[2] := Hi(PayloadLengthWord);
    Result[3] := Lo(PayloadLengthWord);
  end
  else
  begin
    HeaderLen := 10;
    SetLength(Result, HeaderLen + PayloadLen);
    Result[0] := wsFIN or OpCode;
    Result[1] := $7F; // 127 -> 64 bit extended length follows
    PayloadLength64 := UInt64(PayloadLen);
    for i := 0 to 7 do
      Result[2 + i] := Byte(PayloadLength64 shr ((7 - i) * 8));
  end;
  if PayloadLen > 0 then
    Move(Payload[0], Result[HeaderLen], PayloadLen);
end;

Procedure TWSServer.Send(var Socket: TCustomWinSocket; FrameText: string);
begin
  if not Assigned(Socket) then
    Exit;
  try
    Socket.SendText(BytesToRawAnsiString(Seal(TEncoding.UTF8.GetBytes(FrameText), wsOpcodeText)));
  except
    ; // socket may already have been closed by the peer
  end;
end;

Procedure TWSServer.Send(var Socket: TCustomWinSocket; Data: TBytes);
begin
  if not Assigned(Socket) then
    Exit;
  try
    Socket.SendText(BytesToRawAnsiString(Seal(Data, wsOpcodeBinary)));
  except
    ; // socket may already have been closed by the peer
  end;
end;

Procedure TWSServer.BroadcastRaw(const Sealed: AnsiString);
var
  i: Integer;
begin
  fSocket.Socket.Lock;
  try
    for i := 0 to fSocket.Socket.ActiveConnections - 1 do
    begin
      try
        fSocket.Socket.Connections[i].SendText(Sealed);
      except
        ; // socket may already have been closed by the peer
      end;
    end;
  finally
    fSocket.Socket.Unlock;
  end;
end;

Procedure TWSServer.Broadcast(FrameText: string);
begin
  BroadcastRaw(BytesToRawAnsiString(Seal(TEncoding.UTF8.GetBytes(FrameText), wsOpcodeText)));
end;

Procedure TWSServer.Broadcast(Data: TBytes);
begin
  BroadcastRaw(BytesToRawAnsiString(Seal(Data, wsOpcodeBinary)));
end;

end.
