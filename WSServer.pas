unit WSServer;

interface

uses
  System.SysUtils, System.Hash, System.NetEncoding, System.Win.ScktComp;

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

  DefaultMaxFrameSize: Int64 = 16 * 1024 * 1024; // 16 MB safety cap; also caps a reassembled fragmented message
  DefaultMaxHTTPHeaderSize: Integer = 8 * 1024; // 8 KB safety cap for the handshake header block

  wsCloseProtocolError: Word = 1002;
  wsCloseInvalidPayload: Word = 1007;
  wsCloseMessageTooBig: Word = 1009;

type
  TConnectionData = class(TObject)
    Constructor Create;
  private
    Data: Pointer;
    ConnectionType: Integer;
    Buffer: TBytes;
    FragmentBuffer: TBytes;
    FragmentActive: Boolean;
    FragmentIsText: Boolean;
    SecWebSocketAcceptKey: string;
    SecWebSocketKey: string;
    SecWebSocketVersion: string;
    HttpMethod: string;
    Path: string;
    GotRequestLine: Boolean;
    HasUpgradeHeader: Boolean;
    HasConnectionUpgrade: Boolean;
    HttpHeaderBytesConsumed: Integer;
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
    fMaxHTTPHeaderSize: Integer;
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
    Procedure CloseWithError(var Socket: TCustomWinSocket; StatusCode: Word);
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
    Property MaxHTTPHeaderSize: Integer read fMaxHTTPHeaderSize write fMaxHTTPHeaderSize;
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

// Returns the Index-th (1-based) space-delimited token from S, skipping repeated spaces.
function ExtractHttpToken(const S: string; Index: Integer): string;
var
  i, wordIdx, startPos: Integer;
  inWord: Boolean;
begin
  Result := '';
  wordIdx := 0;
  inWord := False;
  startPos := 1;
  for i := 1 to Length(S) do
  begin
    if S[i] = ' ' then
    begin
      if inWord then
      begin
        Inc(wordIdx);
        if wordIdx = Index then
        begin
          Result := Copy(S, startPos, i - startPos);
          Exit;
        end;
        inWord := False;
      end;
    end
    else if not inWord then
    begin
      startPos := i;
      inWord := True;
    end;
  end;
  if inWord then
  begin
    Inc(wordIdx);
    if wordIdx = Index then
      Result := Copy(S, startPos, Length(S) - startPos + 1);
  end;
end;

function ContainsTextCI(const S, SubStr: string): Boolean;
begin
  Result := Pos(UpperCase(SubStr), UpperCase(S)) > 0;
end;

// Well-formed UTF-8 byte sequence check per the Unicode Standard (Table 3-7),
// rejecting overlong encodings, surrogate halves and out-of-range code points.
function IsValidUTF8(const B: TBytes): Boolean;
var
  i, n: Integer;
  b0, b1, b2, b3: Byte;
begin
  i := 0;
  n := Length(B);
  while i < n do
  begin
    b0 := B[i];
    if b0 <= $7F then
      Inc(i)
    else if (b0 >= $C2) and (b0 <= $DF) then
    begin
      if i + 1 >= n then Exit(False);
      b1 := B[i + 1];
      if (b1 < $80) or (b1 > $BF) then Exit(False);
      Inc(i, 2);
    end
    else if (b0 = $E0) or ((b0 >= $E1) and (b0 <= $EC)) or (b0 = $ED) or ((b0 >= $EE) and (b0 <= $EF)) then
    begin
      if i + 2 >= n then Exit(False);
      b1 := B[i + 1];
      b2 := B[i + 2];
      if b0 = $E0 then
      begin
        if (b1 < $A0) or (b1 > $BF) then Exit(False);
      end
      else if b0 = $ED then
      begin
        if (b1 < $80) or (b1 > $9F) then Exit(False); // exclude UTF-16 surrogate halves
      end
      else if (b1 < $80) or (b1 > $BF) then Exit(False);
      if (b2 < $80) or (b2 > $BF) then Exit(False);
      Inc(i, 3);
    end
    else if (b0 = $F0) or ((b0 >= $F1) and (b0 <= $F3)) or (b0 = $F4) then
    begin
      if i + 3 >= n then Exit(False);
      b1 := B[i + 1];
      b2 := B[i + 2];
      b3 := B[i + 3];
      if b0 = $F0 then
      begin
        if (b1 < $90) or (b1 > $BF) then Exit(False);
      end
      else if b0 = $F4 then
      begin
        if (b1 < $80) or (b1 > $8F) then Exit(False); // exclude code points above U+10FFFF
      end
      else if (b1 < $80) or (b1 > $BF) then Exit(False);
      if (b2 < $80) or (b2 > $BF) then Exit(False);
      if (b3 < $80) or (b3 > $BF) then Exit(False);
      Inc(i, 4);
    end
    else
      Exit(False);
  end;
  Result := True;
end;

function IsValidCloseStatusCode(Code: Integer): Boolean;
begin
  Result := ((Code >= 1000) and (Code <= 1014) and (Code <> 1004) and (Code <> 1005) and (Code <> 1006)) or
    ((Code >= 3000) and (Code <= 4999));
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
  fMaxHTTPHeaderSize := DefaultMaxHTTPHeaderSize;
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
    begin
      if Conn.HttpHeaderBytesConsumed + Length(Conn.Buffer) > fMaxHTTPHeaderSize then
      begin
        Socket.SendText(AnsiString('HTTP/1.1 400 Bad Request' + HTTP_EOL + HTTP_EOL));
        Socket.Close;
      end;
      Exit; // wait for more data to arrive
    end;

    line := TEncoding.ASCII.GetString(Conn.Buffer, 0, eolPos);
    Conn.Buffer := Copy(Conn.Buffer, eolPos + 2, Length(Conn.Buffer) - eolPos - 2);
    Inc(Conn.HttpHeaderBytesConsumed, eolPos + 2);

    if Conn.HttpHeaderBytesConsumed > fMaxHTTPHeaderSize then
    begin
      Socket.SendText(AnsiString('HTTP/1.1 400 Bad Request' + HTTP_EOL + HTTP_EOL));
      Socket.Close;
      Exit;
    end;

    if not Conn.GotRequestLine then
    begin
      Conn.GotRequestLine := True;
      Conn.HttpMethod := UpperCase(Trim(ExtractHttpToken(line, 1)));
      Conn.Path := Trim(ExtractHttpToken(line, 2));
      Continue;
    end;

    if SameText(Copy(line, 1, 8), 'Upgrade:') and ContainsTextCI(line, 'websocket') then
      Conn.HasUpgradeHeader := True;

    if SameText(Copy(line, 1, 11), 'Connection:') and ContainsTextCI(line, 'Upgrade') then
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

      if Conn.SecWebSocketVersion <> '13' then
      begin
        // RFC 6455 4.4: tell the client which version(s) we do support
        Socket.SendText(AnsiString('HTTP/1.1 426 Upgrade Required' + HTTP_EOL + 'Sec-WebSocket-Version: 13' +
          HTTP_EOL + HTTP_EOL));
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
  LastFrame, Masked, IsControlFrame: Boolean;
  FrameSizeBits: Byte;
  FrameSize64: Int64;
  PayloadLen, BaseHeaderSize, TotalHeaderSize, MaskOffset, PayloadOffset: Integer;
  Mask: array [0 .. 3] of Byte;
  Payload, CloseReason: TBytes;
  CloseStatusCode: Integer;
  i: Integer;
begin
  Conn := TConnectionData(Socket.Data);

  while Length(Conn.Buffer) >= 2 do
  begin
    LastFrame := ((Conn.Buffer[0] and wsFIN) = wsFIN);
    OPCODE := Conn.Buffer[0] and $0F;
    Masked := ((Conn.Buffer[1] and wsMASKED) = wsMASKED);
    FrameSizeBits := Conn.Buffer[1] and $7F;
    IsControlFrame := OPCODE in [wsOpcodeClose, wsOpcodePing, wsOpcodePong];

    if (Conn.Buffer[0] and $70) <> 0 then
    begin
      // RSV1-3 set without a negotiated extension that defines them
      CloseWithError(Socket, wsCloseProtocolError);
      Exit;
    end;

    if not (OPCODE in [wsOpcodeContinuation, wsOpcodeText, wsOpcodeBinary, wsOpcodeClose, wsOpcodePing,
      wsOpcodePong]) then
    begin
      CloseWithError(Socket, wsCloseProtocolError);
      Exit;
    end;

    if IsControlFrame and not LastFrame then
    begin
      // Control frames must not be fragmented
      CloseWithError(Socket, wsCloseProtocolError);
      Exit;
    end;

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

    if IsControlFrame and (FrameSize64 > 125) then
    begin
      CloseWithError(Socket, wsCloseProtocolError);
      Exit;
    end;

    if (FrameSize64 < 0) or (FrameSize64 > fMaxFrameSize) then
    begin
      // Bogus or oversized frame - refuse to allocate for it
      CloseWithError(Socket, wsCloseMessageTooBig);
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
      CloseWithError(Socket, wsCloseProtocolError);
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
          if not Conn.FragmentActive then
          begin
            // Continuation frame with no message in progress
            CloseWithError(Socket, wsCloseProtocolError);
            Exit;
          end;

          Conn.FragmentBuffer := ConcatBytes(Conn.FragmentBuffer, Payload);
          if Int64(Length(Conn.FragmentBuffer)) > fMaxFrameSize then
          begin
            CloseWithError(Socket, wsCloseMessageTooBig);
            Exit;
          end;

          if LastFrame then
          begin
            if Conn.FragmentIsText then
            begin
              if not IsValidUTF8(Conn.FragmentBuffer) then
              begin
                CloseWithError(Socket, wsCloseInvalidPayload);
                Exit;
              end;
              if Assigned(OnClientFrameReceived) then
                OnClientFrameReceived(Socket, TEncoding.UTF8.GetString(Conn.FragmentBuffer));
            end
            else if Assigned(OnClientBinaryFrameReceived) then
              OnClientBinaryFrameReceived(Socket, Conn.FragmentBuffer);
            Conn.FragmentActive := False;
            Conn.FragmentBuffer := nil;
          end;
        end;
      wsOpcodeText:
        begin
          if Conn.FragmentActive then
          begin
            // A new data frame arrived while a fragmented message was still in progress
            CloseWithError(Socket, wsCloseProtocolError);
            Exit;
          end;

          if LastFrame then
          begin
            if not IsValidUTF8(Payload) then
            begin
              CloseWithError(Socket, wsCloseInvalidPayload);
              Exit;
            end;
            if Assigned(OnClientFrameReceived) then
              OnClientFrameReceived(Socket, TEncoding.UTF8.GetString(Payload));
          end
          else
          begin
            Conn.FragmentActive := True;
            Conn.FragmentIsText := True;
            Conn.FragmentBuffer := Payload;
          end;
        end;
      wsOpcodeBinary:
        begin
          if Conn.FragmentActive then
          begin
            CloseWithError(Socket, wsCloseProtocolError);
            Exit;
          end;

          if LastFrame then
          begin
            if Assigned(OnClientBinaryFrameReceived) then
              OnClientBinaryFrameReceived(Socket, Payload);
          end
          else
          begin
            Conn.FragmentActive := True;
            Conn.FragmentIsText := False;
            Conn.FragmentBuffer := Payload;
          end;
        end;
      wsOpcodeClose:
        begin
          if Length(Payload) = 1 then
          begin
            CloseWithError(Socket, wsCloseProtocolError);
            Exit;
          end;

          if Length(Payload) >= 2 then
          begin
            CloseStatusCode := (Payload[0] shl 8) or Payload[1];
            if not IsValidCloseStatusCode(CloseStatusCode) then
            begin
              CloseWithError(Socket, wsCloseProtocolError);
              Exit;
            end;
            if Length(Payload) > 2 then
            begin
              CloseReason := Copy(Payload, 2, Length(Payload) - 2);
              if not IsValidUTF8(CloseReason) then
              begin
                CloseWithError(Socket, wsCloseInvalidPayload);
                Exit;
              end;
            end;
          end;

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

Procedure TWSServer.CloseWithError(var Socket: TCustomWinSocket; StatusCode: Word);
var
  Payload: TBytes;
begin
  SetLength(Payload, 2);
  Payload[0] := Hi(StatusCode);
  Payload[1] := Lo(StatusCode);
  try
    Socket.SendText(BytesToRawAnsiString(Seal(Payload, wsOpcodeClose)));
  except
    ; // socket may already have been closed by the peer
  end;
  Socket.Close;
end;

Procedure TWSServer.BroadcastRaw(const Sealed: AnsiString);
var
  i: Integer;
  Conn: TConnectionData;
begin
  fSocket.Socket.Lock;
  try
    for i := 0 to fSocket.Socket.ActiveConnections - 1 do
    begin
      Conn := TConnectionData(fSocket.Socket.Connections[i].Data);
      if not Assigned(Conn) or (Conn.ConnectionType <> ctOpenedForWS) then
        Continue;
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
