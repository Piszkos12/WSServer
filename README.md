# WSServer
## Simple WebSocket server unit for Delphi / Object Pascal

### How to use?

Add WSServer to your uses list:
```
uses WSServer;
```

Declare WSServer:
```
var WSServer:TWSServer;
```

In your code, init and destroy the WSServer:
```
procedure DoFantastic;
begin
  WSServer := TWSServer.Create;
  WSServer.SetPort(88);
  WSServer.StartServer;
  WSServer.OnClientFrameReceived := MyFrameReceived;
  WSServer.OnClientConnect := MyConnect;
  WSServer.OnClientDisconnect := MyDisconnect;
  WSServer.OnClientSwitchProtocol := MySwitchProtocoll;
end;

Procedure LetTheFantasticOver;
begin
  WSServer.StopServer;
  WSServer.Free;
end;
```

And define event handlers:
```
Procedure MyConnect(var Socket: TCustomWinSocket);
begin
  // Connected
  MySocket := Socket;
end;

Procedure MyDisconnect(var Socket: TCustomWinSocket);
begin
  // Disconnected
end;

Procedure MySwitchProtocoll(var Socket: TCustomWinSocket; SecWebSocketAcceptKey, SecWebSocketKey,
    SecWebSocketVersion, Path: string);
begin
  // Switching protocol
  // Sec-WebSocket-AcceptKey = SecWebSocketAcceptKey
  //       Sec-WebSocket-Key = SecWebSocketKey
  //   Sec-WebSocket-Version = SecWebSocketVersion
  //                    Path = requested path, e.g. "/chat"
end;

Procedure MyFrameReceived(var Socket: TCustomWinSocket; Frame: string);
begin
  // Frame contains a text message, decoded from UTF-8 to a normal Unicode string
end;

Procedure MyBinaryFrameReceived(var Socket: TCustomWinSocket; Data: TBytes);
begin
  // Data contains a binary message as raw bytes
end;
```

Sending frame over websocket:
```
procedure DoSendSomeText;
begin
  WSServer.Send(MySocket, 'Text for send');       // text frame (string, UTF-8 on the wire)
  // WSServer.Send(MySocket, MyBinaryData);       // binary frame (TBytes)
end;
```

Broadcasting to every connected client:
```
procedure DoBroadcastSomeText;
begin
  WSServer.Broadcast('Text for everyone');        // text frame
  // WSServer.Broadcast(MyBinaryData);            // binary frame (TBytes)
end;
```

Notes:
- The public API uses plain Unicode `string` for text and `TBytes` for binary data - no `AnsiString` anywhere except internally, right at the `TCustomWinSocket.SendText`/`ReceiveText` boundary (which is `AnsiString`-typed because that VCL component predates Unicode Delphi and only ever treats it as a raw byte buffer).
- Text frames are UTF-8 on the wire, per the WebSocket spec.
- Ping frames are answered with Pong automatically; Close frames are acknowledged and the socket is closed.
- Fragmented messages (continuation frames) are reassembled before `OnClientFrameReceived` / `OnClientBinaryFrameReceived` fires.
- Non-websocket / malformed HTTP requests get a `400 Bad Request` instead of being upgraded.
- `WSServer.MaxFrameSize` (default 16 MB) caps the accepted payload size per frame.
- Depends only on `System.SysUtils`, `System.StrUtils`, `System.Hash`, `System.NetEncoding` and `System.Win.ScktComp` - all standard RTL/VCL units, no third-party packages.
