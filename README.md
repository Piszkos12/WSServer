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
    SecWebSocketVersion: AnsiString);
begin
  // Switching protocol
  // Sec-WebSocket-AcceptKey = SecWebSocketAcceptKey
  //       Sec-WebSocket-Key = SecWebSocketKey
  //   Sec-WebSocket-Version = SecWebSocketVersion
end;

Procedure MyFrameReceived(var Socket: TCustomWinSocket; FrameText: AnsiString);
begin
  // FrameText contains the frame data in AnsiString
end;
```

Sending frame over websocket:
```
procedure DoSendSomeText;
begin
  WSServer.Send(MySocket, 'Text for send');
end;
```
