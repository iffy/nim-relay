# Copyright (c) 2021 Matt Haggard. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import ws
import asyncdispatch
import asynchttpserver
import protocols/netstring
import ./proto
import ./stringproto
import logging

type
  WSClient = ref object
    ws: WebSocket

proc sendEvent*(c: WSClient, ev: RelayEvent)

type
  RelayServer = ref object
    relay: Relay[WSClient]

proc newRelayServer*(): RelayServer =
  new(result)
  result.relay = newRelay[WSClient]()

proc sendEvent*(c: WSClient, ev: RelayEvent) =
  asyncCheck c.ws.send(nsencode(dumps(ev)))

proc newWSClient(ws: WebSocket): WSClient =
  new(result)
  result.ws = ws

proc handleRequest*(server: RelayServer, req: Request) {.async, gcsafe.} =
  ## Handle a relay server websocket request.  See `proc listen` for
  ## an example of how to use this.
  try:
    var ws = await newWebSocket(req)
    var wsclient = newWSClient(ws)
    let client_id = server.relay.add(wsclient)
    var decoder = newNetstringDecoder()
    while ws.readyState == Open:
      let packet = await ws.receiveStrPacket()
      decoder.consume(packet)
      while decoder.hasMessage():
        let cmd = loadsRelayCommand(decoder.nextMessage())
        # echo "server: cmd: ", $cmd
        server.relay.handleCommand(client_id, cmd)
    discard server.relay.removeClient(client_id)
  except WebSocketError:
    error "server: socket closed: " & getCurrentExceptionMsg()
    await req.respond(Http400, "Bad request")

proc listen*(s: RelayServer, port = 9001.Port, address = "") =
  ## Start the default relay server on the given port.
  var server = newAsyncHttpServer()
  proc cb(req: Request) {.async, gcsafe.} =
    if req.url.path == "/relay":
      await s.handleRequest(req)
    else:
      await req.respond(Http404, "Not found")
  asyncCheck server.serve(port, cb, address = address)


