# Copyright (c) 2021 Matt Haggard. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

# import relaypkg/relay
# import relaypkg/stringencoder

# when isMainModule:
#   import ws
#   import argparse
#   import asyncdispatch
#   import asynchttpserver
#   var server = newAsyncHttpServer()
#   proc cb(req: Request) {.async.} =
#     if req.url.path == "/relay":
#       var ws = await newWebSocket(req)
#       await ws.send("Welcome to simple echo server")
#       while ws.readyState == Open:
#         let packet = await ws.receiveStrPacket()
#         await ws.send(packet)
#     else:
#       await req.respond(Http200, "Relay Server")

#   waitFor server.serve(Port(9001), cb)
