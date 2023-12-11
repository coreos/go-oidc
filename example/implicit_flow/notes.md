### Working?

Got this "working" - talks to platform_server2 - on localhost:9090/launch
  - keysets serve up correctly, yay
  - redirect dance works: plat-launch -> tool-loginInit -> plat-auth -> tool-login ✅
  - further unpack id_token - pull out claims, put name into redirect URI to content, etc.
    - like in "tool_server" -> diff lib for unpacking claims than peregrine-lti uses?


    