# CloudMeet host-control plugins

`mod_muc_host_transfer.lua` was recovered read-only on 2026-11-10 from the
historical 202 instance's persistent custom plugin directory. Original SHA256:
`91779945f43d4f7d7ad2cabe32f04503fb62d29ddaf410e74cfc87209b1b201c`.
The historical server was not modified. This is now the maintained source;
deployment copies must identify this repository commit and match SHA256.

The module defaults off. It requires the online JWT owner revocation gate,
authenticated HTTPS internal API endpoints, exact XMPP session bindings,
durable transfer fencing and private credential acknowledgement by the recipient.
Administrator recovery remains off. Never substitute an ordinary moderator grant.

Run executable protocol boundary tests from the repository root:

```sh
lua tests/host-transfer.lua jitsi-plugins/cloudmeet/mod_muc_host_transfer.lua
luac -p jitsi-plugins/cloudmeet/mod_muc_host_transfer.lua
```

These exercise real plugin handlers with controlled MUC/HTTP boundaries, not a
live server. Installed Android/Electron acceptance is a separate deployment gate.
