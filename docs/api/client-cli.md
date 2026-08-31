# Windows client CLI

`stella-client` owns one protected node identity, strict controller trust, the
durable desired-network list, and the Windows TAP/data-plane runtime. Commands
use `--config client.toml` unless another path is supplied.

## Initialize

```powershell
stella-client --config C:\Stella\client.toml init `
  --controller 203.0.113.10:44900 `
  --tls-name controller.example.net `
  --controller-id 0123456789abcdef0123456789abcdef `
  --spki-pin sha256/BASE64_SHA256_SPKI_DIGEST= `
  --display-name "Gaming PC" `
  --udp-bind 0.0.0.0:45100
```

`init` creates the configuration and `secrets/node.pk8` with create-new
semantics. On Windows, identity inheritance is disabled and only the current
account and `LocalSystem` receive access. Existing targets are never replaced;
failed initialization removes only targets created by that invocation.

Successful output contains the lowercase node ID and configuration path. The
configuration initially has no network entries. Enrollment and join tokens are
never accepted by `init` and are never written to disk.

The remaining commands will use ephemeral token arguments:

```powershell
stella-client --config C:\Stella\client.toml join --network <id> --token <token> --tap-adapter "Stella LAN"
stella-client --config C:\Stella\client.toml run
stella-client --config C:\Stella\client.toml status
stella-client --config C:\Stella\client.toml leave --network <id>
```

`join` persists only the network ID and TAP adapter after the controller has
accepted membership. `leave` stops forwarding before requesting removal and
deletes durable intent only after authoritative success. `status` never prints
credentials or private key material.
