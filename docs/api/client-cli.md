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

## Join

```powershell
stella-client --config C:\Stella\client.toml join `
  --network <id> `
  --token <unpadded-base64url-token> `
  --tap-adapter "Stella LAN"
```

For a node not yet enrolled with the controller, add the one-use
`--enrollment-token <unpadded-base64url-token>` argument. Both token forms must
decode to exactly 32 bytes. They remain process-local, are redacted from debug
output, and are never written to the configuration.

`join` authenticates and waits for a complete validated controller snapshot
before atomically persisting the network ID and TAP adapter. Repeating an
already accepted join may omit `--token`; repeating it with the same TAP adapter
is idempotent, while a conflicting adapter is rejected before contacting the
controller.

## Status

```powershell
stella-client --config C:\Stella\client.toml status
```

`status` is an offline command. It validates the configuration and protected
identity, then prints the derived node ID, controller address/name/ID, UDP bind,
and each desired network with its TAP adapter. It never prints SPKI pins,
credentials, private key material, or the private-key path.

The following runtime commands are implemented in later Phase 2 batches:

```powershell
stella-client --config C:\Stella\client.toml run
stella-client --config C:\Stella\client.toml leave --network <id>
```

`leave` stops forwarding before requesting removal and deletes durable intent
only after authoritative success. `status` never prints credentials or private
key material.
