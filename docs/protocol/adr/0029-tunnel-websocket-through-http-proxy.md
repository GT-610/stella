# ADR 0029: Tunnel secure WebSocket relay through an explicit HTTP proxy

- Status: Accepted
- Date: 2026-09-02

## Context

The secure WebSocket relay carrier is intended to work in networks that permit
HTTPS only through an explicit proxy. The first implementation connects its TCP
socket directly to the relay, so a client in a proxy-only campus or enterprise
network cannot reach the carrier even when the proxy permits WebSocket traffic.

Proxy configuration belongs to the client network environment. Publishing it
through the authenticated controller would disclose a local routing detail,
would not help another node, and could incorrectly apply one site's proxy to a
different site.

## Decision

The Windows client configuration may contain one optional numeric
`secure_websocket_proxy` socket address. It affects only the secure WebSocket
relay carrier. Direct UDP, TURN UDP, TURN TCP, and TURN TLS keep their existing
connection behavior and fallback order.

When configured, the client opens TCP to the proxy and sends one HTTP/1.1
`CONNECT` request whose request target and `Host` field are the canonical relay
WebSocket authority. The request carries no Stella relay authorization and no
proxy credentials. The first reference profile does not persist or synthesize
proxy authentication material; a `407` response fails closed like any other
non-success response.

The response header is read under the normal connection deadline, is limited to
16 KiB and 64 fields, and must be a complete HTTP/1.0 or HTTP/1.1 response with
a 2xx status. Obsolete folding, malformed fields, informational responses,
redirects, authentication challenges, response bodies, and bytes following the
header are rejected. Diagnostics expose only the proxy address, status code,
and stable failure class, never header values.

After CONNECT succeeds, the client performs the normal TLS 1.3 handshake inside
the tunnel and validates the relay name and configured Web PKI/SPKI trust exactly
as it does for a direct connection. Only then does it send the authenticated
WebSocket upgrade. The proxy therefore never receives TURN credentials or
Stella datagrams in plaintext.

## Consequences

An unauthenticated explicit HTTP proxy can carry Stella through the same
outbound TCP 443 policy used by ordinary HTTPS without changing controller or
relay configuration. The proxy learns the relay authority, client address,
timing, and byte volume, but cannot inspect or modify authenticated relay or L2
content without failing TLS validation.

Proxies requiring Basic, Digest, NTLM, Kerberos, or interactive authentication
remain unsupported by the first profile. Adding operating-system credential
integration later requires a separate decision because it changes secret
storage, UI, and impersonation boundaries.
