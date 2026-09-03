//! Strict bounded HTTP CONNECT negotiation shared by controller and relay TLS.

use std::{io::ErrorKind, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout_at, Instant},
};

const MAX_HTTP_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_HTTP_CONNECT_FIELDS: usize = 64;
const HTTP_CONNECT_READ_CHUNK_BYTES: usize = 1024;
const HTTP_HEADER_TERMINATOR: &[u8; 4] = b"\r\n\r\n";

#[derive(Debug, Error)]
pub(crate) enum HttpConnectError {
    #[error("HTTP proxy negotiation timed out")]
    Timeout,
    #[error("HTTP proxy {operation} failed")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP proxy rejected CONNECT with status {status_code}")]
    Rejected { status_code: u16 },
    #[error("HTTP proxy response is invalid: {detail}")]
    Invalid { detail: &'static str },
    #[error("HTTP proxy deadline overflowed")]
    DeadlineOverflow,
}

pub(crate) async fn negotiate_http_connect(
    stream: &mut TcpStream,
    authority: &str,
    transaction_timeout: Duration,
) -> Result<(), HttpConnectError> {
    let deadline = Instant::now()
        .checked_add(transaction_timeout)
        .ok_or(HttpConnectError::DeadlineOverflow)?;
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| HttpConnectError::Timeout)?
        .map_err(|source| HttpConnectError::Io {
            operation: "write HTTP proxy CONNECT request",
            source,
        })?;

    let mut response = Vec::with_capacity(HTTP_CONNECT_READ_CHUNK_BYTES);
    let mut chunk = [0_u8; HTTP_CONNECT_READ_CHUNK_BYTES];
    loop {
        if response.len() == MAX_HTTP_CONNECT_RESPONSE_BYTES {
            return Err(HttpConnectError::Invalid {
                detail: "header exceeds 16 KiB",
            });
        }
        let remaining = MAX_HTTP_CONNECT_RESPONSE_BYTES - response.len();
        let peek_capacity = remaining.min(chunk.len());
        let available = timeout_at(deadline, stream.peek(&mut chunk[..peek_capacity]))
            .await
            .map_err(|_| HttpConnectError::Timeout)?
            .map_err(|source| HttpConnectError::Io {
                operation: "read HTTP proxy CONNECT response",
                source,
            })?;
        if available == 0 {
            return Err(HttpConnectError::Io {
                operation: "read HTTP proxy CONNECT response",
                source: std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "proxy closed before completing the CONNECT response",
                ),
            });
        }
        let response_end = http_header_end(&response, &chunk[..available]);
        let consume = response_end.map_or(available, |end| end - response.len());
        timeout_at(deadline, stream.read_exact(&mut chunk[..consume]))
            .await
            .map_err(|_| HttpConnectError::Timeout)?
            .map_err(|source| HttpConnectError::Io {
                operation: "read HTTP proxy CONNECT response",
                source,
            })?;
        response.extend_from_slice(&chunk[..consume]);
        if response_end.is_some() {
            break;
        }
    }
    validate_http_connect_response(&response)?;

    let mut trailing = [0_u8; 1];
    match stream.try_read(&mut trailing) {
        Ok(0) => Err(HttpConnectError::Invalid {
            detail: "proxy closed the tunnel before TLS",
        }),
        Ok(_) => Err(HttpConnectError::Invalid {
            detail: "bytes follow the CONNECT response header",
        }),
        Err(source) if source.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(source) => Err(HttpConnectError::Io {
            operation: "inspect HTTP proxy CONNECT response boundary",
            source,
        }),
    }
}

fn http_header_end(response: &[u8], available: &[u8]) -> Option<usize> {
    for prefix_length in (1..HTTP_HEADER_TERMINATOR.len()).rev() {
        if response.ends_with(&HTTP_HEADER_TERMINATOR[..prefix_length])
            && available.starts_with(&HTTP_HEADER_TERMINATOR[prefix_length..])
        {
            return Some(response.len() + HTTP_HEADER_TERMINATOR.len() - prefix_length);
        }
    }
    available
        .windows(HTTP_HEADER_TERMINATOR.len())
        .position(|window| window == HTTP_HEADER_TERMINATOR)
        .map(|position| response.len() + position + HTTP_HEADER_TERMINATOR.len())
}

fn validate_http_connect_response(response: &[u8]) -> Result<(), HttpConnectError> {
    if !response.ends_with(b"\r\n\r\n") || !response.is_ascii() {
        return Err(HttpConnectError::Invalid {
            detail: "header must be complete ASCII with CRLF line endings",
        });
    }
    let text =
        std::str::from_utf8(&response[..response.len().saturating_sub(4)]).map_err(|_| {
            HttpConnectError::Invalid {
                detail: "header must be valid ASCII",
            }
        })?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(HttpConnectError::Invalid {
        detail: "status line is missing",
    })?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let status_text = status_parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || status_parts.next().is_none() {
        return Err(HttpConnectError::Invalid {
            detail: "status line must use HTTP/1.0 or HTTP/1.1",
        });
    }
    if status_text.len() != 3 || !status_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpConnectError::Invalid {
            detail: "status code must contain three decimal digits",
        });
    }
    let status_code = status_text
        .parse::<u16>()
        .map_err(|_| HttpConnectError::Invalid {
            detail: "status code is outside the HTTP range",
        })?;

    let mut field_count = 0_usize;
    let mut saw_content_length = false;
    for line in lines {
        field_count = field_count.saturating_add(1);
        if field_count > MAX_HTTP_CONNECT_FIELDS {
            return Err(HttpConnectError::Invalid {
                detail: "header exceeds 64 fields",
            });
        }
        if line.starts_with([' ', '\t']) {
            return Err(HttpConnectError::Invalid {
                detail: "obsolete folded fields are forbidden",
            });
        }
        let (name, value) = line.split_once(':').ok_or(HttpConnectError::Invalid {
            detail: "header field is malformed",
        })?;
        if name.is_empty() || !name.bytes().all(is_http_token) {
            return Err(HttpConnectError::Invalid {
                detail: "header field name is invalid",
            });
        }
        let value = value.trim_matches([' ', '\t']);
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
        {
            return Err(HttpConnectError::Invalid {
                detail: "header field value contains a control character",
            });
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpConnectError::Invalid {
                detail: "CONNECT response must not carry a transfer encoding",
            });
        }
        if name.eq_ignore_ascii_case("content-length") {
            if saw_content_length || value != "0" {
                return Err(HttpConnectError::Invalid {
                    detail: "CONNECT response body is forbidden",
                });
            }
            saw_content_length = true;
        }
    }
    if !(200..=299).contains(&status_code) {
        return Err(HttpConnectError::Rejected { status_code });
    }
    Ok(())
}

const fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };

    use super::{
        negotiate_http_connect, validate_http_connect_response, HttpConnectError,
        HTTP_CONNECT_READ_CHUNK_BYTES,
    };

    #[test]
    fn response_is_strict_bounded_and_redacted() {
        validate_http_connect_response(
            b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("valid CONNECT response");
        assert!(matches!(
            validate_http_connect_response(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=secret\r\n\r\n"
            ),
            Err(HttpConnectError::Rejected { status_code: 407 })
        ));
        assert!(matches!(
            validate_http_connect_response(
                b"HTTP/1.1 200 Connection Established\r\nTransfer-Encoding: chunked\r\n\r\n"
            ),
            Err(HttpConnectError::Invalid { .. })
        ));
        assert!(matches!(
            validate_http_connect_response(
                b"HTTP/1.1 200 Connection Established\r\n folded: value\r\n\r\n"
            ),
            Err(HttpConnectError::Invalid { .. })
        ));
        let error = HttpConnectError::Rejected { status_code: 407 };
        assert!(!error.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn request_contains_only_the_canonical_authority() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind proxy listener");
        let proxy_address = listener.local_addr().expect("proxy listener address");
        let (release_sender, release_receiver) = oneshot::channel();
        let proxy = tokio::spawn(async move {
            let (mut stream, _client) = listener.accept().await.expect("accept proxy client");
            let mut request = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                stream
                    .read_exact(&mut byte)
                    .await
                    .expect("read CONNECT request");
                request.push(byte[0]);
                assert!(request.len() <= 1_024);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert_eq!(
                request,
                b"CONNECT service.example.test:443 HTTP/1.1\r\nHost: service.example.test:443\r\n\r\n"
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("write CONNECT response");
            let _ = release_receiver.await;
        });
        let mut stream = TcpStream::connect(proxy_address)
            .await
            .expect("connect proxy client");
        negotiate_http_connect(
            &mut stream,
            "service.example.test:443",
            Duration::from_secs(1),
        )
        .await
        .expect("establish CONNECT tunnel");
        release_sender.send(()).expect("release proxy");
        proxy.await.expect("proxy task");
    }

    #[tokio::test]
    async fn response_read_stops_at_the_header_boundary() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind proxy listener");
        let proxy_address = listener.local_addr().expect("proxy listener address");
        let proxy = tokio::spawn(async move {
            let (mut stream, _client) = listener.accept().await.expect("accept proxy client");
            let mut request = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                stream
                    .read_exact(&mut byte)
                    .await
                    .expect("read CONNECT request");
                request.push(byte[0]);
                assert!(request.len() <= 1_024);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }

            let mut response = b"HTTP/1.1 200 Connection Established\r\nX-Padding: ".to_vec();
            response.extend(std::iter::repeat_n(b'a', HTTP_CONNECT_READ_CHUNK_BYTES));
            response.extend_from_slice(b"\r\n\r\ntunnel data");
            stream
                .write_all(&response)
                .await
                .expect("write CONNECT response and tunnel data");
        });
        let mut stream = TcpStream::connect(proxy_address)
            .await
            .expect("connect proxy client");
        let error = negotiate_http_connect(
            &mut stream,
            "service.example.test:443",
            Duration::from_secs(1),
        )
        .await
        .expect_err("reject bytes following the response header");
        assert!(matches!(
            error,
            HttpConnectError::Invalid {
                detail: "bytes follow the CONNECT response header"
            }
        ));
        proxy.await.expect("proxy task");
    }
}
