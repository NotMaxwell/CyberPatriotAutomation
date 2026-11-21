// Copyright 2026 Maxwell McCormick
// SPDX-License-Identifier: Apache-2.0

//! A small HTTP/1.1 server, and the checks every request passes first.
//!
//! Hand-rolled on tokio's `TcpListener` rather than hyper or axum: the release
//! binary must stay static musl, and seven endpoints on loopback need a request
//! line, headers and a `Content-Length` body - nothing a framework adds is worth
//! its weight in a binary that ships to a competition image. Every response but
//! the event stream is `Connection: close`, so there is no keep-alive state.
//!
//! This server makes root changes, so the checks matter more than the routing:
//! a random token on every request (any page in the browser can reach
//! loopback), the `Host` header (DNS rebinding turns a hostile domain into
//! 127.0.0.1), and `Origin` on POST (a cross-site form post carries no token
//! but would otherwise get as far as the parser).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pinnacle_core::files;
use pinnacle_core::platform::Platform;
use pinnacle_core::session::RunKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::api::WebAction;
use super::controller::Controller;

pub const INDEX_HTML: &str = include_str!("index.html");

/// Largest POST body accepted. An edited README is a few kilobytes.
pub const MAX_BODY: usize = 1024 * 1024;
/// Largest request line plus headers.
const MAX_HEAD: usize = 16 * 1024;
/// A client that has not sent its request by now is not a browser.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Keeps proxies and the browser from deciding an idle stream is dead.
const PING_EVERY: Duration = Duration::from_secs(15);
/// At most five snapshots a second per stream: a run emits lines far faster
/// than anyone reads them, and every snapshot carries 400 lines of output.
const MIN_PUSH_GAP: Duration = Duration::from_millis(200);

const CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; \
                   script-src 'self' 'unsafe-inline'; connect-src 'self'";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path without the query string, percent-decoded.
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The client went away or never finished; nothing to answer.
    Closed,
    Malformed,
    HeadTooLarge,
    BodyTooLarge,
}

impl ReadError {
    fn status(&self) -> Option<u16> {
        match self {
            ReadError::Closed => None,
            ReadError::Malformed => Some(400),
            ReadError::HeadTooLarge => Some(431),
            ReadError::BodyTooLarge => Some(413),
        }
    }
}

/// Read one request: request line, headers, and a `Content-Length` body.
///
/// The body limit is applied to the declared length before any of it is read,
/// so an oversized upload costs nothing but the headers.
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request, ReadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(at) = find(&buf, b"\r\n\r\n") {
            break at;
        }
        if buf.len() > MAX_HEAD {
            return Err(ReadError::HeadTooLarge);
        }
        let mut chunk = [0u8; 2048];
        let n = r.read(&mut chunk).await.map_err(|_| ReadError::Closed)?;
        if n == 0 {
            return Err(ReadError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if head_end > MAX_HEAD {
        return Err(ReadError::HeadTooLarge);
    }
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| ReadError::Malformed)?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(version), None) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return Err(ReadError::Malformed);
    };
    if !version.starts_with("HTTP/1.") || method.is_empty() || !target.starts_with('/') {
        return Err(ReadError::Malformed);
    }
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ReadError::Malformed)?;
        if name.is_empty() || name.contains(' ') {
            return Err(ReadError::Malformed);
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }

    // Chunked bodies are not supported; no browser sends one for a fetch with
    // a string body, and guessing at the framing is how smuggling starts.
    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(ReadError::Malformed);
    }
    let lengths: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n == "content-length")
        .map(|(_, v)| v.as_str())
        .collect();
    let length = match lengths.as_slice() {
        [] => 0,
        [one] => one.parse::<usize>().map_err(|_| ReadError::Malformed)?,
        _ => return Err(ReadError::Malformed),
    };
    if length > MAX_BODY {
        return Err(ReadError::BodyTooLarge);
    }
    let mut body = buf[head_end + 4..].to_vec();
    if body.len() > length {
        // Pipelined requests are not supported: one request per connection.
        body.truncate(length);
    }
    if body.len() < length {
        let start = body.len();
        body.resize(length, 0);
        r.read_exact(&mut body[start..])
            .await
            .map_err(|_| ReadError::Closed)?;
    }

    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    Ok(Request {
        method: method.to_string(),
        path: percent_decode(raw_path).ok_or(ReadError::Malformed)?,
        query: parse_query(raw_query).ok_or(ReadError::Malformed)?,
        headers,
        body,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_query(query: &str) -> Option<Vec<(String, String)>> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Some((percent_decode(k)?, percent_decode(v)?))
        })
        .collect()
}

/// `%XX` and `+` decoding. `None` for a broken escape or invalid UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Compare without stopping at the first difference, so response timing does
/// not reveal how much of a guessed token was right.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What every request must carry.
pub struct Guard {
    pub token: String,
    pub port: u16,
}

impl Guard {
    pub fn host_ok(&self, req: &Request) -> bool {
        req.header("host").is_some_and(|h| {
            h == format!("127.0.0.1:{}", self.port) || h == format!("localhost:{}", self.port)
        })
    }

    pub fn token_ok(&self, req: &Request) -> bool {
        let given = req
            .header("x-pinnacle-token")
            .or_else(|| req.query("t"))
            .unwrap_or("");
        constant_time_eq(given.as_bytes(), self.token.as_bytes())
    }

    /// An absent `Origin` is allowed: same-origin GET-style tools and curl do
    /// not send one, and the token still has to be right.
    pub fn origin_ok(&self, req: &Request) -> bool {
        req.header("origin").is_none_or(|o| {
            o == format!("http://127.0.0.1:{}", self.port)
                || o == format!("http://localhost:{}", self.port)
        })
    }

    /// The security checks, in order, as the status to refuse with.
    pub fn check(&self, req: &Request) -> Result<(), u16> {
        if !self.host_ok(req) || !self.token_ok(req) {
            return Err(403);
        }
        if req.method == "POST" && !self.origin_ok(req) {
            return Err(403);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Index,
    State,
    Events,
    Action,
    Ls,
    Log,
    Quit,
}

pub fn route(method: &str, path: &str) -> Result<Route, u16> {
    if method != "GET" && method != "POST" {
        return Err(405);
    }
    let (want, route) = match path {
        "/" => ("GET", Route::Index),
        "/api/state" => ("GET", Route::State),
        "/api/events" => ("GET", Route::Events),
        "/api/action" => ("POST", Route::Action),
        "/api/ls" => ("GET", Route::Ls),
        "/api/log" => ("GET", Route::Log),
        "/api/quit" => ("POST", Route::Quit),
        _ => return Err(404),
    };
    if method == want { Ok(route) } else { Err(405) }
}

fn json_content_type(req: &Request) -> bool {
    req.header("content-type").is_some_and(|ct| {
        ct.split(';')
            .next()
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
    })
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
    }

    fn json(status: u16, value: serde_json::Value) -> Self {
        Self::new(status, "application/json", value.to_string())
    }

    fn error(status: u16) -> Self {
        Self::new(status, "text/plain; charset=utf-8", reason(status))
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    }
}

fn head(status: u16, content_type: &str) -> String {
    format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: {CSP}\r\nReferrer-Policy: no-referrer\r\n",
        reason(status)
    )
}

async fn write_response<W: AsyncWrite + Unpin>(w: &mut W, resp: &Response) -> std::io::Result<()> {
    let mut out = head(resp.status, resp.content_type);
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        resp.body.len()
    ));
    w.write_all(out.as_bytes()).await?;
    w.write_all(&resp.body).await?;
    w.flush().await
}

/// Serve one connection: one request, or one event stream.
pub async fn handle<P: Platform + 'static>(
    mut stream: TcpStream,
    guard: Arc<Guard>,
    ctl: Arc<Controller<P>>,
) {
    let req = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => {
            if let Some(status) = e.status() {
                let _ = write_response(&mut stream, &Response::error(status)).await;
            }
            return;
        }
        Err(_) => return,
    };
    let route = guard
        .check(&req)
        .and_then(|()| route(&req.method, &req.path));
    let response = match route {
        Err(status) => Response::error(status),
        Ok(Route::Events) => {
            events(stream, ctl).await;
            return;
        }
        Ok(r) => dispatch(r, &req, &ctl).await,
    };
    let _ = write_response(&mut stream, &response).await;
    let _ = stream.shutdown().await;
}

async fn dispatch<P: Platform + 'static>(
    route: Route,
    req: &Request,
    ctl: &Arc<Controller<P>>,
) -> Response {
    if req.method == "POST" && route == Route::Action && !json_content_type(req) {
        return Response::error(415);
    }
    match route {
        Route::Index => Response::new(200, "text/html; charset=utf-8", INDEX_HTML),
        Route::State => Response::new(200, "application/json", ctl.snapshot_json()),
        Route::Action => match serde_json::from_slice::<WebAction>(&req.body) {
            Err(e) => Response::json(
                400,
                serde_json::json!({"ok": false, "error": format!("Malformed action: {e}")}),
            ),
            Ok(action) => match ctl.perform(action) {
                Ok(()) => Response::json(200, serde_json::json!({"ok": true})),
                Err(e) => Response::json(200, serde_json::json!({"ok": false, "error": e})),
            },
        },
        Route::Ls => list(req).await,
        Route::Log => {
            let kind = match req.query("kind") {
                Some("preview") => RunKind::Preview,
                Some("real") => RunKind::Real,
                _ => return Response::error(404),
            };
            let Some(path) = ctl.log_path(kind) else {
                return Response::error(404);
            };
            match tokio::fs::read(&path).await {
                Ok(text) => Response::new(200, "text/plain; charset=utf-8", text),
                Err(_) => Response::error(404),
            }
        }
        Route::Quit => {
            ctl.request_quit();
            Response::json(200, serde_json::json!({"ok": true}))
        }
        Route::Events => Response::error(500),
    }
}

async fn list(req: &Request) -> Response {
    let readme_only = req.query("readme_only") == Some("1");
    let dir = match req.query("path") {
        Some(p) if !p.is_empty() => {
            if !Path::new(p).is_absolute() {
                return Response::json(
                    400,
                    serde_json::json!({"error": "The path must be absolute."}),
                );
            }
            p.into()
        }
        _ => files::start_dir(),
    };
    let listed = tokio::task::spawn_blocking(move || files::list_dir(&dir, readme_only)).await;
    match listed {
        Ok(Ok(listing)) => {
            let mut v = serde_json::to_value(listing).unwrap_or_default();
            v["roots"] = serde_json::json!(files::roots());
            Response::json(200, v)
        }
        Ok(Err(e)) => Response::json(400, serde_json::json!({"error": e.to_string()})),
        Err(e) => Response::json(400, serde_json::json!({"error": e.to_string()})),
    }
}

/// The event stream: a snapshot now and after every change, at most five a
/// second, and a ping comment when nothing has happened for a while.
async fn events<P: Platform + 'static>(stream: TcpStream, ctl: Arc<Controller<P>>) {
    let _connected = ctl.stream_opened();
    let (mut reader, mut writer) = stream.into_split();
    let mut out = head(200, "text/event-stream");
    out.push_str("Connection: keep-alive\r\n\r\n");
    if writer.write_all(out.as_bytes()).await.is_err() {
        return;
    }
    let mut version = ctl.subscribe();

    let push = async move {
        loop {
            version.mark_unchanged();
            let frame = format!("event: state\ndata: {}\n\n", ctl.snapshot_json());
            writer.write_all(frame.as_bytes()).await?;
            writer.flush().await?;
            let sent = Instant::now();
            loop {
                match tokio::time::timeout(PING_EVERY, version.changed()).await {
                    Ok(Ok(())) => break,
                    Ok(Err(_)) => return Ok::<(), std::io::Error>(()),
                    Err(_) => writer.write_all(b": ping\n\n").await?,
                }
            }
            tokio::time::sleep(MIN_PUSH_GAP.saturating_sub(sent.elapsed())).await;
        }
    };
    // The browser sends nothing after the request, so a read that returns is
    // the tab closing; without watching for it a closed page would only be
    // noticed at the next ping, delaying the idle exit.
    let gone = async move {
        let mut scratch = [0u8; 256];
        loop {
            match reader.read(&mut scratch).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::select! {
        _ = push => {}
        _ = gone => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn guard() -> Guard {
        Guard {
            token: TOKEN.to_string(),
            port: 18080,
        }
    }

    fn request(method: &str, target: &str, headers: &[(&str, &str)]) -> Request {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: parse_query(query).unwrap(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    async fn read(raw: &[u8]) -> Result<Request, ReadError> {
        let mut r = raw;
        read_request(&mut r).await
    }

    #[test]
    fn a_missing_or_wrong_token_is_refused() {
        let g = guard();
        let host = ("Host", "127.0.0.1:18080");
        assert_eq!(g.check(&request("GET", "/", &[host])), Err(403));
        assert_eq!(
            g.check(&request(
                "GET",
                "/?t=0123456789abcdef0123456789abcdee",
                &[host]
            )),
            Err(403)
        );
        assert_eq!(g.check(&request("GET", "/?t=", &[host])), Err(403));
        assert_eq!(
            g.check(&request("GET", "/", &[host, ("X-Pinnacle-Token", "nope")])),
            Err(403)
        );
        assert_eq!(
            g.check(&request("GET", &format!("/?t={TOKEN}x"), &[host])),
            Err(403),
            "a longer token is not a prefix match"
        );
    }

    #[test]
    fn the_right_token_is_accepted_in_the_query_or_the_header() {
        let g = guard();
        let host = ("Host", "127.0.0.1:18080");
        assert_eq!(
            g.check(&request("GET", &format!("/?t={TOKEN}"), &[host])),
            Ok(())
        );
        assert_eq!(
            g.check(&request(
                "GET",
                "/api/state",
                &[host, ("X-Pinnacle-Token", TOKEN)]
            )),
            Ok(())
        );
    }

    #[test]
    fn only_loopback_hosts_on_our_port_are_accepted() {
        let g = guard();
        let t = ("X-Pinnacle-Token", TOKEN);
        for ok in ["127.0.0.1:18080", "localhost:18080"] {
            assert_eq!(
                g.check(&request("GET", "/", &[("Host", ok), t])),
                Ok(()),
                "{ok}"
            );
        }
        for bad in [
            "evil.com",
            "evil.com:18080",
            "127.0.0.1:18081",
            "127.0.0.1",
            "localhost",
            "127.0.0.1:18080.evil.com",
        ] {
            assert_eq!(
                g.check(&request("GET", "/", &[("Host", bad), t])),
                Err(403),
                "{bad}"
            );
        }
        assert_eq!(g.check(&request("GET", "/", &[t])), Err(403), "no Host");
    }

    #[test]
    fn a_cross_site_post_is_refused_and_a_same_origin_one_is_not() {
        let g = guard();
        let base = [("Host", "127.0.0.1:18080"), ("X-Pinnacle-Token", TOKEN)];
        let with = |origin: &str| {
            let mut h = base.to_vec();
            h.push(("Origin", origin));
            request("POST", "/api/action", &h)
        };
        assert_eq!(g.check(&with("http://evil.example")), Err(403));
        assert_eq!(g.check(&with("http://127.0.0.1:9999")), Err(403));
        assert_eq!(g.check(&with("null")), Err(403));
        assert_eq!(g.check(&with("http://127.0.0.1:18080")), Ok(()));
        assert_eq!(g.check(&with("http://localhost:18080")), Ok(()));
        assert_eq!(
            g.check(&request("POST", "/api/action", &base)),
            Ok(()),
            "no Origin"
        );
        // A GET carries no state change; Origin is only enforced on POST.
        let mut get = with("http://evil.example");
        get.method = "GET".to_string();
        assert_eq!(g.check(&get), Ok(()));
    }

    #[test]
    fn tokens_compare_equal_only_when_identical() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn routes_answer_their_method_and_nothing_else() {
        assert_eq!(route("GET", "/"), Ok(Route::Index));
        assert_eq!(route("GET", "/api/state"), Ok(Route::State));
        assert_eq!(route("GET", "/api/events"), Ok(Route::Events));
        assert_eq!(route("POST", "/api/action"), Ok(Route::Action));
        assert_eq!(route("GET", "/api/ls"), Ok(Route::Ls));
        assert_eq!(route("GET", "/api/log"), Ok(Route::Log));
        assert_eq!(route("POST", "/api/quit"), Ok(Route::Quit));
        assert_eq!(route("GET", "/api/action"), Err(405));
        assert_eq!(route("POST", "/"), Err(405));
        assert_eq!(route("GET", "/api/quit"), Err(405));
        for m in ["PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
            assert_eq!(route(m, "/api/state"), Err(405), "{m}");
        }
        assert_eq!(route("GET", "/favicon.ico"), Err(404));
        assert_eq!(route("GET", "/api/state/"), Err(404));
    }

    #[test]
    fn only_a_json_body_is_accepted_for_an_action() {
        let json = |ct: &str| json_content_type(&request("POST", "/", &[("Content-Type", ct)]));
        assert!(json("application/json"));
        assert!(json("application/json; charset=utf-8"));
        assert!(!json("text/plain"));
        assert!(!json("application/x-www-form-urlencoded"));
        assert!(!json_content_type(&request("POST", "/", &[])));
    }

    #[tokio::test]
    async fn a_request_is_parsed_into_path_query_headers_and_body() {
        let req = read(
            b"POST /api/ls?path=%2Fhome%2Fa%20b&readme_only=1 HTTP/1.1\r\n\
              Host: 127.0.0.1:1\r\nContent-Type: application/json\r\n\
              X-Pinnacle-Token:  abc \r\nContent-Length: 4\r\n\r\nbody",
        )
        .await
        .unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/ls");
        assert_eq!(req.query("path"), Some("/home/a b"));
        assert_eq!(req.query("readme_only"), Some("1"));
        assert_eq!(req.header("x-pinnacle-token"), Some("abc"));
        assert_eq!(req.header("host"), Some("127.0.0.1:1"));
        assert_eq!(req.body, b"body");
    }

    #[tokio::test]
    async fn a_request_without_a_body_reads_as_empty() {
        let req = read(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        assert!(req.body.is_empty() && req.query.is_empty());
    }

    #[tokio::test]
    async fn a_body_over_one_mebibyte_is_refused_before_it_is_read() {
        let head = format!(
            "POST /api/action HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(read(head.as_bytes()).await, Err(ReadError::BodyTooLarge));
        assert_eq!(ReadError::BodyTooLarge.status(), Some(413));

        let mut exact =
            format!("POST /api/action HTTP/1.1\r\nHost: x\r\nContent-Length: {MAX_BODY}\r\n\r\n")
                .into_bytes();
        exact.extend(std::iter::repeat_n(b'a', MAX_BODY));
        assert_eq!(read(&exact).await.unwrap().body.len(), MAX_BODY);
    }

    #[tokio::test]
    async fn malformed_requests_are_rejected() {
        for raw in [
            &b"GET\r\n\r\n"[..],
            b"GET / HTTP/1.1 extra\r\n\r\n",
            b"GET relative HTTP/1.1\r\n\r\n",
            b"GET / SPDY/3\r\n\r\n",
            b"GET / HTTP/1.1\r\nno colon here\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET /%zz HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                read(raw).await,
                Err(ReadError::Malformed),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        assert_eq!(read(b"GET / HTTP/1.1\r\n").await, Err(ReadError::Closed));
        assert_eq!(
            read(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").await,
            Err(ReadError::Closed)
        );
    }

    #[tokio::test]
    async fn oversized_headers_are_refused() {
        let mut raw = b"GET / HTTP/1.1\r\nX: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD + 10));
        raw.extend_from_slice(b"\r\n\r\n");
        assert_eq!(read(&raw).await, Err(ReadError::HeadTooLarge));
    }

    #[tokio::test]
    async fn every_response_carries_the_security_headers() {
        let mut out = Vec::new();
        write_response(&mut out, &Response::error(403))
            .await
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        for h in [
            "Cache-Control: no-store\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; \
             script-src 'self' 'unsafe-inline'; connect-src 'self'\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "Connection: close\r\n",
            "Content-Length: 9\r\n",
        ] {
            assert!(text.contains(h), "missing {h:?} in {text}");
        }
    }
}
