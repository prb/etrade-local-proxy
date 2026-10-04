//! axum request handling: a single fallback handler routes every request
//! through the pure `admit` decision (verb-first), so the GET-only/prefix
//! invariant is the one source of truth and no route is pre-matched by method.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use reqwest::Client;

use crate::core::admission::{admit, Admission, RejectReason};
use crate::core::config::Config;
use crate::core::oauth::HttpMethod;
use crate::shell::clock_nonce::{Clock, NonceSource, Signer};
use crate::shell::error::ProxyError;
use crate::shell::state::{self, SharedState};
use crate::shell::upstream::{self, RelayedResponse};

/// Everything the fallback handler needs. Cloned per request (all `Arc`s).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub auth: SharedState,
    pub clock: Arc<dyn Clock + Send + Sync>,
    pub nonces: Arc<dyn NonceSource + Send + Sync>,
    pub client: Client,
    /// Base-URL override for the upstream host (tests point this at a local
    /// fake). `None` uses the real `https://api.etrade.com`.
    pub upstream_base: Option<String>,
}

/// Map an axum `Method` into the core [`HttpMethod`].
fn to_core_method(method: &Method) -> HttpMethod {
    match *method {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        Method::PUT => HttpMethod::Put,
        Method::DELETE => HttpMethod::Delete,
        Method::PATCH => HttpMethod::Patch,
        Method::HEAD => HttpMethod::Head,
        Method::OPTIONS => HttpMethod::Options,
        Method::TRACE => HttpMethod::Trace,
        Method::CONNECT => HttpMethod::Connect,
        _ => HttpMethod::Other,
    }
}

/// The single fallback handler. Converts the request into core types, calls
/// `admit`, and dispatches on the outcome.
pub async fn handle(State(app): State<AppState>, request: Request) -> Response {
    let method = to_core_method(request.method());
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("")
        .to_string();
    // Capture the client's Accept header (if any valid UTF-8) to forward
    // upstream, so a client can request ETrade's JSON representation.
    let accept = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    match admit(&method, &path_and_query) {
        Admission::Status => status_response(&app.auth),
        Admission::Forward(upstream_path) => {
            forward_response(&app, upstream_path.as_str(), accept.as_deref()).await
        }
        Admission::Reject(RejectReason::MethodNotGet) => {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }
        Admission::Reject(RejectReason::OutOfPrefix) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serialize the `/internal/status` body from the current phase.
fn status_response(auth: &SharedState) -> Response {
    let body = state::status_body(auth);
    // Serialization of a two-field struct cannot fail; documented expect.
    let json = serde_json::to_string(&body).expect("status body serializes");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response()
}

/// Forward an admitted request upstream, or 503 if not yet authorized.
/// `accept` is the client's `Accept` header, forwarded verbatim when present.
async fn forward_response(app: &AppState, mapped_path: &str, accept: Option<&str>) -> Response {
    let Some(authorized) = state::authorized_handle(&app.auth) else {
        return proxy_error_response(&ProxyError::NotReady);
    };

    let signer = Signer::new(app.clock.as_ref(), app.nonces.as_ref());
    let result = upstream::forward(
        &app.client,
        &app.config,
        &authorized,
        mapped_path,
        accept,
        app.upstream_base.as_deref(),
        signer,
    )
    .await;

    match result {
        Ok(relayed) => relay_to_response(relayed),
        Err(err) => proxy_error_response(&err),
    }
}

/// Build the local response from a buffered upstream relay.
fn relay_to_response(relayed: RelayedResponse) -> Response {
    let status = StatusCode::from_u16(relayed.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::builder().status(status);

    for (name, value) in &relayed.headers {
        // Both name and value came from a parsed upstream header, but guard
        // against anything the framework would reject rather than panicking.
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            response = response.header(hn, hv);
        }
    }

    response
        .body(Body::from(relayed.body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// Map a [`ProxyError`] to its HTTP status (502/502/503).
fn proxy_error_response(err: &ProxyError) -> Response {
    let status = match err {
        ProxyError::Upstream(_) | ProxyError::UpstreamTooLarge { .. } => StatusCode::BAD_GATEWAY,
        ProxyError::NotReady => StatusCode::SERVICE_UNAVAILABLE,
    };
    status.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_mapping_covers_common_verbs() {
        assert_eq!(to_core_method(&Method::GET), HttpMethod::Get);
        assert_eq!(to_core_method(&Method::POST), HttpMethod::Post);
        assert_eq!(to_core_method(&Method::DELETE), HttpMethod::Delete);
    }

    #[test]
    fn proxy_error_status_codes() {
        assert_eq!(
            proxy_error_response(&ProxyError::NotReady).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            proxy_error_response(&ProxyError::UpstreamTooLarge { cap: 10 }).status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
