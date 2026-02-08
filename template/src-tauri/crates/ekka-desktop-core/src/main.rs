//! EKKA Desktop Core
//!
//! Security-critical logic process that communicates via JSON-RPC over stdio.
//!
//! # Protocol
//!
//! Request (one JSON object per line on stdin):
//!   { "id": "<uuid>", "op": "<string>", "payload": {...} }
//!
//! Response (one JSON object per line on stdout):
//!   { "id": "<uuid>", "ok": true|false, "result": {...}|null, "error": {...}|null }
//!
//! # Handled Operations
//!
//! - nodeCredentials.status
//! - nodeCredentials.set
//! - nodeCredentials.clear
//! - node.auth.authenticate
//! - runner.taskStats
//! - wellKnown.fetch
//! - setup.status
//! - engine.status
//! - runner.status
//! - auth.login
//! - auth.refresh
//! - auth.logout
//! - workflowRuns.create
//! - workflowRuns.get
//! - nodeSession.status
//! - nodeSession.ensureIdentity
//! - runtime.info
//! - home.status
//! - debug.isDevMode

mod bootstrap;
mod config;
mod device_secret;
mod node_credentials;
mod node_vault_crypto;
mod node_vault_store;
mod security_epoch;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};

// =============================================================================
// Protocol Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct Request {
    id: String,
    op: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorDetail>,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

impl Response {
    fn ok(id: String, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: String, code: &str, message: &str) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            }),
        }
    }
}

// =============================================================================
// Op Dispatch
// =============================================================================

fn dispatch(req: &Request) -> Response {
    tracing::info!(op = %req.op, request_id = %req.id, "core.dispatch");
    match req.op.as_str() {
        "nodeCredentials.status" => handle_credentials_status(&req.id),
        "nodeCredentials.set" => handle_credentials_set(&req.id, &req.payload),
        "nodeCredentials.clear" => handle_credentials_clear(&req.id),
        "node.auth.authenticate" => handle_auth_authenticate(&req.id, &req.payload),
        "runner.taskStats" => handle_runner_task_stats(&req.id),
        "wellKnown.fetch" => handle_well_known_fetch(&req.id),
        "setup.status" => handle_setup_status(&req.id),
        "engine.status" => handle_engine_status(&req.id, &req.payload),
        "runner.status" => handle_runner_status(&req.id, &req.payload),
        "auth.login" => handle_auth_login(&req.id, &req.payload),
        "auth.refresh" => handle_auth_refresh(&req.id, &req.payload),
        "auth.logout" => handle_auth_logout(&req.id, &req.payload),
        "workflowRuns.create" => handle_workflow_runs_create(&req.id, &req.payload),
        "workflowRuns.get" => handle_workflow_runs_get(&req.id, &req.payload),
        "nodeSession.status" => handle_node_session_status(&req.id, &req.payload),
        "nodeSession.ensureIdentity" => handle_ensure_node_identity(&req.id, &req.payload),
        "runtime.info" => handle_runtime_info(&req.id, &req.payload),
        "home.status" => handle_home_status(&req.id, &req.payload),
        "execution.plans.list" => handle_execution_proxy_get(&req.id, &req.payload, "/engine/admin/execution/plans", "execution.plans.list", &["limit", "offset", "search"]),
        "execution.plans.get" => handle_execution_proxy_get_by_id(&req.id, &req.payload, "id", "/engine/admin/execution/plans", "execution.plans.get"),
        "execution.plans.runs.list" => handle_execution_plan_runs_list(&req.id, &req.payload),
        "execution.runs.get" => handle_execution_proxy_get_by_id(&req.id, &req.payload, "runId", "/engine/admin/execution/runs", "execution.runs.get"),
        "execution.runs.events" => handle_execution_runs_events(&req.id, &req.payload),
        "execution.runs.start" => handle_execution_runs_start(&req.id, &req.payload),
        "admin.logs" => handle_admin_logs(&req.id, &req.payload),
        "debug.isDevMode" => handle_is_dev_mode(&req.id),
        _ => Response::err(
            req.id.clone(),
            "UNKNOWN_OP",
            &format!("Desktop Core does not handle op: {}", req.op),
        ),
    }
}

// =============================================================================
// Handlers
// =============================================================================

/// nodeCredentials.status — check if credentials exist, return node_id
fn handle_credentials_status(id: &str) -> Response {
    tracing::info!(op = "core.nodeCredentials.status", "Handling nodeCredentials.status");

    let status = node_credentials::get_status();

    Response::ok(
        id.to_string(),
        serde_json::json!({
            "hasCredentials": status.has_credentials,
            "nodeId": status.node_id,
        }),
    )
}

/// nodeCredentials.set — store node_id + node_secret in vault
fn handle_credentials_set(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.nodeCredentials.set", "Handling nodeCredentials.set");

    // Extract node_id
    let node_id_str = match payload.get("nodeId").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "nodeId is required"),
    };

    // Validate node_id format
    let node_id = match node_credentials::validate_node_id(node_id_str) {
        Ok(id) => id,
        Err(e) => return Response::err(id.to_string(), "INVALID_NODE_ID", &e.to_string()),
    };

    // Extract node_secret
    let node_secret = match payload.get("nodeSecret").and_then(|v| v.as_str()) {
        Some(secret) => secret,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "nodeSecret is required"),
    };

    // Validate node_secret
    if let Err(e) = node_credentials::validate_node_secret(node_secret) {
        return Response::err(id.to_string(), "INVALID_NODE_SECRET", &e.to_string());
    }

    // Store credentials
    match node_credentials::store_credentials(&node_id, node_secret) {
        Ok(()) => {
            tracing::info!(
                op = "core.nodeCredentials.stored",
                node_id = %node_id,
                "Credentials stored successfully"
            );
            Response::ok(
                id.to_string(),
                serde_json::json!({
                    "ok": true,
                    "nodeId": node_id.to_string(),
                }),
            )
        }
        Err(e) => Response::err(id.to_string(), "CREDENTIALS_STORE_ERROR", &e.to_string()),
    }
}

/// nodeCredentials.clear — remove credentials from vault
fn handle_credentials_clear(id: &str) -> Response {
    tracing::info!(op = "core.nodeCredentials.clear", "Handling nodeCredentials.clear");

    match node_credentials::clear_credentials() {
        Ok(()) => Response::ok(
            id.to_string(),
            serde_json::json!({ "ok": true }),
        ),
        Err(e) => Response::err(id.to_string(), "CREDENTIALS_CLEAR_ERROR", &e.to_string()),
    }
}

/// setup.status — check if node credentials are configured (onboarding gate)
///
/// Called by TS on launch to determine if setup wizard is needed.
/// Reads credential status directly (no RPC hop).
fn handle_setup_status(id: &str) -> Response {
    tracing::info!(op = "core.setup.status", "Handling setup.status");

    let status = node_credentials::get_status();
    let node_configured = status.has_credentials;

    Response::ok(
        id.to_string(),
        serde_json::json!({
            "nodeIdentity": if node_configured { "configured" } else { "not_configured" },
            "setupComplete": node_configured,
        }),
    )
}

/// engine.status — format engine status from host-provided fields
///
/// Host probes the live engine process and passes raw fields as payload.
/// Core owns the response contract/formatting.
fn handle_engine_status(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.engine.status", "Handling engine.status");

    // Pass through host-provided fields (Core owns the contract shape)
    let installed = payload.get("installed").and_then(|v| v.as_bool()).unwrap_or(false);
    let running = payload.get("running").and_then(|v| v.as_bool()).unwrap_or(false);
    let available = payload.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
    let pid = payload.get("pid").and_then(|v| v.as_u64()).map(|n| n as u32);
    let version = payload.get("version").and_then(|v| v.as_str());
    let build = payload.get("build").and_then(|v| v.as_str());

    Response::ok(
        id.to_string(),
        serde_json::json!({
            "installed": installed,
            "running": running,
            "available": available,
            "pid": pid,
            "version": version,
            "build": build,
        }),
    )
}

/// runner.status — format runner status from host-provided fields
///
/// Host probes the live runner state and passes fields as payload.
/// Core owns the response contract/formatting.
fn handle_runner_status(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.runner.status", "Handling runner.status");

    // Pass through host-provided fields (Core owns the contract shape)
    Response::ok(id.to_string(), payload.clone())
}

/// node.auth.authenticate — authenticate with engine using node_secret
///
/// Uses shared AUTH_CACHE: returns cached token if still valid (>60s remaining),
/// otherwise authenticates fresh. This prevents duplicate server sessions when
/// both startup-auth and auto-auth call this handler.
fn handle_auth_authenticate(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.node.auth.authenticate", "Handling node.auth.authenticate");

    // Engine URL from payload or baked config
    let engine_url = payload
        .get("engineUrl")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| config::engine_url());

    // Use get_cached_or_fresh_token so all auth goes through the same cache + backoff path
    match get_cached_or_fresh_token(engine_url) {
        Ok(token) => {
            tracing::info!(
                op = "core.node.auth.success",
                node_id = %token.node_id,
                session_id = %token.session_id,
                "Node authenticated (cached for reuse)"
            );
            Response::ok(
                id.to_string(),
                serde_json::json!({
                    "ok": true,
                    "token": token.token,
                    "nodeId": token.node_id.to_string(),
                    "tenantId": token.tenant_id.to_string(),
                    "workspaceId": token.workspace_id.to_string(),
                    "sessionId": token.session_id.to_string(),
                    "expiresAt": token.expires_at.to_rfc3339(),
                }),
            )
        }
        Err(ref e) if e.contains("session_limit") => {
            Response::err(id.to_string(), "SESSION_LIMIT", e)
        }
        Err(e) => Response::err(id.to_string(), "NODE_AUTH_ERROR", &e),
    }
}

// =============================================================================
// Runner Stats
// =============================================================================

/// runner.taskStats — fetch runner task stats from engine API (V2)
///
/// Authenticates using node_secret from vault (cached until expiry).
/// Proxies GET /engine/runner-tasks-v2/stats through Core to avoid CORS.
/// On 401: clears cache, re-authenticates, retries once.
fn handle_runner_task_stats(id: &str) -> Response {
    tracing::debug!(op = "core.runner.taskStats", request_id = %id, "Handling runner.taskStats");

    let engine_url = config::engine_url();

    // Get auth token (cached or fresh)
    let token = match get_cached_or_fresh_token(engine_url) {
        Ok(t) => t,
        Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
    };

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    let request_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(op = "core.runner.taskStats.http", correlation_id = %request_id, "Proxying to engine");

    let send_stats_request =
        |bearer_token: &str| -> Result<reqwest::blocking::Response, reqwest::Error> {
            client
                .get(format!("{}/engine/runner-tasks-v2/stats", engine_url))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", bearer_token))
                .header("X-EKKA-PROOF-TYPE", "jwt")
                .header("X-REQUEST-ID", &request_id)
                .header("X-EKKA-CORRELATION-ID", &request_id)
                .header("X-EKKA-MODULE", "engine.runner_tasks_v2")
                .header("X-EKKA-ACTION", "stats")
                .header("X-EKKA-CLIENT", config::app_slug())
                .header("X-EKKA-CLIENT-VERSION", "0.2.0")
                .send()
        };

    // First attempt
    let response = match send_stats_request(&token.token) {
        Ok(r) => r,
        Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    };

    // 401 → clear cache, re-auth, retry once
    if response.status().as_u16() == 401 {
        tracing::info!(op = "core.runner.taskStats.401", "Got 401, clearing cache and retrying");
        clear_auth_cache();

        let retry_token = match get_cached_or_fresh_token(engine_url) {
            Ok(t) => t,
            Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
        };

        let retry_response = match send_stats_request(&retry_token.token) {
            Ok(r) => r,
            Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
        };

        return parse_stats_response(id, retry_response);
    }

    parse_stats_response(id, response)
}

/// Parse stats HTTP response into a JSON-RPC Response
fn parse_stats_response(id: &str, resp: reqwest::blocking::Response) -> Response {
    let status = resp.status();
    if status.is_success() {
        match resp.json::<serde_json::Value>() {
            Ok(data) => Response::ok(id.to_string(), data),
            Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
        }
    } else {
        let status_code = status.as_u16();
        let body = resp.text().unwrap_or_default();
        Response::err(
            id.to_string(),
            "HTTP_ERROR",
            &format!("HTTP {}: {}", status_code, body),
        )
    }
}

/// Module-level auth token cache shared by all handlers.
/// `handle_auth_authenticate`, `get_cached_or_fresh_token`, and `clear_auth_cache`
/// all read/write through this single cache to prevent duplicate server sessions.
static AUTH_CACHE: std::sync::Mutex<Option<node_credentials::NodeAuthToken>> =
    std::sync::Mutex::new(None);

/// Backoff deadline — when set, `get_cached_or_fresh_token` will refuse to call
/// `authenticate_node` until `Utc::now()` passes this timestamp.
/// Prevents the 2-second polling loop from hammering `/engine/nodes/auth` after a
/// 429 session_limit or other transient auth failure.
static AUTH_BACKOFF_UNTIL: std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>> =
    std::sync::Mutex::new(None);

/// Clear the cached auth token (used after 401 to force re-auth)
fn clear_auth_cache() {
    if let Ok(mut guard) = AUTH_CACHE.lock() {
        *guard = None;
        tracing::info!(op = "core.auth.cache.cleared", "Auth cache cleared");
    }
}

/// Get a cached auth token or authenticate fresh via node_secret.
///
/// Backoff protection: after a failed auth (especially 429 session_limit),
/// further attempts are blocked for a cooldown period to prevent the 2-second
/// `runner.taskStats` polling loop from hammering the auth endpoint.
fn get_cached_or_fresh_token(engine_url: &str) -> Result<node_credentials::NodeAuthToken, String> {
    // Check cache — valid token means no network call
    if let Ok(guard) = AUTH_CACHE.lock() {
        if let Some(ref cached) = *guard {
            if cached.expires_at > chrono::Utc::now() + chrono::Duration::seconds(60) {
                tracing::debug!(op = "core.auth.cache.hit", "Using cached auth token");
                return Ok(cached.clone());
            }
            tracing::info!(op = "core.auth.cache.expired", "Cached token near expiry, re-authenticating");
        }
    }

    // Check backoff — prevent retry loop after 429 or transient failure
    if let Ok(guard) = AUTH_BACKOFF_UNTIL.lock() {
        if let Some(until) = *guard {
            if chrono::Utc::now() < until {
                let secs = (until - chrono::Utc::now()).num_seconds();
                tracing::warn!(
                    op = "core.auth.backoff.active",
                    remaining_secs = secs,
                    "Auth backoff active, skipping auth attempt"
                );
                return Err(format!(
                    "Auth backoff active ({}s remaining). Previous auth failed.",
                    secs
                ));
            }
        }
    }

    // Need to authenticate
    if !node_credentials::has_credentials() {
        return Err("Node not authenticated. Complete setup first.".to_string());
    }

    match node_credentials::authenticate_node(engine_url) {
        Ok(token) => {
            // Cache the token and clear any backoff
            if let Ok(mut guard) = AUTH_CACHE.lock() {
                *guard = Some(token.clone());
            }
            if let Ok(mut guard) = AUTH_BACKOFF_UNTIL.lock() {
                *guard = None;
            }
            tracing::info!(op = "core.auth.cache.stored", "Auth token cached");
            Ok(token)
        }
        Err(node_credentials::CredentialsError::AuthFailed(429, ref body)) => {
            // 429 session_limit — long backoff, do NOT retry quickly
            let backoff_secs = 60;
            if let Ok(mut guard) = AUTH_BACKOFF_UNTIL.lock() {
                *guard = Some(chrono::Utc::now() + chrono::Duration::seconds(backoff_secs));
            }
            tracing::error!(
                op = "core.auth.session_limit",
                backoff_secs = backoff_secs,
                "429 session_limit — backing off {}s",
                backoff_secs
            );
            Err(format!("session_limit: {}", body))
        }
        Err(e) => {
            // Other auth failure — short backoff to avoid rapid retries
            let backoff_secs = 10;
            if let Ok(mut guard) = AUTH_BACKOFF_UNTIL.lock() {
                *guard = Some(chrono::Utc::now() + chrono::Duration::seconds(backoff_secs));
            }
            tracing::warn!(
                op = "core.auth.failed",
                backoff_secs = backoff_secs,
                error = %e,
                "Auth failed — backing off {}s",
                backoff_secs
            );
            Err(format!("Node authentication failed: {}", e))
        }
    }
}

// =============================================================================
// Well-Known Configuration
// =============================================================================

/// wellKnown.fetch — fetch grant verification key from engine's public endpoint
///
/// GET /engine/.well-known/ekka-configuration (no auth required)
/// Returns the grant verification key for cryptographic grant validation.
fn handle_well_known_fetch(id: &str) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(op = "core.wellKnown.fetch", correlation_id = %request_id, "Handling wellKnown.fetch");

    let engine_url = config::engine_url();
    let url = format!(
        "{}/engine/.well-known/ekka-configuration",
        engine_url.trim_end_matches('/')
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    let response = client
        .get(&url)
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => {
                        tracing::info!(
                            op = "core.wellKnown.fetch.success",
                            "Grant verification key fetched successfully"
                        );
                        Response::ok(id.to_string(), data)
                    }
                    Err(e) => Response::err(
                        id.to_string(),
                        "PARSE_ERROR",
                        &format!("Failed to parse well-known config: {}", e),
                    ),
                }
            } else {
                let status_code = status.as_u16();
                let reason = status.canonical_reason().unwrap_or("Unknown");
                Response::err(
                    id.to_string(),
                    "HTTP_ERROR",
                    &format!("Engine returned error: {} {}", status_code, reason),
                )
            }
        }
        Err(e) => Response::err(
            id.to_string(),
            "REQUEST_FAILED",
            &format!("Failed to fetch well-known config: {}", e),
        ),
    }
}

// =============================================================================
// Auth Proxy (credential-handling HTTP)
// =============================================================================

/// auth.login — proxy login request to API so credentials never traverse host logic
///
/// POST {engine_url}/auth/login with { identifier, password }
/// Returns API response verbatim.
fn handle_auth_login(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.auth.login", request_id = %id, "Handling auth.login");

    // Extract credentials
    let identifier = match payload.get("identifier").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "identifier is required"),
    };
    let password = match payload.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "password is required"),
    };

    let api_url = config::engine_url();

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Security headers (same envelope as host build_security_headers(None, "auth", "login"))
    let request_id = uuid::Uuid::new_v4().to_string();

    let body = serde_json::json!({
        "identifier": identifier,
        "password": password
    });

    let response = client
        .post(format!("{}/auth/login", api_url))
        .header("Content-Type", "application/json")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .header("X-EKKA-PROOF-TYPE", "none")
        .header("X-EKKA-MODULE", "auth")
        .header("X-EKKA-ACTION", "login")
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-EKKA-CLIENT-VERSION", "0.2.0")
        .json(&body)
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => {
                        tracing::info!(op = "core.auth.login.success", "Login succeeded");
                        Response::ok(id.to_string(), data)
                    }
                    Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body_text = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body_text)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or(v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                tracing::warn!(
                    op = "core.auth.login.failed",
                    status = status_code,
                    "Login failed: {}",
                    error_msg
                );
                Response::err(
                    id.to_string(),
                    "AUTH_LOGIN_FAILED",
                    &format!("HTTP {}: {}", status_code, error_msg),
                )
            }
        }
        Err(e) => Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    }
}

/// auth.refresh — proxy token refresh to API so refresh_token never traverses host logic
///
/// POST {engine_url}/auth/refresh with { refresh_token }
/// If jwt is provided, sets proof_type=jwt and Authorization header.
/// Returns API response verbatim.
fn handle_auth_refresh(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.auth.refresh", "Handling auth.refresh");

    // Extract refresh token
    let refresh_token = match payload.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "refresh_token is required"),
    };

    // Extract optional current JWT (for proof_type header)
    let jwt = payload.get("jwt").and_then(|v| v.as_str());

    let api_url = config::engine_url();

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Security headers (same envelope as host build_security_headers(jwt, "auth", "refresh_token"))
    let request_id = uuid::Uuid::new_v4().to_string();
    let proof_type = if jwt.is_some() { "jwt" } else { "none" };

    let body = serde_json::json!({
        "refresh_token": refresh_token
    });

    let mut req_builder = client
        .post(format!("{}/auth/refresh", api_url))
        .header("Content-Type", "application/json")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .header("X-EKKA-PROOF-TYPE", proof_type)
        .header("X-EKKA-MODULE", "auth")
        .header("X-EKKA-ACTION", "refresh_token")
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-EKKA-CLIENT-VERSION", "0.2.0");

    if let Some(token) = jwt {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
    }

    let response = req_builder.json(&body).send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => {
                        tracing::info!(op = "core.auth.refresh.success", "Token refresh succeeded");
                        Response::ok(id.to_string(), data)
                    }
                    Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body_text = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body_text)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or(v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                tracing::warn!(
                    op = "core.auth.refresh.failed",
                    status = status_code,
                    "Token refresh failed: {}",
                    error_msg
                );
                Response::err(
                    id.to_string(),
                    "AUTH_REFRESH_FAILED",
                    &format!("HTTP {}: {}", status_code, error_msg),
                )
            }
        }
        Err(e) => Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    }
}

/// auth.logout — proxy logout request to API so refresh_token never traverses host logic
///
/// POST {engine_url}/auth/logout with { refresh_token }
/// Returns API response verbatim.
fn handle_auth_logout(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.auth.logout", "Handling auth.logout");

    // Extract refresh token
    let refresh_token = match payload.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "refresh_token is required"),
    };

    let api_url = config::engine_url();

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Security headers (same envelope as host build_security_headers(None, "auth", "logout"))
    let request_id = uuid::Uuid::new_v4().to_string();

    let body = serde_json::json!({
        "refresh_token": refresh_token
    });

    let response = client
        .post(format!("{}/auth/logout", api_url))
        .header("Content-Type", "application/json")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .header("X-EKKA-PROOF-TYPE", "none")
        .header("X-EKKA-MODULE", "auth")
        .header("X-EKKA-ACTION", "logout")
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-EKKA-CLIENT-VERSION", "0.2.0")
        .json(&body)
        .send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => {
                        tracing::info!(op = "core.auth.logout.success", "Logout succeeded");
                        Response::ok(id.to_string(), data)
                    }
                    Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body_text = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body_text)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or(v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                tracing::warn!(
                    op = "core.auth.logout.failed",
                    status = status_code,
                    "Logout failed: {}",
                    error_msg
                );
                Response::err(
                    id.to_string(),
                    "AUTH_LOGOUT_FAILED",
                    &format!("HTTP {}: {}", status_code, error_msg),
                )
            }
        }
        Err(e) => Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    }
}

// =============================================================================
// Runtime Info (host-probes/core-formats)
// =============================================================================

/// runtime.info — format runtime info from host-provided home state
///
/// Host reads home state/path and passes them as payload.
/// Core owns the response contract/formatting. No FS/vault/network access.
fn handle_runtime_info(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.runtime.info", "Handling runtime.info");

    let home_state = payload.get("homeState").and_then(|v| v.as_str()).unwrap_or("unknown");
    let home_path = payload.get("homePath").and_then(|v| v.as_str()).unwrap_or("");

    Response::ok(
        id.to_string(),
        serde_json::json!({
            "runtime": "ekka-bridge",
            "engine_present": true,
            "mode": "engine",
            "homeState": home_state,
            "homePath": home_path,
        }),
    )
}

// =============================================================================
// Home Status (host-probes/core-formats)
// =============================================================================

/// home.status — format home status from host-provided fields
///
/// Host computes homeState/homePath/grantPresent/reason via SDK.
/// Core owns the response contract/formatting. No FS/vault/grants access.
fn handle_home_status(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.home.status", "Handling home.status");

    let state = payload.get("state").and_then(|v| v.as_str()).unwrap_or("BOOTSTRAP_PRE_LOGIN");
    let home_path = payload.get("homePath").and_then(|v| v.as_str()).unwrap_or("");
    let grant_present = payload.get("grantPresent").and_then(|v| v.as_bool()).unwrap_or(false);
    let reason = payload.get("reason").and_then(|v| v.as_str());

    Response::ok(
        id.to_string(),
        serde_json::json!({
            "state": state,
            "homePath": home_path,
            "grantPresent": grant_present,
            "reason": reason,
        }),
    )
}

// =============================================================================
// Node Session Status (host-probes/core-formats)
// =============================================================================

/// nodeSession.status — format node session status from host-provided fields
///
/// Host passes session state fields. Core owns the response contract/formatting.
fn handle_node_session_status(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.nodeSession.status", "Handling nodeSession.status");

    // Host passes pre-computed fields (no secrets)
    let has_session = payload.get("hasSession").and_then(|v| v.as_bool()).unwrap_or(false);
    let session_valid = payload.get("sessionValid").and_then(|v| v.as_bool()).unwrap_or(false);

    // Session fields (optional, only present if hasSession)
    let session = if has_session {
        let session_id = payload.get("session").and_then(|v| v.get("session_id")).and_then(|v| v.as_str());
        let tenant_id = payload.get("session").and_then(|v| v.get("tenant_id")).and_then(|v| v.as_str());
        let workspace_id = payload.get("session").and_then(|v| v.get("workspace_id")).and_then(|v| v.as_str());
        let expires_at = payload.get("session").and_then(|v| v.get("expires_at")).and_then(|v| v.as_str());
        let is_expired = payload.get("session").and_then(|v| v.get("is_expired")).and_then(|v| v.as_bool()).unwrap_or(false);
        Some(serde_json::json!({
            "session_id": session_id,
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "expires_at": expires_at,
            "is_expired": is_expired,
        }))
    } else {
        None
    };

    Response::ok(
        id.to_string(),
        serde_json::json!({
            "hasIdentity": false,
            "hasSession": has_session,
            "sessionValid": session_valid,
            "identity": null,
            "session": session,
        }),
    )
}

/// nodeSession.ensureIdentity — verify node identity from host-provided fields
///
/// Host checks if node_auth_token exists and passes fields (no token strings).
/// If token present: returns success with identity fields.
/// If token absent: core checks credentials directly and returns appropriate error.
fn handle_ensure_node_identity(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.nodeSession.ensureIdentity", "Handling nodeSession.ensureIdentity");

    let has_token = payload.get("hasToken").and_then(|v| v.as_bool()).unwrap_or(false);

    if has_token {
        // Host has a valid node auth token — return identity from provided fields
        let node_id = match payload.get("nodeId").and_then(|v| v.as_str()) {
            Some(nid) => nid,
            None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "nodeId is required when hasToken is true"),
        };
        let tenant_id = payload.get("tenantId").and_then(|v| v.as_str()).unwrap_or("");
        let workspace_id = payload.get("workspaceId").and_then(|v| v.as_str()).unwrap_or("");

        return Response::ok(
            id.to_string(),
            serde_json::json!({
                "ok": true,
                "node_id": node_id,
                "tenant_id": tenant_id,
                "workspace_id": workspace_id,
                "auth_method": "node_secret"
            }),
        );
    }

    // No token — check if credentials exist (core has direct access)
    let status = node_credentials::get_status();

    if status.has_credentials {
        // Credentials exist but auth failed or not attempted
        Response::err(
            id.to_string(),
            "NODE_NOT_AUTHENTICATED",
            "Node credentials exist but not authenticated. Restart app to authenticate.",
        )
    } else {
        // No credentials configured
        Response::err(
            id.to_string(),
            "NODE_CREDENTIALS_MISSING",
            "Node credentials not configured. Use nodeCredentials.set to configure.",
        )
    }
}

// =============================================================================
// Workflow Runs (proxied HTTP)
// =============================================================================

/// workflowRuns.create — proxy workflow run creation to engine API
///
/// POST {engine_url}/engine/workflow-runs with the request body.
/// If jwt is provided, sets proof_type=jwt and Authorization header.
/// Returns API response verbatim.
fn handle_workflow_runs_create(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.workflowRuns.create", "Handling workflowRuns.create");

    // Extract request body
    let request = match payload.get("request") {
        Some(r) => r.clone(),
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "request is required"),
    };

    // Extract optional JWT
    let jwt = payload.get("jwt").and_then(|v| v.as_str());

    let engine_url = config::engine_url();

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Security headers (same as host build_security_headers(jwt, "desktop.docgen", "workflow.create"))
    let request_id = uuid::Uuid::new_v4().to_string();
    let proof_type = if jwt.is_some() { "jwt" } else { "none" };

    let mut req_builder = client
        .post(format!("{}/engine/workflow-runs", engine_url))
        .header("Content-Type", "application/json")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .header("X-EKKA-PROOF-TYPE", proof_type)
        .header("X-EKKA-MODULE", "desktop.docgen")
        .header("X-EKKA-ACTION", "workflow.create")
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-EKKA-CLIENT-VERSION", "0.2.0");

    if let Some(token) = jwt {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
    }

    let response = req_builder.json(&request).send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => {
                        tracing::info!(op = "core.workflowRuns.create.success", "Workflow run created");
                        Response::ok(id.to_string(), data)
                    }
                    Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body_text = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body_text)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or(v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                tracing::warn!(
                    op = "core.workflowRuns.create.failed",
                    status = status_code,
                    "Workflow run creation failed: {}",
                    error_msg
                );
                Response::err(
                    id.to_string(),
                    "WORKFLOW_RUN_CREATE_FAILED",
                    &format!("HTTP {}: {}", status_code, error_msg),
                )
            }
        }
        Err(e) => {
            if e.is_connect() {
                Response::err(
                    id.to_string(),
                    "ENGINE_UNAVAILABLE",
                    &format!("Cannot connect to engine at {}. Is the engine running?", engine_url),
                )
            } else {
                Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string())
            }
        }
    }
}

/// workflowRuns.get — proxy workflow run fetch from engine API
///
/// GET {engine_url}/engine/workflow-runs/{id}
/// If jwt is provided, sets proof_type=jwt and Authorization header.
/// Returns API response verbatim.
fn handle_workflow_runs_get(id: &str, payload: &Value) -> Response {
    tracing::info!(op = "core.workflowRuns.get", "Handling workflowRuns.get");

    // Extract workflow run ID
    let run_id = match payload.get("id").and_then(|v| v.as_str()) {
        Some(rid) => rid,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "id is required"),
    };

    // Extract optional JWT
    let jwt = payload.get("jwt").and_then(|v| v.as_str());

    let engine_url = config::engine_url();

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    // Security headers (same as host build_security_headers(jwt, "desktop.docgen", "workflow.get"))
    let request_id = uuid::Uuid::new_v4().to_string();
    let proof_type = if jwt.is_some() { "jwt" } else { "none" };

    let mut req_builder = client
        .get(format!("{}/engine/workflow-runs/{}", engine_url, run_id))
        .header("Content-Type", "application/json")
        .header("X-REQUEST-ID", &request_id)
        .header("X-EKKA-CORRELATION-ID", &request_id)
        .header("X-EKKA-PROOF-TYPE", proof_type)
        .header("X-EKKA-MODULE", "desktop.docgen")
        .header("X-EKKA-ACTION", "workflow.get")
        .header("X-EKKA-CLIENT", config::app_slug())
        .header("X-EKKA-CLIENT-VERSION", "0.2.0");

    if let Some(token) = jwt {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
    }

    let response = req_builder.send();

    match response {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.json::<serde_json::Value>() {
                    Ok(data) => {
                        tracing::info!(op = "core.workflowRuns.get.success", "Workflow run fetched");
                        Response::ok(id.to_string(), data)
                    }
                    Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
                }
            } else {
                let status_code = status.as_u16();
                let body_text = resp.text().unwrap_or_default();
                let error_msg = serde_json::from_str::<Value>(&body_text)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or(v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| format!("HTTP {}", status_code));
                tracing::warn!(
                    op = "core.workflowRuns.get.failed",
                    status = status_code,
                    "Workflow run fetch failed: {}",
                    error_msg
                );
                Response::err(
                    id.to_string(),
                    "WORKFLOW_RUN_GET_FAILED",
                    &format!("HTTP {}: {}", status_code, error_msg),
                )
            }
        }
        Err(e) => {
            if e.is_connect() {
                Response::err(
                    id.to_string(),
                    "ENGINE_UNAVAILABLE",
                    &format!("Cannot connect to engine at {}. Is the engine running?", engine_url),
                )
            } else {
                Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string())
            }
        }
    }
}

// =============================================================================
// Execution Plans (engine API proxies)
// =============================================================================

/// Reusable: authenticated GET proxy with optional query params.
/// `query_keys` names payload fields to forward as ?key=value.
fn handle_execution_proxy_get(
    id: &str,
    payload: &Value,
    path: &str,
    action: &str,
    query_keys: &[&str],
) -> Response {
    let engine_url = config::engine_url();
    let token = match get_cached_or_fresh_token(engine_url) {
        Ok(t) => t,
        Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    let mut url = format!("{}{}", engine_url, path);

    // Build query string from payload fields
    let mut qs_parts: Vec<String> = Vec::new();
    for key in query_keys {
        if let Some(val) = payload.get(*key) {
            if let Some(s) = val.as_str() {
                qs_parts.push(format!("{}={}", key, s));
            } else if let Some(n) = val.as_i64() {
                qs_parts.push(format!("{}={}", key, n));
            }
        }
    }
    if !qs_parts.is_empty() {
        url = format!("{}?{}", url, qs_parts.join("&"));
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(op = "core.execution.proxy", correlation_id = %request_id, action = %action, path = %path, "Proxying to engine");
    let send = |bearer: &str| -> Result<reqwest::blocking::Response, reqwest::Error> {
        client
            .get(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", bearer))
            .header("X-EKKA-PROOF-TYPE", "jwt")
            .header("X-REQUEST-ID", &request_id)
            .header("X-EKKA-CORRELATION-ID", &request_id)
            .header("X-EKKA-MODULE", "desktop")
            .header("X-EKKA-ACTION", action)
            .header("X-EKKA-CLIENT", config::app_slug())
            .header("X-EKKA-CLIENT-VERSION", "0.2.0")
            .send()
    };

    let resp = match send(&token.token) {
        Ok(r) => r,
        Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    };

    if resp.status().as_u16() == 401 {
        clear_auth_cache();
        let retry_token = match get_cached_or_fresh_token(engine_url) {
            Ok(t) => t,
            Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
        };
        let retry_resp = match send(&retry_token.token) {
            Ok(r) => r,
            Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
        };
        return parse_proxy_response(id, retry_resp);
    }

    parse_proxy_response(id, resp)
}

/// Reusable: authenticated GET proxy for /path/{id}
fn handle_execution_proxy_get_by_id(
    id: &str,
    payload: &Value,
    id_field: &str,
    base_path: &str,
    action: &str,
) -> Response {
    let resource_id = match payload.get(id_field).and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", &format!("'{}' is required", id_field)),
    };
    let path = format!("{}/{}", base_path, resource_id);
    handle_execution_proxy_get(id, payload, &path, action, &[])
}

/// execution.plans.runs.list — GET /engine/admin/execution/plans/{planId}/runs
fn handle_execution_plan_runs_list(id: &str, payload: &Value) -> Response {
    let plan_id = match payload.get("planId").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "'planId' is required"),
    };
    let path = format!("/engine/admin/execution/plans/{}/runs", plan_id);
    handle_execution_proxy_get(id, payload, &path, "execution.plans.runs.list", &["limit", "offset"])
}

/// execution.runs.events — GET /engine/admin/execution/runs/{runId}/events
fn handle_execution_runs_events(id: &str, payload: &Value) -> Response {
    let run_id = match payload.get("runId").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "'runId' is required"),
    };
    let path = format!("/engine/admin/execution/runs/{}/events", run_id);
    handle_execution_proxy_get(id, payload, &path, "execution.runs.events", &[])
}

/// execution.runs.start — POST /engine/execution/runs
fn handle_execution_runs_start(id: &str, payload: &Value) -> Response {
    let engine_url = config::engine_url();
    let token = match get_cached_or_fresh_token(engine_url) {
        Ok(t) => t,
        Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    let request_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(op = "core.execution.runs.start.http", correlation_id = %request_id, "Proxying to engine");
    let body = serde_json::json!({
        "plan_id": payload.get("plan_id"),
        "inputs": payload.get("inputs").unwrap_or(&serde_json::json!({})),
    });

    let send = |bearer: &str| -> Result<reqwest::blocking::Response, reqwest::Error> {
        client
            .post(format!("{}/engine/execution/runs", engine_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", bearer))
            .header("X-EKKA-PROOF-TYPE", "jwt")
            .header("X-REQUEST-ID", &request_id)
            .header("X-EKKA-CORRELATION-ID", &request_id)
            .header("X-EKKA-MODULE", "desktop")
            .header("X-EKKA-ACTION", "execution.runs.start")
            .header("X-EKKA-CLIENT", config::app_slug())
            .header("X-EKKA-CLIENT-VERSION", "0.2.0")
            .json(&body)
            .send()
    };

    let resp = match send(&token.token) {
        Ok(r) => r,
        Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    };

    if resp.status().as_u16() == 401 {
        clear_auth_cache();
        let retry_token = match get_cached_or_fresh_token(engine_url) {
            Ok(t) => t,
            Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
        };
        let retry_resp = match send(&retry_token.token) {
            Ok(r) => r,
            Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
        };
        return parse_proxy_response(id, retry_resp);
    }

    parse_proxy_response(id, resp)
}

/// Parse an engine HTTP response into a JSON-RPC Response (reused by all execution proxies)
fn parse_proxy_response(id: &str, resp: reqwest::blocking::Response) -> Response {
    let status = resp.status();
    if status.is_success() {
        match resp.json::<serde_json::Value>() {
            Ok(data) => Response::ok(id.to_string(), data),
            Err(e) => Response::err(id.to_string(), "PARSE_ERROR", &e.to_string()),
        }
    } else {
        let status_code = status.as_u16();
        let body = resp.text().unwrap_or_default();
        let msg = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("message").or(v.get("error")).and_then(|m| m.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("HTTP {}", status_code));
        Response::err(id.to_string(), "EXECUTION_PROXY_FAILED", &format!("HTTP {}: {}", status_code, msg))
    }
}

// =============================================================================
// Debug (stateless)
// =============================================================================

/// admin.logs — proxy GET /engine/admin/logs with query params
fn handle_admin_logs(id: &str, payload: &Value) -> Response {
    let correlation_id = match payload.get("correlation_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Response::err(id.to_string(), "INVALID_PAYLOAD", "'correlation_id' is required"),
    };
    let since = payload.get("since").and_then(|v| v.as_str()).unwrap_or("10m");
    let limit = payload.get("limit").and_then(|v| v.as_i64()).unwrap_or(200);
    let service = payload.get("service").and_then(|v| v.as_str());

    let engine_url = config::engine_url();
    let token = match get_cached_or_fresh_token(engine_url) {
        Ok(t) => t,
        Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
    };
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Response::err(id.to_string(), "HTTP_CLIENT_ERROR", &e.to_string()),
    };

    let mut url = format!(
        "{}/engine/admin/logs?correlation_id={}&since={}&limit={}",
        engine_url,
        correlation_id,
        since,
        limit,
    );
    if let Some(svc) = service {
        url.push_str(&format!("&service={}", svc));
    }

    let request_id = uuid::Uuid::new_v4().to_string();
    tracing::info!(op = "core.admin.logs", correlation_id = %correlation_id, "Fetching logs");

    let send = |bearer: &str| -> Result<reqwest::blocking::Response, reqwest::Error> {
        client
            .get(&url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", bearer))
            .header("X-EKKA-PROOF-TYPE", "jwt")
            .header("X-REQUEST-ID", &request_id)
            .header("X-EKKA-CORRELATION-ID", &request_id)
            .header("X-EKKA-MODULE", "desktop")
            .header("X-EKKA-ACTION", "admin.logs")
            .header("X-EKKA-CLIENT", config::app_slug())
            .header("X-EKKA-CLIENT-VERSION", "0.2.0")
            .send()
    };

    let resp = match send(&token.token) {
        Ok(r) => r,
        Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
    };

    if resp.status().as_u16() == 401 {
        clear_auth_cache();
        let retry_token = match get_cached_or_fresh_token(engine_url) {
            Ok(t) => t,
            Err(e) => return Response::err(id.to_string(), "NOT_AUTHENTICATED", &e),
        };
        let retry_resp = match send(&retry_token.token) {
            Ok(r) => r,
            Err(e) => return Response::err(id.to_string(), "REQUEST_FAILED", &e.to_string()),
        };
        return parse_proxy_response(id, retry_resp);
    }

    parse_proxy_response(id, resp)
}

// =============================================================================

/// debug.isDevMode — check if running in development mode
///
/// Reads EKKA_ENV environment variable directly (no host state needed).
/// Returns { isDevMode: bool }.
fn handle_is_dev_mode(id: &str) -> Response {
    tracing::info!(op = "core.debug.isDevMode", "Handling debug.isDevMode");

    let is_dev = std::env::var("EKKA_ENV")
        .map(|v| v == "development")
        .unwrap_or(false);

    Response::ok(
        id.to_string(),
        serde_json::json!({ "isDevMode": is_dev }),
    )
}

// =============================================================================
// Main Loop
// =============================================================================

fn main() {
    // Initialize tracing to stderr (stdout is reserved for JSON-RPC)
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ekka_desktop_core=info".parse().unwrap()),
        )
        .with_target(true)
        .init();

    tracing::info!(op = "core.startup", "EKKA Desktop Core starting (stdio JSON-RPC)");

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(op = "core.stdin.error", error = %e, "Failed to read stdin");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse request
        let req: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                // Can't correlate to an ID, write error with empty ID
                let resp = Response::err(
                    String::new(),
                    "PARSE_ERROR",
                    &format!("Invalid JSON request: {}", e),
                );
                let _ = serde_json::to_writer(&mut stdout_lock, &resp);
                let _ = stdout_lock.write_all(b"\n");
                let _ = stdout_lock.flush();
                continue;
            }
        };

        tracing::debug!(op = "core.dispatch", id = %req.id, op_name = %req.op, "Dispatching");

        // Dispatch and respond
        let resp = dispatch(&req);

        if let Err(e) = serde_json::to_writer(&mut stdout_lock, &resp) {
            tracing::error!(op = "core.stdout.error", error = %e, "Failed to write response");
            break;
        }
        if let Err(e) = stdout_lock.write_all(b"\n") {
            tracing::error!(op = "core.stdout.error", error = %e, "Failed to write newline");
            break;
        }
        if let Err(e) = stdout_lock.flush() {
            tracing::error!(op = "core.stdout.error", error = %e, "Failed to flush stdout");
            break;
        }
    }

    tracing::info!(op = "core.shutdown", "EKKA Desktop Core shutting down");
}
