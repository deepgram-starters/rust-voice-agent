// Rust Voice Agent Starter - Backend Server
//
// Simple WebSocket proxy to Deepgram's Voice Agent API using Axum.
// Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
//
// Routes:
//
//   GET  /api/session       - Issue signed session token
//   WS   /api/voice-agent   - WebSocket proxy to Deepgram Agent API (auth required)
//   GET  /api/metadata      - Project metadata from deepgram.toml
//   GET  /health            - Health check

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite};
use tower_http::cors::{Any, CorsLayer};

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Application configuration loaded from environment variables.
#[derive(Clone)]
struct AppConfig {
    deepgram_api_key: String,
    deepgram_agent_url: String,
    port: String,
    host: String,
    session_secret: Vec<u8>,
}

impl AppConfig {
    /// Load configuration from environment variables with sensible defaults.
    fn from_env() -> Self {
        // Load .env file if it exists (development convenience)
        let _ = dotenvy::dotenv();

        let deepgram_api_key = std::env::var("DEEPGRAM_API_KEY").unwrap_or_else(|_| {
            eprintln!(
                "ERROR: DEEPGRAM_API_KEY environment variable is required\n\
                 Please copy sample.env to .env and add your API key"
            );
            std::process::exit(1);
        });

        let session_secret = match std::env::var("SESSION_SECRET") {
            Ok(s) if !s.is_empty() => s.into_bytes(),
            _ => {
                let mut buf = [0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut buf);
                buf.to_vec()
            }
        };

        Self {
            deepgram_api_key,
            deepgram_agent_url: "wss://agent.deepgram.com/v1/agent/converse".to_string(),
            port: std::env::var("PORT").unwrap_or_else(|_| "8081".to_string()),
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            session_secret,
        }
    }
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

/// JWT expiry duration in seconds (1 hour).
const JWT_EXPIRY_SECS: i64 = 3600;

/// JWT claims structure for session tokens.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iat: i64,
    exp: i64,
}

/// Creates a signed JWT with a 1-hour expiry.
fn issue_token(secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        iat: now,
        exp: now + JWT_EXPIRY_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Verifies a JWT token string and returns an error if invalid.
fn validate_token(token_str: &str, secret: &[u8]) -> Result<(), jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.validate_exp = true;
    decode::<Claims>(token_str, &DecodingKey::from_secret(secret), &validation)?;
    Ok(())
}

/// Extracts and validates a JWT from the `access_token.<jwt>` subprotocol.
/// Returns the full subprotocol string if valid, None if invalid.
fn validate_ws_token(protocols: &[String], secret: &[u8]) -> Option<String> {
    for proto in protocols {
        if let Some(token_str) = proto.strip_prefix("access_token.") {
            if validate_token(token_str, secret).is_ok() {
                return Some(proto.clone());
            }
        }
    }
    None
}

// ============================================================================
// METADATA - deepgram.toml parser
// ============================================================================

/// Represents the structure of deepgram.toml for metadata extraction.
#[derive(serde::Deserialize)]
struct DeepgramToml {
    meta: Option<toml::Table>,
}

// ============================================================================
// WEBSOCKET HELPERS
// ============================================================================

/// Reserved WebSocket close codes that cannot be set by applications (RFC 6455).
const RESERVED_CLOSE_CODES: [u16; 4] = [1004, 1005, 1006, 1015];

/// Return a valid WebSocket close code, translating reserved codes to 1000 (normal closure).
fn get_safe_close_code(code: u16) -> u16 {
    if (1000..=4999).contains(&code) && !RESERVED_CLOSE_CODES.contains(&code) {
        code
    } else {
        1000
    }
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

/// GET /api/session - Issue a signed JWT session token.
async fn handle_session(State(config): State<Arc<AppConfig>>) -> impl IntoResponse {
    match issue_token(&config.session_secret) {
        Ok(token) => Json(json!({ "token": token })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to generate session token"})),
        )
            .into_response(),
    }
}

/// GET /api/metadata - Return project metadata from deepgram.toml.
async fn handle_metadata() -> impl IntoResponse {
    let contents = match std::fs::read_to_string("deepgram.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading deepgram.toml: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": "Failed to read metadata from deepgram.toml"
                })),
            )
                .into_response();
        }
    };

    let cfg: DeepgramToml = match toml::from_str(&contents) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing deepgram.toml: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": "Failed to parse deepgram.toml"
                })),
            )
                .into_response();
        }
    };

    match cfg.meta {
        Some(meta) => {
            let value: Value = toml::Value::Table(meta).try_into().unwrap_or(json!({}));
            Json(value).into_response()
        }
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Missing [meta] section in deepgram.toml"
            })),
        )
            .into_response(),
    }
}

/// GET /health - Health check endpoint.
async fn handle_health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

// ============================================================================
// WEBSOCKET PROXY HANDLER
// ============================================================================

/// WS /api/voice-agent - Proxy WebSocket connections to Deepgram's Voice Agent API.
/// Forwards all messages (JSON and binary) bidirectionally without modification.
async fn handle_voice_agent(
    State(config): State<Arc<AppConfig>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Extract and validate JWT from access_token.<jwt> subprotocol.
    // Axum's WebSocketUpgrade parses Sec-WebSocket-Protocol into its protocols() list.
    let protocols: Vec<String> = ws.protocols().map(|p| p.to_string()).collect();
    let valid_proto = match validate_ws_token(&protocols, &config.session_secret) {
        Some(proto) => proto,
        None => {
            eprintln!("WebSocket auth failed: invalid or missing token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    // Accept the WebSocket connection, echoing back the validated subprotocol
    ws.protocols([valid_proto])
        .on_upgrade(move |socket| handle_voice_agent_socket(socket, config))
}

/// Handle the upgraded WebSocket connection: connect to Deepgram and proxy messages.
async fn handle_voice_agent_socket(client_ws: WebSocket, config: Arc<AppConfig>) {
    println!("Client connected to /api/voice-agent");

    // Connect to Deepgram Voice Agent API
    // No query parameters needed -- config is sent via JSON after connection
    println!("Initiating Deepgram connection...");

    let url = match url::Url::parse(&config.deepgram_agent_url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Failed to parse Deepgram agent URL: {}", e);
            return;
        }
    };

    let request = match tungstenite::http::Request::builder()
        .uri(config.deepgram_agent_url.as_str())
        .header("Host", url.host_str().unwrap_or("agent.deepgram.com"))
        .header("Authorization", format!("Token {}", config.deepgram_api_key))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to build Deepgram request: {}", e);
            return;
        }
    };

    let (deepgram_ws, _response) = match connect_async(request).await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to connect to Deepgram: {}", e);
            // Send error message to client before closing
            let (mut sender, _) = client_ws.split();
            let err_msg = json!({
                "type": "Error",
                "description": "Failed to establish proxy connection",
                "code": "CONNECTION_FAILED"
            });
            let _ = sender
                .send(Message::Text(err_msg.to_string().into()))
                .await;
            let _ = sender.close().await;
            return;
        }
    };

    println!("Connected to Deepgram Agent API");

    // Split both WebSocket connections into sender/receiver halves
    let (client_sender, client_receiver) = client_ws.split();
    let (deepgram_sender, deepgram_receiver) = deepgram_ws.split();

    // Wrap senders in Arc<Mutex> for shared access
    let client_sender = Arc::new(Mutex::new(client_sender));
    let deepgram_sender = Arc::new(Mutex::new(deepgram_sender));

    // Forward messages: Deepgram -> Client
    let client_sender_clone = client_sender.clone();
    let deepgram_to_client = {
        let mut deepgram_receiver = deepgram_receiver;
        async move {
            while let Some(msg) = deepgram_receiver.next().await {
                match msg {
                    Ok(tungstenite::Message::Text(text)) => {
                        let mut sender = client_sender_clone.lock().await;
                        if sender.send(Message::Text(text.into())).await.is_err() {
                            eprintln!("Error forwarding text to client");
                            break;
                        }
                    }
                    Ok(tungstenite::Message::Binary(data)) => {
                        let mut sender = client_sender_clone.lock().await;
                        if sender.send(Message::Binary(data.into())).await.is_err() {
                            eprintln!("Error forwarding binary to client");
                            break;
                        }
                    }
                    Ok(tungstenite::Message::Close(frame)) => {
                        let code = frame
                            .as_ref()
                            .map(|f| get_safe_close_code(f.code.into()))
                            .unwrap_or(1000);
                        let reason = frame
                            .as_ref()
                            .map(|f| f.reason.to_string())
                            .unwrap_or_default();
                        if code == 1000 || code == 1001 {
                            println!("Deepgram connection closed normally");
                        } else {
                            eprintln!("Deepgram connection closed: {} {}", code, reason);
                        }
                        let mut sender = client_sender_clone.lock().await;
                        let _ = sender
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code,
                                reason: reason.into(),
                            })))
                            .await;
                        break;
                    }
                    Ok(tungstenite::Message::Ping(data)) => {
                        let mut sender = client_sender_clone.lock().await;
                        let _ = sender.send(Message::Ping(data.into())).await;
                    }
                    Ok(tungstenite::Message::Pong(data)) => {
                        let mut sender = client_sender_clone.lock().await;
                        let _ = sender.send(Message::Pong(data.into())).await;
                    }
                    Ok(tungstenite::Message::Frame(_)) => {
                        // Raw frames are not forwarded
                    }
                    Err(e) => {
                        eprintln!("Deepgram read error: {}", e);
                        let mut sender = client_sender_clone.lock().await;
                        let _ = sender
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1000,
                                reason: "".into(),
                            })))
                            .await;
                        break;
                    }
                }
            }
        }
    };

    // Forward messages: Client -> Deepgram
    let deepgram_sender_clone = deepgram_sender.clone();
    let client_to_deepgram = {
        let mut client_receiver = client_receiver;
        async move {
            while let Some(msg) = client_receiver.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        let mut sender = deepgram_sender_clone.lock().await;
                        if sender
                            .send(tungstenite::Message::Text(text.into()))
                            .await
                            .is_err()
                        {
                            eprintln!("Error forwarding text to Deepgram");
                            break;
                        }
                    }
                    Ok(Message::Binary(data)) => {
                        let mut sender = deepgram_sender_clone.lock().await;
                        if sender
                            .send(tungstenite::Message::Binary(data.into()))
                            .await
                            .is_err()
                        {
                            eprintln!("Error forwarding binary to Deepgram");
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => {
                        println!("Client disconnected normally");
                        break;
                    }
                    Ok(Message::Ping(data)) => {
                        let mut sender = deepgram_sender_clone.lock().await;
                        let _ = sender
                            .send(tungstenite::Message::Ping(data.into()))
                            .await;
                    }
                    Ok(Message::Pong(data)) => {
                        let mut sender = deepgram_sender_clone.lock().await;
                        let _ = sender
                            .send(tungstenite::Message::Pong(data.into()))
                            .await;
                    }
                    Err(e) => {
                        eprintln!("Client read error: {}", e);
                        break;
                    }
                }
            }
        }
    };

    // Wait for either side to close, then clean up both
    tokio::select! {
        _ = deepgram_to_client => {
            println!("Deepgram disconnected, closing client connection");
            let mut sender = client_sender.lock().await;
            let _ = sender.close().await;
        }
        _ = client_to_deepgram => {
            println!("Client disconnected, closing Deepgram connection");
            let mut sender = deepgram_sender.lock().await;
            let _ = sender
                .send(tungstenite::Message::Close(Some(
                    tungstenite::protocol::CloseFrame {
                        code: tungstenite::protocol::frame::coding::CloseCode::Normal,
                        reason: "Client disconnected".into(),
                    },
                )))
                .await;
            let _ = sender.close().await;
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    // Load configuration from environment variables
    let config = Arc::new(AppConfig::from_env());

    // Configure CORS for development
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the Axum router
    let app = Router::new()
        .route("/api/session", get(handle_session))
        .route("/api/metadata", get(handle_metadata))
        .route("/api/voice-agent", get(handle_voice_agent))
        .route("/health", get(handle_health))
        .layer(cors)
        .with_state(config.clone());

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("Failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    // Print startup banner
    let separator = "=".repeat(70);
    println!("{}", separator);
    println!(
        "Backend API Server running at http://localhost:{}",
        config.port
    );
    println!();
    println!("GET  /api/session");
    println!("WS   /api/voice-agent (auth required)");
    println!("GET  /api/metadata");
    println!("GET  /health");
    println!("{}", separator);

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            eprintln!("Server error: {}", e);
            std::process::exit(1);
        });

    println!("Shutdown complete");
}

/// Wait for SIGINT or SIGTERM to trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            println!("\nSIGINT signal received: starting graceful shutdown...");
        }
        _ = terminate => {
            println!("\nSIGTERM signal received: starting graceful shutdown...");
        }
    }
}
