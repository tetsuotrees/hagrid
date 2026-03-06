use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use hagrid::drift::DriftCheckResult;
use hagrid::index::models::GroupStatus;
use hagrid::notify::{
    build_audit_event, build_drift_event, build_rotate_event, deliver_to_webhook,
    dispatch_with_config, load_notification_config_from_path, EventKind, NotificationConfig,
    NotificationEvent, WebhookConfig,
};
use hagrid::policy::{AffectedRef, PolicyResult, Severity};
use hagrid::rotate::{FileRotateResult, RotateResult};
use tempfile::TempDir;

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let n = stream.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }

        request.extend_from_slice(&chunk[..n]);

        if header_end.is_none() {
            if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let end = pos + 4;
                header_end = Some(end);

                let headers = String::from_utf8_lossy(&request[..end]);
                content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
            }
        }

        if let Some(end) = header_end {
            if request.len() >= end + content_length {
                break;
            }
        }
    }

    String::from_utf8_lossy(&request).to_string()
}

fn write_ok_response(stream: &mut TcpStream) {
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    stream.write_all(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}

// ── Config loading tests ────────────────────────────────────────────

#[test]
fn test_config_missing_file_returns_default() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("nonexistent.toml");
    let config = load_notification_config_from_path(&path);
    assert!(!config.enabled);
    assert_eq!(config.timeout_ms, 2000);
    assert!(config.webhook.is_empty());
}

#[test]
fn test_config_malformed_returns_default() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bad.toml");
    std::fs::write(&path, "enabled = [not valid toml structure").unwrap();
    let config = load_notification_config_from_path(&path);
    assert!(!config.enabled);
}

#[test]
fn test_config_disabled_is_noop() {
    let config = NotificationConfig {
        enabled: false,
        timeout_ms: 2000,
        webhook: vec![WebhookConfig {
            name: "test".to_string(),
            url: "http://127.0.0.1:1/should-not-be-called".to_string(),
            events: vec![],
        }],
    };

    let event = NotificationEvent {
        event: EventKind::DriftDetected,
        timestamp: "2026-03-06T00:00:00Z".to_string(),
        hostname: "test".to_string(),
        exit_code: 3,
        summary: "test".to_string(),
        details: serde_json::json!({}),
    };

    // Should return immediately without attempting any HTTP calls
    dispatch_with_config(&config, &event);
}

#[test]
fn test_config_parses_full_example() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("notifications.toml");
    std::fs::write(
        &path,
        r#"
enabled = true
timeout_ms = 3000

[[webhook]]
name = "local-dev"
url = "http://127.0.0.1:8787/hagrid"
events = ["drift_detected", "policy_violations", "rotation_failure"]
"#,
    )
    .unwrap();

    let config = load_notification_config_from_path(&path);
    assert!(config.enabled);
    assert_eq!(config.timeout_ms, 3000);
    assert_eq!(config.webhook.len(), 1);
    assert_eq!(config.webhook[0].name, "local-dev");
    assert_eq!(config.webhook[0].events.len(), 3);
}

#[test]
fn test_config_serde_defaults() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("minimal.toml");
    std::fs::write(&path, "enabled = true\n").unwrap();

    let config = load_notification_config_from_path(&path);
    assert!(config.enabled);
    assert_eq!(config.timeout_ms, 2000);
    assert!(config.webhook.is_empty());
}

// ── Payload safety tests ────────────────────────────────────────────

#[test]
fn test_drift_payload_no_secret_values() {
    let results = vec![DriftCheckResult {
        group_label: "aws-key".to_string(),
        group_id: uuid::Uuid::new_v4(),
        status: GroupStatus::Drifted,
        member_fingerprints: {
            let mut m = HashMap::new();
            m.insert("identity_abc".to_string(), "fp_123456".to_string());
            m.insert("identity_def".to_string(), "fp_789012".to_string());
            m
        },
        drifted: true,
        removed_members: vec![],
        pruned_members: vec![],
    }];

    let event = build_drift_event(3, &results);
    let json = serde_json::to_string(&event).unwrap();

    // Must NOT contain member_fingerprints or identity_keys
    assert!(!json.contains("fp_123456"));
    assert!(!json.contains("fp_789012"));
    assert!(!json.contains("identity_abc"));
    assert!(!json.contains("identity_def"));
    // Must contain expected metadata
    assert!(json.contains("drift_detected"));
    assert!(json.contains("aws-key"));
}

#[test]
fn test_audit_payload_no_secret_values() {
    let results = vec![PolicyResult {
        rule_name: "no-sprawl".to_string(),
        severity: Severity::Violation,
        message: "too many refs".to_string(),
        affected_references: vec![AffectedRef {
            identity_key: "secret_identity_key_abc123".to_string(),
            display_label: "AWS_KEY".to_string(),
            file_path: "/home/user/.env".to_string(),
        }],
    }];

    let event = build_audit_event(4, &results);
    let json = serde_json::to_string(&event).unwrap();

    // Must NOT contain identity_keys
    assert!(!json.contains("secret_identity_key_abc123"));
    // Must contain expected metadata
    assert!(json.contains("policy_violations"));
    assert!(json.contains("no-sprawl"));
    assert!(json.contains("/home/user/.env"));
}

#[test]
fn test_rotate_payload_no_secret_values() {
    let result = RotateResult {
        total_members: 3,
        succeeded: 1,
        failed: 2,
        skipped: 0,
        file_results: vec![
            FileRotateResult {
                file_path: "/app/.env".to_string(),
                identity_key: "secret_identity_key_xyz789".to_string(),
                success: true,
                error: None,
                backed_up: false,
                verified: true,
            },
            FileRotateResult {
                file_path: "/app/config.json".to_string(),
                identity_key: "secret_identity_key_aaa111".to_string(),
                success: false,
                error: Some("write failed".to_string()),
                backed_up: false,
                verified: false,
            },
        ],
    };

    let event = build_rotate_event(5, "db-password", &result);
    let json = serde_json::to_string(&event).unwrap();

    // Must NOT contain identity_keys
    assert!(!json.contains("secret_identity_key_xyz789"));
    assert!(!json.contains("secret_identity_key_aaa111"));
    // Must contain expected metadata
    assert!(json.contains("rotation_failure"));
    assert!(json.contains("db-password"));
    assert!(json.contains("/app/config.json"));
    assert!(json.contains("write failed"));
}

// ── Webhook delivery tests ──────────────────────────────────────────

#[test]
fn test_webhook_delivery_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let hook = WebhookConfig {
        name: "test".to_string(),
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
    };

    let payload = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();

    // Spawn a thread to accept the connection and respond
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        write_ok_response(&mut stream);

        request
    });

    let result = deliver_to_webhook(&hook, &payload, 5000);
    assert!(result.is_ok(), "delivery failed: {:?}", result.err());

    let request = handle.join().unwrap();
    assert!(request.contains("POST /hook"));
    assert!(request.contains("application/json"));
    assert!(request.contains(r#"{"test":true}"#));
}

#[test]
fn test_webhook_delivery_timeout() {
    // Bind but never accept — causes a timeout
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let hook = WebhookConfig {
        name: "slow".to_string(),
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
    };

    let payload = b"{}";

    // Spawn a thread that accepts but never responds
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Read the request but never respond
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        std::thread::sleep(Duration::from_secs(10));
    });

    let result = deliver_to_webhook(&hook, payload, 200);
    assert!(result.is_err());

    // Clean up the blocking thread
    drop(handle);
}

#[test]
fn test_webhook_delivery_connection_refused() {
    let hook = WebhookConfig {
        name: "dead".to_string(),
        url: "http://127.0.0.1:1/hook".to_string(), // port 1 is almost certainly closed
        events: vec![],
    };

    let result = deliver_to_webhook(&hook, b"{}", 1000);
    assert!(result.is_err());
}

// ── Event filtering tests ───────────────────────────────────────────

#[test]
fn test_webhook_event_filter_match() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let config = NotificationConfig {
        enabled: true,
        timeout_ms: 5000,
        webhook: vec![WebhookConfig {
            name: "filtered".to_string(),
            url: format!("http://127.0.0.1:{}/hook", port),
            events: vec!["drift_detected".to_string()],
        }],
    };

    let event = NotificationEvent {
        event: EventKind::DriftDetected,
        timestamp: "2026-03-06T00:00:00Z".to_string(),
        hostname: "test".to_string(),
        exit_code: 3,
        summary: "test drift".to_string(),
        details: serde_json::json!({}),
    };

    // Accept the connection in a background thread
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        write_ok_response(&mut stream);
        request
    });

    dispatch_with_config(&config, &event);

    let request = handle.join().unwrap();
    assert!(request.contains("drift_detected"));
}

#[test]
fn test_webhook_event_filter_mismatch() {
    // Use a listener that we'll check was NOT contacted
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener
        .set_nonblocking(true)
        .unwrap();

    let config = NotificationConfig {
        enabled: true,
        timeout_ms: 1000,
        webhook: vec![WebhookConfig {
            name: "wrong-filter".to_string(),
            url: format!("http://127.0.0.1:{}/hook", port),
            events: vec!["rotation_failure".to_string()], // only rotation
        }],
    };

    let event = NotificationEvent {
        event: EventKind::DriftDetected, // drift — should NOT match
        timestamp: "2026-03-06T00:00:00Z".to_string(),
        hostname: "test".to_string(),
        exit_code: 3,
        summary: "test drift".to_string(),
        details: serde_json::json!({}),
    };

    dispatch_with_config(&config, &event);

    // Give a moment then check no connection was made
    std::thread::sleep(Duration::from_millis(100));
    assert!(listener.accept().is_err(), "webhook should not have been contacted");
}

#[test]
fn test_webhook_empty_events_receives_all() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let config = NotificationConfig {
        enabled: true,
        timeout_ms: 5000,
        webhook: vec![WebhookConfig {
            name: "catch-all".to_string(),
            url: format!("http://127.0.0.1:{}/hook", port),
            events: vec![], // empty = subscribe to all
        }],
    };

    let event = NotificationEvent {
        event: EventKind::PolicyViolations,
        timestamp: "2026-03-06T00:00:00Z".to_string(),
        hostname: "test".to_string(),
        exit_code: 4,
        summary: "test audit".to_string(),
        details: serde_json::json!({}),
    };

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        write_ok_response(&mut stream);
        request
    });

    dispatch_with_config(&config, &event);

    let request = handle.join().unwrap();
    assert!(request.contains("policy_violations"));
}

// ── Failure isolation test ──────────────────────────────────────────

#[test]
fn test_dispatch_with_config_failure_does_not_panic() {
    let config = NotificationConfig {
        enabled: true,
        timeout_ms: 200,
        webhook: vec![WebhookConfig {
            name: "dead".to_string(),
            url: "http://127.0.0.1:1/hook".to_string(),
            events: vec![],
        }],
    };

    let event = NotificationEvent {
        event: EventKind::RotationFailure,
        timestamp: "2026-03-06T00:00:00Z".to_string(),
        hostname: "test".to_string(),
        exit_code: 5,
        summary: "test rotation failure".to_string(),
        details: serde_json::json!({}),
    };

    // Must not panic — just logs to stderr
    dispatch_with_config(&config, &event);
}
