use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{
        header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, SET_COOKIE},
        HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode,
    },
    Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::time::sleep;
use tower::ServiceExt;
use vexa_vm::{
    config::{Config, HypervisorMode},
    models::{HostMetric, NewJob, NewVm, VmMetric},
    services::{background, traffic},
    state::AppState,
};

const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "IntegrationAdmin!234";
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl TestResponse {
    fn assert_status(&self, expected: StatusCode) {
        assert_eq!(
            self.status,
            expected,
            "unexpected response status; body: {}",
            String::from_utf8_lossy(&self.body)
        );
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "response was not JSON ({error}); status {}; body: {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).expect("response body should be UTF-8")
    }
}

#[derive(Clone)]
struct AdminSession {
    cookie: String,
    csrf: String,
}

struct Fixture {
    _root: TempDir,
    app: Router,
    state: Arc<AppState>,
    iso_dir: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().expect("create test directory");
        let iso_dir = root.path().join("isos");
        let config = Config {
            bind: "127.0.0.1:18080".parse().unwrap(),
            public_url: "http://127.0.0.1:18080".into(),
            database_path: root.path().join("vexa.db"),
            template_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates"),
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static"),
            master_key: [0x5a; 32],
            bootstrap_admin: ADMIN_USERNAME.into(),
            bootstrap_password: Some(ADMIN_PASSWORD.into()),
            secure_cookies: false,
            hypervisor_mode: HypervisorMode::Mock,
            libvirt_uri: "qemu:///system".into(),
            vm_storage: root.path().join("vms"),
            iso_storage: iso_dir.clone(),
            cloud_init_storage: root.path().join("cloud-init"),
            guest_tools_socket_dir: root.path().join("guest-tools-sockets"),
            guest_tools_linux_x86_64_artifact: None,
            guest_tools_windows_x86_64_artifact: None,
            guest_tools_version: "0.1.0".into(),
            network_bridge: "virbr0".into(),
            public_interface: None,
            vnc_ttl: Duration::from_secs(600),
            metrics_interval: Duration::from_secs(5),
        }
        .validate()
        .expect("valid test config");
        std::fs::create_dir_all(&config.vm_storage).expect("create mock VM storage");
        let (app, state) = vexa_vm::build(config).await.expect("initialize test app");
        background::spawn(state.clone());
        Self {
            _root: root,
            app,
            state,
            iso_dir,
        }
    }

    async fn raw(
        &self,
        method: Method,
        uri: &str,
        body: Vec<u8>,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
    ) -> TestResponse {
        let body_length = body.len();
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::from(body))
            .expect("build request");
        if body_length > 0 {
            request.headers_mut().insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&body_length.to_string()).expect("valid content length"),
            );
        }
        if let Some(content_type) = content_type {
            request.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_str(content_type).expect("valid content type"),
            );
        }
        for (name, value) in headers {
            request.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).expect("valid test header name"),
                HeaderValue::from_str(value).expect("valid test header value"),
            );
        }
        let response = self.app.clone().oneshot(request).await.expect("router response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("read response body")
            .to_vec();
        TestResponse {
            status,
            headers,
            body,
        }
    }

    async fn get(&self, uri: &str) -> TestResponse {
        self.raw(Method::GET, uri, Vec::new(), None, &[]).await
    }

    async fn json_request(&self, method: Method, uri: &str, body: Value) -> TestResponse {
        self.raw(
            method,
            uri,
            serde_json::to_vec(&body).unwrap(),
            Some("application/json"),
            &[],
        )
        .await
    }

    async fn login(&self) -> AdminSession {
        let response = self
            .json_request(
                Method::POST,
                "/api/v1/auth/login",
                json!({"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}),
            )
            .await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.json()["admin"]["username"], ADMIN_USERNAME);
        let session = response_cookie(&response.headers, "vexa_session");
        let csrf = response_cookie(&response.headers, "vexa_csrf");
        AdminSession {
            cookie: format!("vexa_session={session}; vexa_csrf={csrf}"),
            csrf,
        }
    }

    async fn admin_get(&self, session: &AdminSession, uri: &str) -> TestResponse {
        self.raw(
            Method::GET,
            uri,
            Vec::new(),
            None,
            &[(COOKIE.as_str(), &session.cookie)],
        )
        .await
    }

    async fn admin_json(
        &self,
        session: &AdminSession,
        method: Method,
        uri: &str,
        body: Value,
    ) -> TestResponse {
        self.raw(
            method,
            uri,
            serde_json::to_vec(&body).unwrap(),
            Some("application/json"),
            &[
                (COOKIE.as_str(), &session.cookie),
                ("x-csrf-token", &session.csrf),
            ],
        )
        .await
    }

    async fn bearer_get(&self, token: &str, uri: &str) -> TestResponse {
        let authorization = format!("Bearer {token}");
        self.raw(
            Method::GET,
            uri,
            Vec::new(),
            None,
            &[(AUTHORIZATION.as_str(), &authorization)],
        )
        .await
    }

    async fn bearer_json(&self, token: &str, method: Method, uri: &str, body: Value) -> TestResponse {
        self.bearer_json_with_headers(token, method, uri, body, &[]).await
    }

    async fn bearer_json_with_headers(
        &self,
        token: &str,
        method: Method,
        uri: &str,
        body: Value,
        extra_headers: &[(&str, &str)],
    ) -> TestResponse {
        let authorization = format!("Bearer {token}");
        let mut headers = vec![(AUTHORIZATION.as_str(), authorization.as_str())];
        headers.extend_from_slice(extra_headers);
        self.raw(
            method,
            uri,
            serde_json::to_vec(&body).unwrap(),
            Some("application/json"),
            &headers,
        )
        .await
    }

    async fn bearer_empty(&self, token: &str, method: Method, uri: &str) -> TestResponse {
        let authorization = format!("Bearer {token}");
        self.raw(
            method,
            uri,
            Vec::new(),
            None,
            &[(AUTHORIZATION.as_str(), &authorization)],
        )
        .await
    }

    async fn public_get(&self, cookie: &str, uri: &str) -> TestResponse {
        self.raw(Method::GET, uri, Vec::new(), None, &[(COOKIE.as_str(), cookie)])
            .await
    }

    async fn public_json(
        &self,
        cookie: &str,
        csrf: &str,
        method: Method,
        uri: &str,
        body: Value,
    ) -> TestResponse {
        self.raw(
            method,
            uri,
            serde_json::to_vec(&body).unwrap(),
            Some("application/json"),
            &[(COOKIE.as_str(), cookie), ("x-csrf-token", csrf)],
        )
        .await
    }

    async fn public_empty(&self, cookie: &str, csrf: &str, method: Method, uri: &str) -> TestResponse {
        self.raw(
            method,
            uri,
            Vec::new(),
            None,
            &[(COOKIE.as_str(), cookie), ("x-csrf-token", csrf)],
        )
        .await
    }

    async fn wait_for_job(&self, token: &str, id: &str) -> Value {
        for _ in 0..120 {
            let response = self.bearer_get(token, &format!("/api/v1/jobs/{id}")).await;
            response.assert_status(StatusCode::OK);
            let operation = response.json()["operation"].clone();
            match operation["status"].as_str() {
                Some("succeeded") => return operation,
                Some("failed" | "cancelled") => {
                    panic!("job {id} did not succeed: {operation}")
                }
                _ => sleep(Duration::from_millis(50)).await,
            }
        }
        panic!("job {id} did not reach a terminal state")
    }

    async fn wait_for_public_job(&self, cookie: &str, id: &str) -> Value {
        for _ in 0..120 {
            let response = self.public_get(cookie, &format!("/api/public/jobs/{id}")).await;
            response.assert_status(StatusCode::OK);
            let operation = response.json()["operation"].clone();
            match operation["status"].as_str() {
                Some("succeeded") => return operation,
                Some("failed" | "cancelled") => {
                    panic!("public job {id} did not succeed: {operation}")
                }
                _ => sleep(Duration::from_millis(50)).await,
            }
        }
        panic!("public job {id} did not reach a terminal state")
    }
}

fn response_cookie(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
        .unwrap_or_else(|| panic!("response did not set cookie {name}"))
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn multipart_image(fields: &[(&str, &str)], filename: &str, bytes: &[u8]) -> (Vec<u8>, String) {
    let boundary = "vexa-integration-boundary-7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes());
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (body, format!("multipart/form-data; boundary={boundary}"))
}

fn operation_id(value: &Value) -> String {
    value["operation"]["id"]
        .as_str()
        .expect("operation id")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_http_management_and_customer_lifecycle() {
    let fixture = Fixture::new().await;

    // Liveness/readiness, public pages, security redirects, and shipped assets.
    let health = fixture.get("/healthz").await;
    health.assert_status(StatusCode::OK);
    assert_eq!(health.json()["ok"], true);
    assert_eq!(health.json()["backend"], "mock");
    let ready = fixture.get("/readyz").await;
    ready.assert_status(StatusCode::OK);
    assert_eq!(ready.json()["ready"], true);
    fixture
        .get("/")
        .await
        .assert_status(StatusCode::TEMPORARY_REDIRECT);
    fixture.get("/login").await.assert_status(StatusCode::OK);
    fixture.get("/overall").await.assert_status(StatusCode::SEE_OTHER);
    let openapi = fixture.get("/api/openapi.json").await;
    openapi.assert_status(StatusCode::OK);
    assert!(openapi.json()["paths"].is_object());
    let javascript = fixture.get("/static/js/app.js").await;
    javascript.assert_status(StatusCode::OK);
    let javascript = javascript.text();
    assert!(javascript.contains("function randomUuid()"));
    assert!(javascript.contains("typeof cryptoApi.randomUUID === \"function\""));
    assert!(!javascript.contains("Idempotency-Key: crypto.randomUUID()"));

    // Login produces both session and CSRF credentials; pages accept the former,
    // while a state-changing cookie request must also provide the latter.
    let admin = fixture.login().await;
    let me = fixture.admin_get(&admin, "/api/v1/auth/me").await;
    me.assert_status(StatusCode::OK);
    assert_eq!(me.json()["admin"]["username"], ADMIN_USERNAME);
    for page in [
        "/overall",
        "/vms",
        "/vms/create",
        "/network",
        "/isos",
        "/settings",
        "/docs",
    ] {
        fixture
            .admin_get(&admin, page)
            .await
            .assert_status(StatusCode::OK);
    }
    // MCP onboarding is an authenticated download/configuration surface, not a public listener.
    for path in ["/api/v1/mcp/setup", "/api/v1/mcp/client", "/api/v1/mcp/documentation"] {
        fixture.get(path).await.assert_status(StatusCode::UNAUTHORIZED);
        let response = fixture.admin_get(&admin, path).await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.headers["cache-control"], "no-store");
    }
    let setup = fixture.admin_get(&admin, "/api/v1/mcp/setup").await.json();
    assert_eq!(setup["transport"], "stdio");
    assert_eq!(setup["api_origin"], "http://127.0.0.1:18080");
    assert_eq!(setup["can_create_key"], true);
    assert!(setup.get("api_key").is_none());
    let bridge = fixture.admin_get(&admin, "/api/v1/mcp/client").await;
    assert!(bridge.headers["content-disposition"].to_str().unwrap().contains("vexa_mcp.py"));
    assert!(bridge.text().contains("def main():"));
    let no_csrf = fixture
        .raw(
            Method::PATCH,
            "/api/v1/settings",
            serde_json::to_vec(&json!({"general": {"node_name": "blocked"}})).unwrap(),
            Some("application/json"),
            &[(COOKIE.as_str(), &admin.cookie)],
        )
        .await;
    no_csrf.assert_status(StatusCode::FORBIDDEN);
    let settings = fixture
        .admin_json(
            &admin,
            Method::PATCH,
            "/api/v1/settings",
            json!({
                "general": {
                    "node_name": "integration-node",
                    "locale": "en-US",
                    "timezone": "UTC",
                    "ntp_servers": ["time.cloudflare.com"],
                    "sample_interval_seconds": 5,
                    "metrics_retention_days": 14
                },
                "network": {
                    "default_bridge": "virbr0",
                    "default_port_limit_mbps": 500,
                    "default_traffic_quota_bytes": 2000000000_u64,
                    "dns_servers": ["9.9.9.9", "2620:fe::fe"]
                }
            }),
        )
        .await;
    settings.assert_status(StatusCode::OK);
    assert_eq!(
        settings.json()["settings"]["general"]["node_name"],
        "integration-node"
    );

    // Mint a full-scope API key, then use bearer auth for the management flow.
    let api_key_response = fixture
        .admin_json(
            &admin,
            Method::POST,
            "/api/v1/api-keys",
            json!({
                "name": "integration-suite",
                "permissions": ["*"],
                "expires_at": null,
                "ip_allowlist": []
            }),
        )
        .await;
    api_key_response.assert_status(StatusCode::CREATED);
    let api_key_json = api_key_response.json();
    let api_key = api_key_json["key"].as_str().unwrap().to_owned();
    let api_key_id = api_key_json["record"]["id"].as_str().unwrap().to_owned();
    let narrow_key = fixture.admin_json(&admin, Method::POST, "/api/v1/api-keys", json!({"name":"no-settings-access","permissions":["host:read"],"ip_allowlist":[]})).await;
    narrow_key.assert_status(StatusCode::CREATED);
    let narrow_key = narrow_key.json()["key"].as_str().unwrap().to_owned();
    for path in ["/api/v1/mcp/setup", "/api/v1/mcp/client", "/api/v1/mcp/documentation"] {
        fixture.bearer_get(&narrow_key, path).await.assert_status(StatusCode::FORBIDDEN);
    }
    let host = fixture.bearer_get(&api_key, "/api/v1/host").await;
    host.assert_status(StatusCode::OK);
    assert_eq!(host.json()["host"]["hypervisor"]["backend"], "mock");
    let defaults = fixture.bearer_get(&api_key, "/api/v1/dns/defaults").await;
    defaults.assert_status(StatusCode::OK);
    assert_eq!(defaults.json()["items"].as_array().unwrap().len(), 2);

    // Dual-stack pool materialization, filtering, pool update, and address CRUD.
    let v4_pool = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            "/api/v1/network/pools",
            json!({
                "name": "test-public-v4",
                "cidr": "198.51.100.8/29",
                "scope": "public",
                "gateway": "198.51.100.9",
                "bridge": "virbr0",
                "vlan_id": null,
                "mtu": 1500,
                "enabled": true,
                "reserved": ["198.51.100.12"]
            }),
        )
        .await;
    v4_pool.assert_status(StatusCode::CREATED);
    assert_eq!(v4_pool.json()["materialized_addresses"], 8);
    let v4_pool_id = v4_pool.json()["pool"]["id"].as_str().unwrap().to_owned();
    let v6_pool = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            "/api/v1/network/pools",
            json!({
                "name": "test-public-v6",
                "cidr": "2001:db8:42::/126",
                "scope": "public",
                "gateway": "2001:db8:42::1",
                "bridge": "virbr0",
                "vlan_id": null,
                "mtu": 1500,
                "enabled": true,
                "reserved": []
            }),
        )
        .await;
    v6_pool.assert_status(StatusCode::CREATED);
    assert_eq!(v6_pool.json()["materialized_addresses"], 4);
    let v6_pool_id = v6_pool.json()["pool"]["id"].as_str().unwrap().to_owned();
    let patched_pool = fixture
        .bearer_json(
            &api_key,
            Method::PATCH,
            &format!("/api/v1/network/pools/{v4_pool_id}"),
            json!({"name": "test-public-v4-renamed", "mtu": 1400}),
        )
        .await;
    patched_pool.assert_status(StatusCode::OK);
    assert_eq!(patched_pool.json()["pool"]["mtu"], 1400);
    let v4_addresses = fixture
        .bearer_get(&api_key, "/api/v1/network/addresses?family=4&scope=public")
        .await;
    v4_addresses.assert_status(StatusCode::OK);
    assert!(v4_addresses.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["address"] == "198.51.100.10" && item["status"] == "free"));
    let v6_addresses = fixture
        .bearer_get(&api_key, "/api/v1/network/addresses?family=6&scope=public")
        .await;
    v6_addresses.assert_status(StatusCode::OK);
    assert!(v6_addresses.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["address"] == "2001:db8:42::2" && item["status"] == "free"));

    // Register and verify a local automatic image.
    let local_image_bytes = b"deterministic integration qcow2 image\n";
    let local_image_path = fixture.iso_dir.join("integration.qcow2");
    tokio::fs::write(&local_image_path, local_image_bytes)
        .await
        .unwrap();
    let local_sha = format!("{:x}", Sha256::digest(local_image_bytes));
    let local_iso = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            "/api/v1/isos",
            json!({
                "slug": "integration-cloud",
                "name": "Integration Cloud Image",
                "version": "1",
                "os_family": "linux",
                "architecture": std::env::consts::ARCH,
                "install_mode": "automatic",
                "source_url": null,
                "local_path": local_image_path,
                "checksum_sha256": local_sha,
                "size_bytes": local_image_bytes.len(),
                "supports_guest_agent": true,
                "supports_cloud_init": true,
                "uefi": false,
                "enabled": true,
                "metadata": {"format": "qcow2"}
            }),
        )
        .await;
    local_iso.assert_status(StatusCode::CREATED);
    let local_iso_id = local_iso.json()["image"]["id"].as_str().unwrap().to_owned();
    let verified_iso = fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/isos/{local_iso_id}/verify"),
        )
        .await;
    verified_iso.assert_status(StatusCode::OK);
    assert_eq!(verified_iso.json()["sha256"], local_sha);
    assert_eq!(verified_iso.json()["size_bytes"], local_image_bytes.len());

    // Multipart text fields are streamed into a strict small bound instead of
    // being buffered up to the route's multi-gigabyte file limit.
    let oversized_text = "x".repeat(16 * 1024 + 1);
    let (oversized_multipart, oversized_type) = multipart_image(
        &[("slug", &oversized_text), ("name", "Rejected upload")],
        "rejected.iso",
        b"must not be written",
    );
    let authorization = format!("Bearer {api_key}");
    let rejected_upload = fixture
        .raw(
            Method::POST,
            "/api/v1/isos/upload",
            oversized_multipart,
            Some(&oversized_type),
            &[(AUTHORIZATION.as_str(), &authorization)],
        )
        .await;
    rejected_upload.assert_status(StatusCode::BAD_REQUEST);
    assert!(rejected_upload.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("16 KiB"));
    assert!(!std::fs::read_dir(&fixture.iso_dir)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .path()
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value == "part")
        }));

    // Multipart upload streams and hashes the payload into managed storage.
    let upload_bytes = b"small uploaded installer image\0\x01\x02";
    let (multipart, multipart_type) = multipart_image(
        &[
            ("slug", "uploaded-installer"),
            ("name", "Uploaded Installer"),
            ("os_family", "linux"),
            ("architecture", std::env::consts::ARCH),
            ("provisioning_mode", "manual"),
            ("guest_agent", "on"),
        ],
        "uploaded.iso",
        upload_bytes,
    );
    let uploaded_iso = fixture
        .raw(
            Method::POST,
            "/api/v1/isos/upload",
            multipart,
            Some(&multipart_type),
            &[(AUTHORIZATION.as_str(), &authorization)],
        )
        .await;
    uploaded_iso.assert_status(StatusCode::CREATED);
    let uploaded_iso_json = uploaded_iso.json();
    assert_eq!(uploaded_iso_json["image"]["size_bytes"], upload_bytes.len());
    let uploaded_path = PathBuf::from(uploaded_iso_json["image"]["local_path"].as_str().unwrap());
    assert_eq!(tokio::fs::read(&uploaded_path).await.unwrap(), upload_bytes);
    let uploaded_iso_id = uploaded_iso_json["image"]["id"].as_str().unwrap().to_owned();

    // Remote URLs require a trusted checksum, and verification rejects loopback
    // destinations before a network connection is attempted (SSRF regression).
    let remote_iso = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            "/api/v1/isos",
            json!({
                "slug": "ssrf-rejected",
                "name": "SSRF Rejection",
                "version": null,
                "os_family": "linux",
                "architecture": std::env::consts::ARCH,
                "install_mode": "manual",
                "source_url": "https://127.0.0.1/private.iso",
                "local_path": null,
                "checksum_sha256": "00".repeat(32),
                "size_bytes": null,
                "supports_guest_agent": false,
                "supports_cloud_init": false,
                "uefi": false,
                "enabled": true,
                "metadata": {}
            }),
        )
        .await;
    remote_iso.assert_status(StatusCode::CREATED);
    let remote_iso_id = remote_iso.json()["image"]["id"].as_str().unwrap().to_owned();
    let ssrf = fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/isos/{remote_iso_id}/verify"),
        )
        .await;
    ssrf.assert_status(StatusCode::BAD_REQUEST);
    assert!(ssrf.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("globally routable"));

    // A provisional/failed database record whose libvirt domain never
    // existed must still be deletable, otherwise the unique VM name remains
    // permanently stuck after a provisioning rollback.
    let orphan = fixture
        .state
        .db
        .create_vm(&NewVm {
            name: "failed-provisional".into(),
            hostname: "failed-provisional".into(),
            description: "integration orphan".into(),
            os_family: "linux".into(),
            iso_id: None,
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 5,
            disk_format: "qcow2".into(),
            firmware: "bios".into(),
            machine_type: Some("q35".into()),
            bridge: Some("virbr0".into()),
            tap_name: None,
            mac_address: Some("52:54:00:12:34:ac".into()),
            network_limit_mbps: Some(100),
            traffic_limit_bytes: Some(0),
            root_username: "root".into(),
            guest_agent: false,
            autostart: false,
            timezone: Some("UTC".into()),
            metadata: json!({}),
        })
        .unwrap();
    let missing_password_reinstall = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{}/reinstall", orphan.id),
            json!({"image_id": local_iso_id}),
        )
        .await;
    missing_password_reinstall.assert_status(StatusCode::BAD_REQUEST);
    assert!(missing_password_reinstall.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("requires a guest password"));
    let orphan_link = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{}/status-tokens", orphan.id),
            json!({"expires_at": null, "scopes": [], "bound_ip": null}),
        )
        .await;
    orphan_link.assert_status(StatusCode::OK);
    let orphan_token = orphan_link.json()["token"].as_str().unwrap().to_owned();
    let orphan_exchange = fixture.get(&format!("/status/{orphan_token}")).await;
    orphan_exchange.assert_status(StatusCode::SEE_OTHER);
    let orphan_session = response_cookie(&orphan_exchange.headers, "vexa_status");
    let orphan_csrf = response_cookie(&orphan_exchange.headers, "vexa_status_csrf");
    let orphan_cookie = format!(
        "vexa_status={orphan_session}; vexa_status_csrf={orphan_csrf}"
    );
    let public_missing_password = fixture
        .public_json(
            &orphan_cookie,
            &orphan_csrf,
            Method::POST,
            "/api/public/vm/reinstall",
            json!({"image_id": local_iso_id}),
        )
        .await;
    public_missing_password.assert_status(StatusCode::BAD_REQUEST);
    assert!(public_missing_password.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("requires a guest password"));
    let orphan_delete = fixture
        .bearer_empty(&api_key, Method::DELETE, &format!("/api/v1/vms/{}", orphan.id))
        .await;
    orphan_delete.assert_status(StatusCode::ACCEPTED);
    fixture
        .wait_for_job(&api_key, &operation_id(&orphan_delete.json()))
        .await;
    assert!(fixture.state.db.get_vm(&orphan.id).unwrap().is_none());

    // Create a VM with dual-stack addresses and DNS, verify idempotent replay,
    // and wait until the background worker has materialized the mock domain.
    let create_body = json!({
        "name": "integration-vm",
        "hostname": "integration-vm.example.test",
        "description": "HTTP integration lifecycle",
        "os_family": "linux",
        "iso_id": null,
        "vcpus": 2,
        "memory_mib": 768,
        "disk_gib": 8,
        "disk_format": "qcow2",
        "firmware": "bios",
        "machine_type": "q35",
        "bridge": "virbr0",
        "tap_name": null,
        "mac_address": "52:54:00:12:34:ab",
        "network_limit_mbps": 200,
        "traffic_limit_bytes": 2000000000_u64,
        "root_username": "root",
        "guest_agent": true,
        "autostart": true,
        "timezone": "UTC",
        "metadata": {"owner": "integration-suite"},
        "password": "GuestInitial!234",
        "ip_addresses": ["198.51.100.10", "2001:db8:42::2"],
        "dns_servers": ["1.1.1.1", "2606:4700:4700::1111"],
        "start": true
    });
    let created = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::POST,
            "/api/v1/vms",
            create_body.clone(),
            &[("idempotency-key", "integration-create-0001")],
        )
        .await;
    created.assert_status(StatusCode::ACCEPTED);
    let created_json = created.json();
    let vm_id = created_json["vm"]["id"].as_str().unwrap().to_owned();
    fixture.wait_for_job(&api_key, &operation_id(&created_json)).await;
    // Recovery and direct console access never inherit the legacy vms:write grant.
    let support_key = fixture.admin_json(&admin, Method::POST, "/api/v1/api-keys",
        json!({"name":"legacy-writer", "permissions":["vms:write"], "ip_allowlist":[]})).await;
    support_key.assert_status(StatusCode::CREATED);
    let support_key = support_key.json()["key"].as_str().unwrap().to_owned();
    let recovery_path = format!("/api/v1/vms/{vm_id}/recovery");
    let recovery_body = json!({"method":"linux-shadow","username":"root","password":"RecoverySecret!123", "confirmation":"http-suite-vm", "backup_confirmed":true});
    fixture.get(&format!("/api/v1/vms/{vm_id}/console/screenshot")).await.assert_status(StatusCode::UNAUTHORIZED);
    fixture.bearer_get(&support_key, &format!("/api/v1/vms/{vm_id}/console/screenshot")).await.assert_status(StatusCode::FORBIDDEN);
    fixture.bearer_json(&support_key, Method::POST, &recovery_path, recovery_body.clone()).await.assert_status(StatusCode::FORBIDDEN);
    fixture.bearer_json(&support_key, Method::POST, &format!("/api/v1/vms/{vm_id}/console/keys"), json!({"keys":["KEY_F2"],"confirmation":"http-suite-vm"})).await.assert_status(StatusCode::FORBIDDEN);
    let before_recovery = fixture.state.db.vm_password_envelope(&vm_id).unwrap();
    let vm_name = created_json["vm"]["name"].as_str().unwrap();
    let mut checked_body = recovery_body;
    checked_body["confirmation"] = json!(vm_name);
    checked_body["backup_confirmed"] = json!(false);
    fixture.bearer_json(&api_key, Method::POST, &recovery_path, checked_body.clone()).await.assert_status(StatusCode::BAD_REQUEST);
    checked_body["backup_confirmed"] = json!(true);
    fixture.bearer_json(&api_key, Method::POST, &recovery_path, checked_body).await.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fixture.state.db.vm_password_envelope(&vm_id).unwrap(), before_recovery, "mock recovery must not claim a disk change or overwrite credentials");
    let no_csrf = fixture.raw(Method::POST, &recovery_path, serde_json::to_vec(&json!({"method":"windows-sam","username":"Administrator","confirmation":vm_name,"backup_confirmed":true})).unwrap(), Some("application/json"), &[(COOKIE.as_str(), &admin.cookie)]).await;
    no_csrf.assert_status(StatusCode::FORBIDDEN);

    let replay = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::POST,
            "/api/v1/vms",
            create_body.clone(),
            &[("idempotency-key", "integration-create-0001")],
        )
        .await;
    replay.assert_status(StatusCode::ACCEPTED);
    assert_eq!(replay.json()["replayed"], true);
    let duplicate_name = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::POST,
            "/api/v1/vms",
            create_body.clone(),
            &[("idempotency-key", "integration-create-duplicate-name")],
        )
        .await;
    duplicate_name.assert_status(StatusCode::CONFLICT);
    let vm = fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}"))
        .await;
    vm.assert_status(StatusCode::OK);
    assert_eq!(vm.json()["vm"]["state"], "running");
    assert_eq!(vm.json()["vm"]["addresses"].as_array().unwrap().len(), 2);

    // Address assignment/release outside the VM's primary addresses.
    let address_list = fixture
        .bearer_get(&api_key, "/api/v1/network/addresses?family=4")
        .await
        .json();
    let extra_address = address_list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["address"] == "198.51.100.11")
        .unwrap();
    let extra_address_id = extra_address["id"].as_str().unwrap();
    let assigned = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            &format!("/api/v1/network/addresses/{extra_address_id}/assign"),
            json!({"vm_id": vm_id, "primary": false}),
        )
        .await;
    assigned.assert_status(StatusCode::OK);
    assert_eq!(assigned.json()["address"]["status"], "used");
    let released = fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/network/addresses/{extra_address_id}/release"),
        )
        .await;
    released.assert_status(StatusCode::OK);
    assert_eq!(released.json()["address"]["status"], "free");

    // Password encryption/reveal, DNS mutation, resize, power, and metrics.
    let password = fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}/password"))
        .await;
    password.assert_status(StatusCode::OK);
    assert_eq!(password.json()["password"], "GuestInitial!234");
    fixture
        .bearer_json(
            &api_key,
            Method::PUT,
            &format!("/api/v1/vms/{vm_id}/password"),
            json!({"password": "GuestChanged!567"}),
        )
        .await
        .assert_status(StatusCode::OK);
    let dns = fixture
        .bearer_json(
            &api_key,
            Method::PUT,
            &format!("/api/v1/vms/{vm_id}/dns"),
            json!({"dns_servers": ["8.8.8.8", "2001:4860:4860::8888"]}),
        )
        .await;
    dns.assert_status(StatusCode::OK);
    assert_eq!(dns.json()["items"].as_array().unwrap().len(), 2);
    let resized = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::PATCH,
            &format!("/api/v1/vms/{vm_id}"),
            json!({
                "description": "resized through HTTP",
                "vcpus": 3,
                "memory_mib": 1024,
                "disk_gib": 12,
                "network_limit_mbps": 250,
                "traffic_limit_bytes": 3000000000_u64,
                "autostart": false
            }),
            &[("idempotency-key", "integration-resize-0001")],
        )
        .await;
    resized.assert_status(StatusCode::OK);
    let resize_json = resized.json();
    fixture.wait_for_job(&api_key, &operation_id(&resize_json)).await;
    let resized_vm = fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}"))
        .await
        .json();
    assert_eq!(resized_vm["vm"]["vcpus"], 3);
    assert_eq!(resized_vm["vm"]["memory_mib"], 1024);
    assert_eq!(resized_vm["vm"]["disk_gib"], 12);
    let stopped = fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/actions/shutdown"),
        )
        .await;
    stopped.assert_status(StatusCode::ACCEPTED);
    let stopped_json = stopped.json();
    fixture.wait_for_job(&api_key, &operation_id(&stopped_json)).await;
    assert_eq!(
        fixture
            .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}"))
            .await
            .json()["vm"]["state"],
        "stopped"
    );
    let started = fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/actions/start"),
        )
        .await;
    started.assert_status(StatusCode::ACCEPTED);
    let started_json = started.json();
    fixture.wait_for_job(&api_key, &operation_id(&started_json)).await;

    let metric_time = unix_now() - 30;
    fixture
        .state
        .db
        .insert_host_metric(&HostMetric {
            sampled_at: metric_time,
            cpu_percent: 12.5,
            load_one: 0.1,
            load_five: 0.2,
            load_fifteen: 0.3,
            memory_total_bytes: 8 * 1024 * 1024 * 1024,
            memory_used_bytes: 2 * 1024 * 1024 * 1024,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            disk_total_bytes: 100 * 1024 * 1024 * 1024,
            disk_used_bytes: 20 * 1024 * 1024 * 1024,
            disk_read_bps: 1024.0,
            disk_write_bps: 2048.0,
            network_rx_bytes: 10_000,
            network_tx_bytes: 20_000,
            network_rx_bps: 100.0,
            network_tx_bps: 200.0,
            uptime_seconds: 3600,
            metadata: json!({"source": "integration"}),
        })
        .unwrap();
    fixture
        .state
        .db
        .insert_vm_metric(&VmMetric {
            vm_id: vm_id.clone(),
            sampled_at: metric_time,
            cpu_percent: 20.0,
            memory_used_bytes: 512 * 1024 * 1024,
            memory_total_bytes: 1024 * 1024 * 1024,
            disk_read_bytes: 1_000,
            disk_write_bytes: 2_000,
            disk_read_bps: 10.0,
            disk_write_bps: 20.0,
            network_rx_bytes: 3_000,
            network_tx_bytes: 4_000,
            network_rx_bps: 30.0,
            network_tx_bps: 40.0,
            traffic_used_bytes: 7_000,
            traffic_limit_bytes: Some(3_000_000_000),
            metadata: json!({"source": "integration"}),
        })
        .unwrap();
    let host_metrics = fixture
        .bearer_get(&api_key, "/api/v1/host/metrics?range=1h")
        .await;
    host_metrics.assert_status(StatusCode::OK);
    assert!(!host_metrics.json()["metrics"]["samples"]
        .as_array()
        .unwrap()
        .is_empty());
    let vm_metrics = fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}/metrics?range=1h"))
        .await;
    vm_metrics.assert_status(StatusCode::OK);
    assert!(vm_metrics.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|sample| sample["traffic_used_bytes"] == 7000));

    // A positive allowance is enforced by disabling the VM network. The
    // Vexa-owned block survives a power action and an administrative reset
    // restores networking and starts a new accounting period.
    fixture
        .state
        .db
        .patch_vm(
            &vm_id,
            &vexa_vm::models::VmPatch {
                traffic_limit_bytes: Some(Some(10_000)),
                traffic_used_bytes: Some(10_001),
                ..vexa_vm::models::VmPatch::default()
            },
        )
        .unwrap();
    let blocked = traffic::reconcile_vm(&fixture.state, &vm_id, false)
        .await
        .unwrap();
    assert!(blocked.exceeded);
    assert!(blocked.network_blocked);
    let blocked_vm = fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}"))
        .await
        .json();
    assert_eq!(blocked_vm["vm"]["traffic_quota"]["network_blocked"], true);
    let rebooted = fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/actions/reboot"),
        )
        .await;
    rebooted.assert_status(StatusCode::ACCEPTED);
    fixture
        .wait_for_job(&api_key, &operation_id(&rebooted.json()))
        .await;
    assert!(
        fixture
            .state
            .db
            .vm_traffic_enforcement(&vm_id)
            .unwrap()
            .unwrap()
            .blocked
    );
    let reset = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/traffic/reset"),
            json!({}),
        )
        .await;
    reset.assert_status(StatusCode::OK);
    assert_eq!(reset.json()["vm"]["traffic_used_bytes"], 0);
    assert_eq!(reset.json()["traffic_quota"]["network_blocked"], false);

    // Snapshot creation is queued; revert and deletion are synchronous.
    let snapshot = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/snapshots"),
            json!({"name": "before-public-actions", "description": "integration snapshot"}),
            &[("idempotency-key", "integration-snapshot-0001")],
        )
        .await;
    snapshot.assert_status(StatusCode::ACCEPTED);
    let snapshot_json = snapshot.json();
    let snapshot_id = snapshot_json["snapshot"]["id"].as_str().unwrap().to_owned();
    fixture
        .wait_for_job(&api_key, &operation_id(&snapshot_json))
        .await;
    let snapshots = fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}/snapshots"))
        .await;
    snapshots.assert_status(StatusCode::OK);
    assert_eq!(snapshots.json()["items"][0]["state"], "ready");
    fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/snapshots/{snapshot_id}/revert"),
        )
        .await
        .assert_status(StatusCode::OK);
    fixture
        .bearer_empty(
            &api_key,
            Method::DELETE,
            &format!("/api/v1/vms/{vm_id}/snapshots/{snapshot_id}"),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // One-time customer status link, customer session/CSRF, permitted actions,
    // public reinstall, and the ten-minute one-time VNC exchange.
    let status_token = fixture
        .bearer_json(
            &api_key,
            Method::POST,
            &format!("/api/v1/vms/{vm_id}/status-tokens"),
            json!({"expires_at": null, "scopes": [], "bound_ip": null}),
        )
        .await;
    status_token.assert_status(StatusCode::OK);
    let status_json = status_token.json();
    let status_token_value = status_json["token"].as_str().unwrap().to_owned();
    let status_token_id = status_json["record"]["id"].as_str().unwrap().to_owned();
    assert!(status_json["url"]
        .as_str()
        .is_some_and(|url| url.ends_with(&format!("/status/{status_token_value}"))));
    let exchanged = fixture.get(&format!("/status/{status_token_value}")).await;
    exchanged.assert_status(StatusCode::SEE_OTHER);
    let status_session = response_cookie(&exchanged.headers, "vexa_status");
    let status_csrf = response_cookie(&exchanged.headers, "vexa_status_csrf");
    let status_cookie = format!("vexa_status={status_session}; vexa_status_csrf={status_csrf}");
    fixture
        .get(&format!("/status/{status_token_value}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    fixture
        .public_get(&status_cookie, "/status/session")
        .await
        .assert_status(StatusCode::OK);
    let public_vm = fixture.public_get(&status_cookie, "/api/public/vm").await;
    public_vm.assert_status(StatusCode::OK);
    assert_eq!(public_vm.json()["vm"]["id"], vm_id);
    // A default customer link does not grant offline disk writes.
    fixture.public_json(&status_cookie, &status_csrf, Method::POST, "/api/public/vm/recovery", json!({"method":"windows-sam","username":"Administrator","confirmation":vm_name,"backup_confirmed":true})).await.assert_status(StatusCode::FORBIDDEN);

    let public_metrics = fixture.public_get(&status_cookie, "/api/public/vm/metrics").await;
    public_metrics.assert_status(StatusCode::OK);
    assert!(!public_metrics.json()["items"].as_array().unwrap().is_empty());
    let public_dns = fixture
        .public_json(
            &status_cookie,
            &status_csrf,
            Method::PUT,
            "/api/public/vm/dns",
            json!({"dns_servers": ["1.0.0.1", "2606:4700:4700::1001"]}),
        )
        .await;
    public_dns.assert_status(StatusCode::OK);
    let public_password = fixture
        .public_json(
            &status_cookie,
            &status_csrf,
            Method::PUT,
            "/api/public/vm/password",
            json!({"password": "CustomerChanged!890"}),
        )
        .await;
    public_password.assert_status(StatusCode::OK);
    assert_eq!(
        fixture
            .public_get(&status_cookie, "/api/public/vm/password")
            .await
            .json()["password"],
        "CustomerChanged!890"
    );
    let public_power = fixture
        .public_empty(
            &status_cookie,
            &status_csrf,
            Method::POST,
            "/api/public/vm/actions/reboot",
        )
        .await;
    public_power.assert_status(StatusCode::ACCEPTED);
    let public_power_json = public_power.json();
    fixture
        .wait_for_public_job(&status_cookie, &operation_id(&public_power_json))
        .await;
    let public_reinstall = fixture
        .public_json(
            &status_cookie,
            &status_csrf,
            Method::POST,
            "/api/public/vm/reinstall",
            json!({"image_id": local_iso_id, "password": "ReinstalledGuest!901"}),
        )
        .await;
    public_reinstall.assert_status(StatusCode::ACCEPTED);
    let public_reinstall_json = public_reinstall.json();
    fixture
        .wait_for_public_job(&status_cookie, &operation_id(&public_reinstall_json))
        .await;
    assert_eq!(
        fixture
            .public_get(&status_cookie, "/api/public/vm/password")
            .await
            .json()["password"],
        "ReinstalledGuest!901"
    );
    let public_vnc = fixture
        .public_empty(
            &status_cookie,
            &status_csrf,
            Method::POST,
            "/api/public/vm/vnc-token",
        )
        .await;
    public_vnc.assert_status(StatusCode::OK);
    let vnc_url = public_vnc.json()["url"].as_str().unwrap().to_owned();
    let vnc_token = vnc_url.rsplit('/').next().unwrap();
    let vnc_exchange = fixture.get(&format!("/vnc/{vnc_token}")).await;
    vnc_exchange.assert_status(StatusCode::SEE_OTHER);
    let vnc_session = response_cookie(&vnc_exchange.headers, "vexa_vnc");
    let vnc_cookie = format!("vexa_vnc={vnc_session}");
    fixture
        .get(&format!("/vnc/{vnc_token}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    fixture
        .public_get(&vnc_cookie, "/vnc/session")
        .await
        .assert_status(StatusCode::OK);
    let vnc_info = fixture.public_get(&vnc_cookie, "/api/public/vnc-session").await;
    vnc_info.assert_status(StatusCode::OK);
    assert_eq!(vnc_info.json()["vm"]["id"], vm_id);
    assert_eq!(vnc_info.json()["websocket_url"], "/ws/vnc");

    // Jobs include cancellation, and audit exposes actions from all actor types.
    let cancellable = fixture
        .state
        .db
        .enqueue_job(&NewJob {
            kind: "integration.future-job".into(),
            vm_id: None,
            payload: json!({}),
            idempotency_key: None,
            run_after: Some(unix_now() + 3600),
            max_attempts: 1,
            actor_type: Some("integration_test".into()),
            actor_id: None,
        })
        .unwrap();
    fixture
        .bearer_empty(
            &api_key,
            Method::POST,
            &format!("/api/v1/jobs/{}/cancel", cancellable.id),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        fixture
            .bearer_get(&api_key, &format!("/api/v1/jobs/{}", cancellable.id))
            .await
            .json()["operation"]["status"],
        "cancelled"
    );
    let jobs = fixture.bearer_get(&api_key, "/api/v1/jobs").await;
    jobs.assert_status(StatusCode::OK);
    assert!(jobs.json()["items"].as_array().unwrap().len() >= 7);
    let audit = fixture.bearer_get(&api_key, "/api/v1/audit?limit=200").await;
    audit.assert_status(StatusCode::OK);
    let audit_items = audit.json()["items"].as_array().unwrap().clone();
    assert!(audit_items.iter().any(|item| item["action"] == "vm.create"));
    assert!(audit_items
        .iter()
        .any(|item| item["actor_type"] == "customer_token"));
    assert!(audit_items.iter().any(|item| item["actor_type"] == "api_key"));

    // Revoke public sessions/link, delete VM through its job, remove managed
    // records and pools, revoke the API key, and finally invalidate admin auth.
    fixture
        .raw(
            Method::POST,
            "/api/public/session/logout",
            Vec::new(),
            None,
            &[(COOKIE.as_str(), &status_cookie)],
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);
    fixture
        .raw(
            Method::POST,
            "/api/public/session/logout",
            Vec::new(),
            None,
            &[(COOKIE.as_str(), &vnc_cookie)],
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);
    fixture
        .public_get(&status_cookie, "/api/public/vm")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    fixture
        .bearer_empty(
            &api_key,
            Method::DELETE,
            &format!("/api/v1/vms/{vm_id}/status-tokens/{status_token_id}"),
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let deleted_vm = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::DELETE,
            &format!("/api/v1/vms/{vm_id}"),
            Value::Null,
            &[("idempotency-key", "integration-delete-0001")],
        )
        .await;
    deleted_vm.assert_status(StatusCode::ACCEPTED);
    let deleted_vm_json = deleted_vm.json();
    let deleted_job_id = operation_id(&deleted_vm_json);
    fixture
        .wait_for_job(&api_key, &deleted_job_id)
        .await;
    let delete_replay = fixture
        .bearer_json_with_headers(
            &api_key,
            Method::DELETE,
            &format!("/api/v1/vms/{vm_id}"),
            Value::Null,
            &[("idempotency-key", "integration-delete-0001")],
        )
        .await;
    delete_replay.assert_status(StatusCode::ACCEPTED);
    assert_eq!(delete_replay.json()["replayed"], true);
    assert_eq!(operation_id(&delete_replay.json()), deleted_job_id);
    fixture
        .bearer_get(&api_key, &format!("/api/v1/vms/{vm_id}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    for iso_id in [&uploaded_iso_id, &remote_iso_id, &local_iso_id] {
        fixture
            .bearer_empty(&api_key, Method::DELETE, &format!("/api/v1/isos/{iso_id}"))
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }
    let remaining_addresses = fixture
        .bearer_get(&api_key, "/api/v1/network/addresses")
        .await
        .json();
    let managed_address_ids = remaining_addresses["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["pool_id"] == v4_pool_id || item["pool_id"] == v6_pool_id)
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(managed_address_ids.len(), 12);
    for address_id in managed_address_ids {
        fixture
            .bearer_empty(
                &api_key,
                Method::DELETE,
                &format!("/api/v1/network/addresses/{address_id}"),
            )
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }
    for pool_id in [&v4_pool_id, &v6_pool_id] {
        fixture
            .bearer_empty(
                &api_key,
                Method::DELETE,
                &format!("/api/v1/network/pools/{pool_id}"),
            )
            .await
            .assert_status(StatusCode::NO_CONTENT);
    }
    fixture
        .admin_json(
            &admin,
            Method::DELETE,
            &format!("/api/v1/api-keys/{api_key_id}"),
            Value::Null,
        )
        .await
        .assert_status(StatusCode::NO_CONTENT);
    fixture
        .bearer_get(&api_key, "/api/v1/host")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    fixture
        .admin_json(&admin, Method::POST, "/api/v1/auth/logout", Value::Null)
        .await
        .assert_status(StatusCode::OK);
    fixture
        .admin_get(&admin, "/api/v1/auth/me")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
