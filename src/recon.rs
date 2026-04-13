use anyhow::{anyhow, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};

/// Deserialize a u8 that may be null → default to 0
fn deserialize_null_u8<'de, D>(deserializer: D) -> Result<u8, D::Error>
where D: Deserializer<'de> {
    Ok(Option::<u8>::deserialize(deserializer)?.unwrap_or(0))
}

/// Deserialize a u16 that may be null → default to 0
fn deserialize_null_u16<'de, D>(deserializer: D) -> Result<u16, D::Error>
where D: Deserializer<'de> {
    Ok(Option::<u16>::deserialize(deserializer)?.unwrap_or(0))
}
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::select::WebScope;

// ── RR Schema Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub project_id: String,
    pub bbp: BbpInfo,
    pub scope: ScopeInfo,
    pub target: TargetInfo,
    pub attack_points: Vec<AttackPoint>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BbpInfo {
    pub platform: String,
    pub handle: String,
    pub name: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeInfo {
    pub identifier: String,
    pub asset_type: String,
    pub eligible_for_bounty: bool,
    pub max_severity: Option<String>,
    pub instruction: Option<String>,
    pub availability_requirement: Option<String>,
    pub confidentiality_requirement: Option<String>,
    pub integrity_requirement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub subdomain: String,
    pub ip: Option<String>,
    pub tech_stack: Vec<String>,
    pub status_code: u16,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPoint {
    #[serde(default)]
    pub ap_id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_u8")]
    pub priority: u8,
    #[serde(default)]
    pub evidence: Evidence,
    #[serde(default)]
    pub request_sample: Option<RequestSample>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub raw: String,
    #[serde(default)]
    pub llm_reasoning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSample {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub params: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_null_u16")]
    pub response_status: u16,
    #[serde(default)]
    pub response_snippet: Option<String>,
}

// ── httpx JSON result parsing ──

/// Parsed httpx JSON output for a single host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpxResult {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub input: Option<String>,
    #[serde(default, alias = "status-code", alias = "status_code")]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub webserver: Option<String>,
    #[serde(default, alias = "content-type", alias = "content_type")]
    pub content_type: Option<String>,
    #[serde(default, alias = "tech")]
    pub technologies: Option<Vec<String>>,
    #[serde(default, alias = "header")]
    pub response_headers: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, alias = "body")]
    pub response_body: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default, alias = "content-length", alias = "content_length")]
    pub content_length: Option<u64>,
    #[serde(default)]
    pub method: Option<String>,
}

/// Parse httpx JSON lines into structured results, keyed by hostname
fn parse_httpx_json(lines: &[String]) -> HashMap<String, HttpxResult> {
    let mut map = HashMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(result) = serde_json::from_str::<HttpxResult>(trimmed) {
            let host = if let Some(ref url) = result.url {
                extract_hostname(url)
            } else if let Some(ref input) = result.input {
                extract_hostname(input)
            } else if let Some(ref h) = result.host {
                h.clone()
            } else {
                continue;
            };
            if !host.is_empty() {
                map.insert(host, result);
            }
        }
    }
    map
}

/// Fallback: parse plain text httpx output (for backwards compatibility)
fn parse_httpx_text(lines: &[String]) -> HashMap<String, u16> {
    let mut map = HashMap::new();
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let host = extract_hostname(parts[0]);
        for part in &parts[1..] {
            let trimmed = part.trim_start_matches('[').trim_end_matches(']');
            if let Ok(code) = trimmed.parse::<u16>() {
                if (100..600).contains(&code) {
                    map.insert(host.clone(), code);
                    break;
                }
            }
        }
    }
    map
}

// ── JS Endpoints Sanitization ──

/// Static file extensions to remove — zero AP value
const STATIC_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".ogg", ".wav",
    ".pdf", ".zip", ".gz", ".tar", ".br",
    ".map", ".ts", ".tsx", ".jsx", ".vue", ".scss", ".less",
];

/// Known external domains that are never in scope
const NOISE_DOMAINS: &[&str] = &[
    "googleapis.com", "gstatic.com", "google.com", "googletagmanager.com",
    "google-analytics.com", "googleadservices.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "twimg.com",
    "cdn.shopify.com", "shopify.com",
    "jquery.com", "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "cloudflare.com", "cloudfront.net",
    "wp.com", "wordpress.com",
    "pinterest.com", "linkedin.com", "instagram.com",
    "youtube.com", "ytimg.com",
    "maxcdn.bootstrapcdn.com", "bootstrapcdn.com",
    "gravatar.com", "wp.com",
    "sentry.io", "segment.com", "mixpanel.com", "hotjar.com",
    "intercom.io", "zendesk.com", "crisp.chat",
    "stripe.com", "paypal.com",
    "recaptcha.net", "hcaptcha.com",
];

/// High-value path patterns that should always be kept
const API_PATTERNS: &[&str] = &[
    "/api/", "/api.", "/v1/", "/v2/", "/v3/",
    "/graphql", "/gql",
    "/admin", "/internal", "/private", "/debug", "/management",
    "/auth", "/login", "/logout", "/oauth", "/sso", "/saml",
    "/token", "/session", "/callback",
    "/webhook", "/websocket", "/ws/",
    "/upload", "/download", "/export", "/import",
    "/config", "/settings", "/profile", "/account",
    "/users", "/user/", "/me/",
    "/.well-known/",
    "/swagger", "/api-docs", "/openapi",
    "/actuator", "/metrics", "/health", "/status",
    "/search", "/query", "/filter",
];

/// Sanitize JS endpoints: remove noise, keep AP-relevant paths
pub fn sanitize_js_endpoints(endpoints: &[String], scope_identifiers: &[String]) -> Vec<String> {
    let mut result = Vec::new();

    for ep in endpoints {
        let trimmed = ep.trim();
        if trimmed.is_empty() || trimmed.len() < 3 {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // Skip bare JS filenames (start with - or are just hashes)
        if trimmed.starts_with('-') {
            continue;
        }

        // Skip node_modules paths
        if lower.contains("node_modules") {
            continue;
        }

        // Skip relative source paths (./src/, ./lib/, ./dist/)
        if trimmed.starts_with("./") {
            continue;
        }

        // Skip base64 blobs and encoded data (high ratio of +/= chars)
        let special_chars = trimmed.chars().filter(|c| matches!(c, '+' | '=' | '/' )).count();
        if trimmed.len() > 50 && special_chars as f64 / trimmed.len() as f64 > 0.15 {
            continue;
        }

        // Skip long strings without clear URL structure
        if trimmed.len() > 200 {
            continue;
        }

        // Skip static file extensions
        let is_static = STATIC_EXTENSIONS.iter().any(|ext| {
            lower.ends_with(ext) || lower.contains(&format!("{}?", ext))
        });
        if is_static {
            continue;
        }

        // Skip known external noise domains
        let is_noise = NOISE_DOMAINS.iter().any(|d| lower.contains(d));
        if is_noise {
            continue;
        }

        // If it's a full URL, check scope
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.starts_with("//") {
            let normalized = if trimmed.starts_with("//") {
                format!("https:{}", trimmed)
            } else {
                trimmed.to_string()
            };
            if !is_in_scope(&normalized, scope_identifiers) {
                continue;
            }
        }

        // Keep: API patterns always pass
        let is_api = API_PATTERNS.iter().any(|p| lower.contains(p));
        if is_api {
            result.push(trimmed.to_string());
            continue;
        }

        // Keep: has query parameters (potential injection/IDOR targets)
        if trimmed.contains('?') && trimmed.contains('=') {
            result.push(trimmed.to_string());
            continue;
        }

        // Keep: looks like an API path (starts with / and has structure)
        if trimmed.starts_with('/') {
            let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
            // At least 2 path segments and not just a bare filename
            if segments.len() >= 2 {
                result.push(trimmed.to_string());
                continue;
            }
        }

        // Keep: in-scope full URLs that passed all filters
        if trimmed.starts_with("http") {
            result.push(trimmed.to_string());
        }
    }

    result.sort();
    result.dedup();
    result
}

/// Enrich AP request_sample with httpx packet data
fn enrich_request_samples(
    attack_points: &mut [AttackPoint],
    httpx_json: &HashMap<String, HttpxResult>,
    httpx_text: &HashMap<String, u16>,
) {
    for ap in attack_points.iter_mut() {
        let host = extract_hostname(&ap.url);

        // Parse query params from AP URL
        let mut params = HashMap::new();
        if let Some(query) = ap.url.split('?').nth(1) {
            for pair in query.split('&') {
                let mut kv = pair.splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    params.insert(k.to_string(), v.to_string());
                }
            }
        }

        if let Some(hx) = httpx_json.get(&host) {
            // Rich data from JSON mode
            let status = hx.status_code.unwrap_or(0);

            let mut resp_headers = HashMap::new();
            if let Some(ref ct) = hx.content_type {
                resp_headers.insert("Content-Type".to_string(), ct.clone());
            }
            if let Some(ref ws) = hx.webserver {
                resp_headers.insert("Server".to_string(), ws.clone());
            }
            if let Some(ref cl) = hx.content_length {
                resp_headers.insert("Content-Length".to_string(), cl.to_string());
            }

            // Truncate body to first 500 chars for snippet
            let snippet = hx.response_body.as_ref().map(|b| {
                if b.len() > 500 {
                    format!("{}...", &b[..500])
                } else {
                    b.clone()
                }
            });

            match &mut ap.request_sample {
                Some(sample) => {
                    if sample.response_status == 0 {
                        sample.response_status = status;
                    }
                    if sample.response_snippet.is_none() {
                        sample.response_snippet = snippet;
                    }
                }
                None => {
                    let mut req_headers = HashMap::new();
                    req_headers.insert("Accept".to_string(), "application/json".to_string());
                    req_headers.insert("Host".to_string(), host.clone());

                    ap.request_sample = Some(RequestSample {
                        url: ap.url.clone(),
                        method: ap.method.clone(),
                        headers: req_headers,
                        params,
                        response_status: status,
                        response_snippet: snippet,
                    });
                }
            }
        } else {
            // Fallback to text-mode status code
            let status = httpx_text.get(&host).copied().unwrap_or(0);

            if ap.request_sample.is_none() {
                let mut headers = HashMap::new();
                headers.insert("Accept".to_string(), "application/json".to_string());

                ap.request_sample = Some(RequestSample {
                    url: ap.url.clone(),
                    method: ap.method.clone(),
                    headers,
                    params,
                    response_status: status,
                    response_snippet: None,
                });
            } else if let Some(sample) = &mut ap.request_sample {
                if sample.response_status == 0 {
                    sample.response_status = status;
                }
            }
        }
    }
}

// ── BBOT Flags ──

pub fn get_bbot_flags(scopes: &[WebScope]) -> Vec<String> {
    let has_restriction = scopes.iter().any(|s| {
        let inst = s.instruction.as_deref().unwrap_or("").to_lowercase();
        ["do not test", "no automated", "no scanning", "out of scope"]
            .iter()
            .any(|k| inst.contains(k))
    });

    if has_restriction {
        vec!["-rf".into(), "passive".into()]
    } else {
        vec!["-ef".into(), "aggressive".into()]
    }
}

// ── Scope Filtering ──

/// Check if a URL/hostname is in scope based on scope identifiers from rule.csv.
/// Supports wildcard matching: "*.example.com" matches "sub.example.com" and "example.com".
/// Exact match: "app.example.com" matches only "app.example.com".
pub fn is_in_scope(url_or_host: &str, scope_identifiers: &[String]) -> bool {
    // Extract hostname from URL
    let host = extract_hostname(url_or_host);
    if host.is_empty() {
        return false;
    }
    let host_lower = host.to_lowercase();

    for scope in scope_identifiers {
        let scope_lower = scope.to_lowercase();

        if scope_lower.starts_with("*.") {
            // Wildcard: *.example.com matches example.com and *.example.com
            let base = &scope_lower[2..]; // "example.com"
            if host_lower == base || host_lower.ends_with(&format!(".{}", base)) {
                return true;
            }
        } else {
            // Exact match
            if host_lower == scope_lower {
                return true;
            }
        }
    }

    false
}

/// Extract hostname from a URL string or plain hostname.
fn extract_hostname(input: &str) -> String {
    let without_scheme = input
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    // Take everything before the first / or : (port)
    without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Filter a list of URLs, keeping only those matching scope identifiers.
/// Returns (in_scope, out_of_scope).
pub fn filter_urls_by_scope(urls: &[String], scope_identifiers: &[String]) -> (Vec<String>, Vec<String>) {
    let mut in_scope = Vec::new();
    let mut out_of_scope = Vec::new();

    for url in urls {
        if is_in_scope(url, scope_identifiers) {
            in_scope.push(url.clone());
        } else {
            out_of_scope.push(url.clone());
        }
    }

    (in_scope, out_of_scope)
}

// ── Recon Runner ──

#[derive(Clone)]
pub struct ReconRunner {
    pub project_dir: PathBuf,
    pub recon_dir: PathBuf,
    pub force: bool,
    pub skip_steps: HashSet<String>,
}

impl ReconRunner {
    pub fn new(project_dir: &Path, force: bool, skip_steps: HashSet<String>) -> Self {
        let recon_dir = project_dir.join("recon");
        Self {
            project_dir: project_dir.to_path_buf(),
            recon_dir,
            force,
            skip_steps,
        }
    }

    /// Check if a step's output file exists and is non-empty
    pub fn step_done(&self, filename: &str) -> bool {
        if self.force {
            return false;
        }
        let path = self.recon_dir.join(filename);
        path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false)
    }

    /// Check if a step's marker file exists (for steps with possibly empty output)
    fn marker_done(&self, marker: &str) -> bool {
        if self.force {
            return false;
        }
        self.recon_dir.join(marker).exists()
    }

    /// Sanitize domain name for use as checkpoint filename
    fn sanitize_domain(domain: &str) -> String {
        domain
            .trim_start_matches("*.")
            .replace('.', "_")
            .replace('*', "wildcard")
    }

    fn progress_bar(&self, step: u8, total: u8, msg: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template(&format!("[{}/{}] {{spinner}} {{msg}}", step, total))
                .unwrap(),
        );
        pb.set_message(msg.to_string());
        pb.enable_steady_tick(Duration::from_millis(120));
        pb
    }

    fn extended_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let current_path = std::env::var("PATH").unwrap_or_default();
        format!(
            "{}/go/bin:{}/.local/bin:{}/.cargo/bin:/usr/local/go/bin:{}",
            home, home, home, current_path
        )
    }

    async fn run_cmd(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(cmd)
            .args(args)
            .current_dir(&self.recon_dir)
            .env("PATH", Self::extended_path())
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: {} failed: {}", cmd, stderr.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn read_file_lines(&self, filename: &str) -> Vec<String> {
        let path = self.recon_dir.join(filename);
        std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// Parse BBOT output into subdomain list
    fn parse_bbot_output(output: &str) -> Vec<String> {
        let mut subs = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let etype = val["type"].as_str().unwrap_or("");
                if etype == "DNS_NAME" || etype == "URL_UNVERIFIED" {
                    if let Some(data) = val["data"].as_str() {
                        let host = data.trim_start_matches("http://")
                            .trim_start_matches("https://")
                            .split('/')
                            .next()
                            .unwrap_or(data);
                        if !host.is_empty() {
                            subs.push(host.to_string());
                        }
                    }
                }
            } else {
                subs.push(trimmed.to_string());
            }
        }
        subs
    }

    /// Step 1: Subdomain enumeration with BBOT (parallel, per-domain checkpoints)
    pub async fn run_bbot(&self, targets: &[String], bbot_flags: &[String]) -> Result<Vec<String>> {
        let total = targets.len();
        let pb = Arc::new(ProgressBar::new(total as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[1/5] {bar:30} {pos}/{len} domains — {msg}")
                .unwrap(),
        );
        pb.set_message("BBOT subdomain enumeration");

        // Clean per-domain checkpoints if force
        if self.force {
            for entry in std::fs::read_dir(&self.recon_dir).into_iter().flatten() {
                if let Ok(e) = entry {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with("bbot_") && name.ends_with(".txt") {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }

        let sem = Arc::new(Semaphore::new(5));
        let mut join_set = JoinSet::new();

        for target in targets.iter() {
            let domain = target.trim_start_matches("*.").to_string();
            let checkpoint = format!("bbot_{}.txt", Self::sanitize_domain(&domain));
            let checkpoint_path = self.recon_dir.join(&checkpoint);
            let recon_dir = self.recon_dir.clone();
            let force = self.force;
            let bbot_flags = bbot_flags.to_vec();
            let pb = pb.clone();
            let sem = sem.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                // Per-domain checkpoint
                if !force && checkpoint_path.exists() && checkpoint_path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
                    let cached: Vec<String> = std::fs::read_to_string(&checkpoint_path)
                        .unwrap_or_default()
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.trim().to_string())
                        .collect();
                    pb.inc(1);
                    return cached;
                }

                let mut args = vec![
                    "-t".to_string(), domain.clone(),
                    "--silent".to_string(),
                    "--fast-mode".to_string(),
                    "--force".to_string(),
                    "-f".to_string(), "subdomain-enum".to_string(),
                    "--json".to_string(),
                ];
                args.extend(bbot_flags.iter().cloned());

                let output = Command::new("bbot")
                    .args(&args)
                    .current_dir(&recon_dir)
                    .env("PATH", Self::extended_path())
                    .output()
                    .await;

                let domain_subs = match output {
                    Ok(out) => {
                        if !out.status.success() {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            eprintln!("Warning: bbot failed for {}: {}", domain, stderr.trim());
                        }
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let subs = Self::parse_bbot_output(&stdout);
                        let _ = std::fs::write(&checkpoint_path, subs.join("\n"));
                        subs
                    }
                    Err(e) => {
                        eprintln!("BBOT failed for {}: {}", domain, e);
                        vec![]
                    }
                };

                pb.inc(1);
                domain_subs
            });
        }

        let mut all_subdomains = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(subs) = result {
                all_subdomains.extend(subs);
            }
        }

        all_subdomains.sort();
        all_subdomains.dedup();

        std::fs::write(
            self.recon_dir.join("subdomains.txt"),
            all_subdomains.join("\n"),
        )?;

        pb.finish_with_message(format!("Found {} subdomains", all_subdomains.len()));
        Ok(all_subdomains)
    }

    /// Step 2: Filter live hosts with httpx
    pub async fn run_httpx(&self, subdomains: &[String]) -> Result<Vec<String>> {
        let pb = self.progress_bar(2, 5, "Live host detection (httpx)...");

        let input = subdomains.join("\n");
        let input_path = self.recon_dir.join("subdomains_input.txt");
        std::fs::write(&input_path, &input)?;

        // Run httpx in JSON mode for rich packet data
        let json_output_path = self.recon_dir.join("httpx_results.jsonl");
        let _ = self.run_cmd(
            "httpx",
            &[
                "-l", &input_path.to_string_lossy(),
                "-silent",
                "-json",
                "-title", "-status-code", "-tech-detect",
                "-web-server", "-ip", "-cname",
                "-content-type", "-content-length",
                "-body-preview", "500",
                "-o", &json_output_path.to_string_lossy(),
            ],
        ).await;

        // Generate plain live_hosts.txt from JSON results for other steps
        let json_lines = self.read_file_lines("httpx_results.jsonl");
        let mut live_hosts = Vec::new();
        for line in &json_lines {
            if let Ok(hx) = serde_json::from_str::<HttpxResult>(line) {
                if let Some(ref url) = hx.url {
                    let status = hx.status_code.unwrap_or(0);
                    let title = hx.title.as_deref().unwrap_or("");
                    let tech = hx.technologies.as_ref()
                        .map(|t| t.join(","))
                        .unwrap_or_default();
                    let ws = hx.webserver.as_deref().unwrap_or("");
                    live_hosts.push(format!("{} [{}] [{}] [{}] [{}]", url, status, title, tech, ws));
                }
            }
        }
        std::fs::write(
            self.recon_dir.join("live_hosts.txt"),
            live_hosts.join("\n"),
        )?;

        pb.finish_with_message(format!("Found {} live hosts", live_hosts.len()));
        Ok(live_hosts)
    }

    /// Step 3: URL collection (parallel gau + waybackurls per domain, parallel linkfinder)
    pub async fn run_url_collection(&self, targets: &[String]) -> Result<Vec<String>> {
        let total = targets.len();
        let pb = Arc::new(ProgressBar::new(total as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[3/5] {bar:30} {pos}/{len} domains — {msg}")
                .unwrap(),
        );
        pb.set_message("URL collection (gau + waybackurls)");

        // Parallel URL collection per domain
        let sem = Arc::new(Semaphore::new(5));
        let mut join_set = JoinSet::new();

        for target in targets.iter() {
            let domain = target.trim_start_matches("*.").to_string();
            let recon_dir = self.recon_dir.clone();
            let pb = pb.clone();
            let sem = sem.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let extended_path = Self::extended_path();
                let mut urls = Vec::new();

                // Run gau and waybackurls concurrently for same domain
                let gau_future = Command::new("gau")
                    .args([&domain, "--subs"])
                    .current_dir(&recon_dir)
                    .env("PATH", &extended_path)
                    .output();

                let wb_cmd = format!("echo {} | waybackurls", domain);
                let wb_future = Command::new("sh")
                    .args(["-c", &wb_cmd])
                    .current_dir(&recon_dir)
                    .env("PATH", &extended_path)
                    .output();

                let (gau_result, wb_result) = tokio::join!(gau_future, wb_future);

                if let Ok(out) = gau_result {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    for line in stdout.lines() {
                        if !line.trim().is_empty() {
                            urls.push(line.trim().to_string());
                        }
                    }
                }

                if let Ok(out) = wb_result {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    for line in stdout.lines() {
                        if !line.trim().is_empty() {
                            urls.push(line.trim().to_string());
                        }
                    }
                }

                pb.inc(1);
                urls
            });
        }

        let mut all_urls = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(urls) = result {
                all_urls.extend(urls);
            }
        }

        all_urls.sort();
        all_urls.dedup();

        std::fs::write(
            self.recon_dir.join("urls.txt"),
            all_urls.join("\n"),
        )?;

        // Extract JS files
        let js_files: Vec<String> = all_urls.iter().filter(|u| {
            u.to_lowercase().ends_with(".js") || u.to_lowercase().contains(".js?")
        }).cloned().collect();

        std::fs::write(
            self.recon_dir.join("js_files.txt"),
            js_files.join("\n"),
        )?;

        pb.finish_with_message(format!("Collected {} URLs, {} JS files", all_urls.len(), js_files.len()));

        // Parallel linkfinder on JS files
        if !js_files.is_empty() {
            let lf_pb = ProgressBar::new(js_files.len() as u64);
            lf_pb.set_style(
                ProgressStyle::default_bar()
                    .template("[3/5] {bar:30} {pos}/{len} JS files — linkfinder")
                    .unwrap(),
            );

            let lf_sem = Arc::new(Semaphore::new(10));
            let mut lf_set = JoinSet::new();
            let lf_pb = Arc::new(lf_pb);

            for js_url in js_files.iter() {
                let js_url = js_url.clone();
                let recon_dir = self.recon_dir.clone();
                let lf_sem = lf_sem.clone();
                let lf_pb = lf_pb.clone();

                lf_set.spawn(async move {
                    let _permit = lf_sem.acquire().await.unwrap();
                    let output = Command::new("linkfinder")
                        .args(["-i", &js_url, "-o", "cli"])
                        .current_dir(&recon_dir)
                        .env("PATH", Self::extended_path())
                        .output()
                        .await;

                    let mut endpoints = Vec::new();
                    if let Ok(out) = output {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        for line in stdout.lines() {
                            if !line.trim().is_empty() {
                                endpoints.push(line.trim().to_string());
                            }
                        }
                    }
                    lf_pb.inc(1);
                    endpoints
                });
            }

            let mut js_endpoints = Vec::new();
            while let Some(result) = lf_set.join_next().await {
                if let Ok(eps) = result {
                    js_endpoints.extend(eps);
                }
            }
            js_endpoints.sort();
            js_endpoints.dedup();

            std::fs::write(
                self.recon_dir.join("js_endpoints.txt"),
                js_endpoints.join("\n"),
            )?;

            lf_pb.finish_with_message(format!("{} JS endpoints found", js_endpoints.len()));
        } else {
            std::fs::write(self.recon_dir.join("js_endpoints.txt"), "")?;
        }

        Ok(all_urls)
    }

    /// Step 4: Nuclei scan
    pub async fn run_nuclei(&self) -> Result<Vec<String>> {
        let live_hosts_path = self.recon_dir.join("live_hosts.txt");
        if !live_hosts_path.exists() {
            println!("[4/5] Skipped nuclei — no live hosts");
            return Ok(vec![]);
        }

        let pb = self.progress_bar(4, 5, "Nuclei scan running...");

        let output_path = self.recon_dir.join("nuclei.txt");
        let output = Command::new("nuclei")
            .args([
                "-l", &live_hosts_path.to_string_lossy(),
                "-tags", "exposure,config,misconfig,token,secret,info,takeover,cname",
                "-severity", "critical,high,medium,low",
                "-rate-limit", "10",
                "-timeout", "10",
                "-exclude-tags", "dos,fuzz,intrusive",
                "-stats", "-stats-interval", "10",
                "-o", &output_path.to_string_lossy(),
            ])
            .current_dir(&self.recon_dir)
            .env("PATH", Self::extended_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        if let Err(e) = output {
            eprintln!("Warning: nuclei failed: {}", e);
        }

        let results = self.read_file_lines("nuclei.txt");
        pb.finish_with_message(format!("Nuclei found {} results", results.len()));
        Ok(results)
    }

    /// Step 5: LLM AP identification
    pub async fn run_ap_identification(&self) -> Result<Vec<AttackPoint>> {
        let pb = self.progress_bar(5, 5, "AP identification (claude --print)...");

        // Gather all recon data
        let live_hosts = self.read_file_lines("live_hosts.txt");
        let urls = self.read_file_lines("urls.txt");
        let js_endpoints = self.read_file_lines("js_endpoints.txt");
        let nuclei = self.read_file_lines("nuclei.txt");

        // Read the AP identifier skill
        let skill_content = include_str!("../SKILL/ap-identifier-SKILL.md");

        // Read scope info for LLM context
        let rule_csv = std::fs::read_to_string(self.project_dir.join("rule.csv")).unwrap_or_default();
        let scope_lines: Vec<&str> = rule_csv.lines().skip(1).collect();
        let scope_info = scope_lines.join("\n");

        // Read program policy if available
        let policy_path = self.project_dir.join("policy.md");
        let policy_section = if policy_path.exists() {
            let policy = std::fs::read_to_string(&policy_path).unwrap_or_default();
            if policy.trim().is_empty() {
                String::new()
            } else {
                format!(
                    "\n\n## Program Policy & Guidelines\n\nThis is the official program policy from HackerOne. Follow these rules strictly — they define what is allowed and what is excluded.\n\n```\n{}\n```\n",
                    policy.trim()
                )
            }
        } else {
            String::new()
        };

        // Build scope identifiers for JS endpoint sanitization
        let rule_csv_raw = std::fs::read_to_string(self.project_dir.join("rule.csv")).unwrap_or_default();
        let scope_ids: Vec<String> = rule_csv_raw.lines().skip(1)
            .filter_map(|l| l.split(',').next().map(|s| s.to_string()))
            .filter(|s| !s.is_empty())
            .collect();

        // Sanitize JS endpoints: remove noise, keep AP-relevant paths
        let js_clean = sanitize_js_endpoints(&js_endpoints, &scope_ids);

        // Save sanitized version for debugging
        let _ = std::fs::write(
            self.recon_dir.join("js_endpoints_clean.txt"),
            js_clean.join("\n"),
        );

        let js_sample: Vec<_> = js_clean.iter().take(500).cloned().collect();
        let nuclei_sample: Vec<_> = nuclei.iter().take(200).cloned().collect();

        let prompt = format!(
            "{}\n\n---\n\n## CRITICAL: Scope Boundaries\n\nThe following are the ONLY in-scope targets. Do NOT generate attack points for any domain outside this scope.\n\n```\n{}\n```\n\nAny AP with a URL not matching these scope identifiers will be automatically rejected.{}\n\n---\n\n## Recon Data\n\n### Live Hosts ({} total)\n{}\n\n### URLs (first 200 of {} total)\n{}\n\n### JS Endpoints ({} sanitized from {} raw)\n{}\n\n### Nuclei Results (first 200 of {} total)\n{}\n\n---\n\nAnalyze the above recon data. Return ONLY a JSON array of attack points. Only include in-scope targets. Follow the program policy strictly. No other text.",
            skill_content,
            scope_info,
            policy_section,
            live_hosts.len(),
            live_hosts.join("\n"),
            urls.len(),
            urls.iter().take(200).cloned().collect::<Vec<_>>().join("\n"),
            js_clean.len(), js_endpoints.len(),
            js_sample.join("\n"),
            nuclei.len(),
            nuclei_sample.join("\n"),
        );

        let response = crate::llm::query(&prompt, &self.project_dir).await;

        let attack_points = match response {
            Ok(text) => {
                // Try to parse JSON array from response
                let trimmed = text.trim();
                // Find JSON array bounds
                let start = trimmed.find('[');
                let end = trimmed.rfind(']');

                match (start, end) {
                    (Some(s), Some(e)) if s < e => {
                        let json_str = &trimmed[s..=e];
                        serde_json::from_str::<Vec<AttackPoint>>(json_str).unwrap_or_else(|err| {
                            eprintln!("Failed to parse LLM AP response: {}", err);
                            vec![]
                        })
                    }
                    _ => {
                        eprintln!("LLM response did not contain a JSON array");
                        vec![]
                    }
                }
            }
            Err(e) => {
                eprintln!("LLM call failed: {}. Continuing without LLM APs.", e);
                vec![]
            }
        };

        pb.finish_with_message(format!("Identified {} attack points", attack_points.len()));
        Ok(attack_points)
    }

    /// Generate RR.json
    pub fn generate_rr(&self, attack_points: Vec<AttackPoint>) -> Result<PathBuf> {
        // Read program_info.json
        let info_path = self.project_dir.join("program_info.json");
        let info: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&info_path)?,
        )?;

        // Read rule.csv to get scope info
        let rule_csv = std::fs::read_to_string(self.project_dir.join("rule.csv"))?;
        let mut lines = rule_csv.lines();
        let _header = lines.next();
        let first_scope = lines.next().unwrap_or("");
        let scope_parts: Vec<&str> = first_scope.split(',').collect();

        let project_id = self.project_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let rr = ReconResult {
            project_id,
            bbp: BbpInfo {
                platform: "hackerone".to_string(),
                handle: info["handle"].as_str().unwrap_or("").to_string(),
                name: info["name"].as_str().unwrap_or("").to_string(),
                score: info["score"].as_f64().unwrap_or(0.0),
            },
            scope: ScopeInfo {
                identifier: scope_parts.first().unwrap_or(&"").to_string(),
                asset_type: scope_parts.get(1).unwrap_or(&"").to_string(),
                eligible_for_bounty: true,
                max_severity: scope_parts.get(2).map(|s| s.to_string()).filter(|s| !s.is_empty()),
                instruction: scope_parts.get(3).map(|s| s.to_string()).filter(|s| !s.is_empty()),
                availability_requirement: None,
                confidentiality_requirement: None,
                integrity_requirement: None,
            },
            target: TargetInfo {
                subdomain: scope_parts.first().unwrap_or(&"").to_string(),
                ip: None,
                tech_stack: vec![],
                status_code: 0,
                title: None,
            },
            attack_points,
            created_at: chrono::Local::now().to_rfc3339(),
        };

        let rr_path = self.project_dir.join("RR.json");
        std::fs::write(&rr_path, serde_json::to_string_pretty(&rr)?)?;

        Ok(rr_path)
    }
}

/// Main entry point for recon pipeline
pub async fn run_recon(project_dir: &Path, force: bool, skip_steps: &HashSet<String>) -> Result<()> {
    let runner = ReconRunner::new(project_dir, force, skip_steps.clone());

    // Read rule.csv to get targets
    let rule_csv = std::fs::read_to_string(project_dir.join("rule.csv"))
        .map_err(|_| anyhow!("rule.csv not found in {}", project_dir.display()))?;

    let targets: Vec<String> = rule_csv
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            parts.first().map(|s| s.to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();

    if targets.is_empty() {
        return Err(anyhow!("No targets found in rule.csv"));
    }

    // Read web scopes for BBOT flags
    let web_scopes: Vec<WebScope> = rule_csv
        .lines()
        .skip(1)
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            Some(WebScope {
                identifier: parts.first()?.to_string(),
                asset_type: parts.get(1)?.to_string(),
                max_severity: parts.get(2).map(|s| s.to_string()).filter(|s| !s.is_empty()),
                instruction: parts.get(3).map(|s| s.to_string()).filter(|s| !s.is_empty()),
            })
        })
        .collect();

    let bbot_flags = get_bbot_flags(&web_scopes);

    // Build scope identifier list for filtering
    let scope_identifiers: Vec<String> = targets.clone();

    println!("\n=== Auto-Recon: {} ===\n", project_dir.file_name().unwrap_or_default().to_string_lossy());

    // 1. Subdomain enumeration
    let subdomains = if runner.skip_steps.contains("bbot") {
        println!("[1/5] Skipped BBOT (--skip bbot)");
        runner.read_file_lines("subdomains.txt")
    } else if runner.step_done("subdomains.txt") {
        println!("[1/5] Resuming — subdomains.txt exists");
        runner.read_file_lines("subdomains.txt")
    } else {
        runner.run_bbot(&targets, &bbot_flags).await?
    };

    // Scope filter: subdomains
    let (subdomains, oos_subs) = filter_urls_by_scope(&subdomains, &scope_identifiers);
    if !oos_subs.is_empty() {
        println!("  Filtered {} out-of-scope subdomains", oos_subs.len());
        let _ = std::fs::write(
            runner.recon_dir.join("subdomains_out_of_scope.txt"),
            oos_subs.join("\n"),
        );
        // Rewrite subdomains.txt with only in-scope
        let _ = std::fs::write(
            runner.recon_dir.join("subdomains.txt"),
            subdomains.join("\n"),
        );
    }

    // 2. Live host detection
    let _live_hosts = if runner.skip_steps.contains("httpx") {
        println!("[2/5] Skipped httpx (--skip httpx)");
        runner.read_file_lines("live_hosts.txt")
    } else if runner.step_done("live_hosts.txt") {
        println!("[2/5] Resuming — live_hosts.txt exists");
        runner.read_file_lines("live_hosts.txt")
    } else {
        runner.run_httpx(&subdomains).await?
    };

    // 3. URL collection + JS analysis
    let urls = if runner.skip_steps.contains("urls") {
        println!("[3/5] Skipped URL collection (--skip urls)");
        runner.read_file_lines("urls.txt")
    } else if runner.step_done("urls.txt") {
        println!("[3/5] Resuming — urls.txt exists");
        runner.read_file_lines("urls.txt")
    } else {
        runner.run_url_collection(&targets).await?
    };

    // Scope filter: URLs
    let (urls, oos_urls) = filter_urls_by_scope(&urls, &scope_identifiers);
    if !oos_urls.is_empty() {
        println!("  Filtered {} out-of-scope URLs", oos_urls.len());
        let _ = std::fs::write(
            runner.recon_dir.join("urls_out_of_scope.txt"),
            oos_urls.join("\n"),
        );
        // Rewrite urls.txt with only in-scope
        let _ = std::fs::write(
            runner.recon_dir.join("urls.txt"),
            urls.join("\n"),
        );
        // Also refilter JS files
        let js_files: Vec<&String> = urls.iter().filter(|u| {
            u.to_lowercase().ends_with(".js") || u.to_lowercase().contains(".js?")
        }).collect();
        let _ = std::fs::write(
            runner.recon_dir.join("js_files.txt"),
            js_files.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"),
        );
    }

    // 4. Nuclei scan
    let _nuclei = if runner.skip_steps.contains("nuclei") {
        println!("[4/5] Skipped nuclei (--skip nuclei)");
        runner.read_file_lines("nuclei.txt")
    } else if runner.marker_done(".nuclei_done") {
        println!("[4/5] Resuming — nuclei already completed");
        runner.read_file_lines("nuclei.txt")
    } else {
        let results = runner.run_nuclei().await?;
        let _ = std::fs::write(runner.recon_dir.join(".nuclei_done"), "");
        results
    };

    // 5. LLM AP identification
    let rr_path = project_dir.join("RR.json");
    let attack_points = if runner.skip_steps.contains("llm") {
        println!("[5/5] Skipped LLM AP identification (--skip llm)");
        vec![]
    } else if !force && rr_path.exists() && rr_path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        println!("[5/5] Resuming — RR.json exists");
        println!("\nRR.json already exists: {}", rr_path.display());
        return Ok(());
    } else {
        runner.run_ap_identification().await?
    };

    // Scope filter: AP URLs — remove any APs with out-of-scope URLs
    let mut attack_points: Vec<AttackPoint> = attack_points
        .into_iter()
        .filter(|ap| {
            if is_in_scope(&ap.url, &scope_identifiers) {
                true
            } else {
                eprintln!("  Removed out-of-scope AP: {} ({})", ap.ap_id, ap.url);
                false
            }
        })
        .collect();

    // Enrich request_sample with httpx packet data
    let httpx_json_lines = runner.read_file_lines("httpx_results.jsonl");
    let httpx_json = parse_httpx_json(&httpx_json_lines);
    let live_hosts_lines = runner.read_file_lines("live_hosts.txt");
    let httpx_text = parse_httpx_text(&live_hosts_lines);
    enrich_request_samples(&mut attack_points, &httpx_json, &httpx_text);

    // 6. Generate RR.json
    let rr_path = runner.generate_rr(attack_points)?;
    println!("\nRR.json generated: {}", rr_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbot_flags_passive_when_restricted() {
        let scopes = vec![WebScope {
            identifier: "*.example.com".to_string(),
            asset_type: "WILDCARD".to_string(),
            max_severity: None,
            instruction: Some("Do not test automated scanning".to_string()),
        }];
        let flags = get_bbot_flags(&scopes);
        assert_eq!(flags, vec!["-rf", "passive"]);
    }

    #[test]
    fn test_bbot_flags_aggressive_excluded_when_no_restriction() {
        let scopes = vec![WebScope {
            identifier: "*.example.com".to_string(),
            asset_type: "WILDCARD".to_string(),
            max_severity: None,
            instruction: None,
        }];
        let flags = get_bbot_flags(&scopes);
        assert_eq!(flags, vec!["-ef", "aggressive"]);
    }

    #[test]
    fn test_rr_serialization() {
        let rr = ReconResult {
            project_id: "test_20260408".to_string(),
            bbp: BbpInfo {
                platform: "hackerone".to_string(),
                handle: "test".to_string(),
                name: "Test Program".to_string(),
                score: 85.0,
            },
            scope: ScopeInfo {
                identifier: "*.test.com".to_string(),
                asset_type: "WILDCARD".to_string(),
                eligible_for_bounty: true,
                max_severity: Some("critical".to_string()),
                instruction: None,
                availability_requirement: None,
                confidentiality_requirement: None,
                integrity_requirement: None,
            },
            target: TargetInfo {
                subdomain: "api.test.com".to_string(),
                ip: Some("1.2.3.4".to_string()),
                tech_stack: vec!["nginx".to_string(), "react".to_string()],
                status_code: 200,
                title: Some("Test API".to_string()),
            },
            attack_points: vec![AttackPoint {
                ap_id: "ap_001".to_string(),
                url: "https://api.test.com/v1/users/123".to_string(),
                method: "GET".to_string(),
                category: "idor_candidate".to_string(),
                group_id: None,
                priority: 1,
                evidence: Evidence {
                    source: "gau".to_string(),
                    raw: "/v1/users/123".to_string(),
                    llm_reasoning: Some("Numeric ID in user endpoint".to_string()),
                },
                request_sample: None,
            }],
            created_at: "2026-04-08T00:00:00+09:00".to_string(),
        };

        let json = serde_json::to_string_pretty(&rr).unwrap();
        assert!(json.contains("idor_candidate"));
        assert!(json.contains("ap_001"));

        // Roundtrip
        let parsed: ReconResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.project_id, "test_20260408");
        assert_eq!(parsed.attack_points.len(), 1);
        assert_eq!(parsed.attack_points[0].category, "idor_candidate");
    }

    #[test]
    fn test_generate_rr_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("test_20260408");
        let recon_dir = project_dir.join("recon");
        std::fs::create_dir_all(&recon_dir).unwrap();

        // program_info.json
        std::fs::write(
            project_dir.join("program_info.json"),
            r#"{"handle":"test","name":"Test Program","score":85.0,"web_scopes":3,"difficulty":50.0}"#,
        ).unwrap();

        // rule.csv
        std::fs::write(
            project_dir.join("rule.csv"),
            "identifier,asset_type,max_severity,instruction\n*.test.com,WILDCARD,critical,\n",
        ).unwrap();

        let runner = ReconRunner::new(&project_dir, false, HashSet::new());
        let aps = vec![AttackPoint {
            ap_id: "ap_001".to_string(),
            url: "https://api.test.com/swagger".to_string(),
            method: "GET".to_string(),
            category: "exposure".to_string(),
            group_id: None,
            priority: 2,
            evidence: Evidence {
                source: "nuclei".to_string(),
                raw: "swagger-api".to_string(),
                llm_reasoning: None,
            },
            request_sample: None,
        }];

        let rr_path = runner.generate_rr(aps).unwrap();
        assert!(rr_path.exists());

        let content = std::fs::read_to_string(&rr_path).unwrap();
        let rr: ReconResult = serde_json::from_str(&content).unwrap();
        assert_eq!(rr.bbp.handle, "test");
        assert_eq!(rr.attack_points.len(), 1);
        assert_eq!(rr.attack_points[0].category, "exposure");
    }

    #[test]
    fn test_step_done_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("test_proj");
        let recon_dir = project_dir.join("recon");
        std::fs::create_dir_all(&recon_dir).unwrap();
        std::fs::write(recon_dir.join("subdomains.txt"), "").unwrap();

        let runner = ReconRunner::new(&project_dir, false, HashSet::new());
        assert!(!runner.step_done("subdomains.txt"));
    }

    #[test]
    fn test_step_done_with_content() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("test_proj");
        let recon_dir = project_dir.join("recon");
        std::fs::create_dir_all(&recon_dir).unwrap();
        std::fs::write(recon_dir.join("subdomains.txt"), "a.example.com\nb.example.com").unwrap();

        let runner = ReconRunner::new(&project_dir, false, HashSet::new());
        assert!(runner.step_done("subdomains.txt"));
    }

    #[test]
    fn test_step_done_force_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("test_proj");
        let recon_dir = project_dir.join("recon");
        std::fs::create_dir_all(&recon_dir).unwrap();
        std::fs::write(recon_dir.join("subdomains.txt"), "a.example.com").unwrap();

        let runner = ReconRunner::new(&project_dir, true, HashSet::new());
        assert!(!runner.step_done("subdomains.txt"));
    }

    #[test]
    fn test_sanitize_domain() {
        assert_eq!(ReconRunner::sanitize_domain("*.example.com"), "example_com");
        assert_eq!(ReconRunner::sanitize_domain("api.test.io"), "api_test_io");
        assert_eq!(ReconRunner::sanitize_domain("example.com"), "example_com");
    }

    #[test]
    fn test_marker_done() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("test_proj");
        let recon_dir = project_dir.join("recon");
        std::fs::create_dir_all(&recon_dir).unwrap();

        let runner = ReconRunner::new(&project_dir, false, HashSet::new());
        assert!(!runner.marker_done(".nuclei_done"));

        std::fs::write(recon_dir.join(".nuclei_done"), "").unwrap();
        assert!(runner.marker_done(".nuclei_done"));
    }

    // ── Scope filter tests ──

    #[test]
    fn test_is_in_scope_wildcard() {
        let scopes = vec!["*.grammarly.io".to_string()];
        assert!(is_in_scope("https://app.grammarly.io/api/v1", &scopes));
        assert!(is_in_scope("https://grammarly.io/login", &scopes));
        assert!(is_in_scope("sub.deep.grammarly.io", &scopes));
        assert!(!is_in_scope("https://coda.io/api", &scopes));
        assert!(!is_in_scope("https://evil-grammarly.io/x", &scopes));
    }

    #[test]
    fn test_is_in_scope_exact() {
        let scopes = vec!["app.example.com".to_string()];
        assert!(is_in_scope("https://app.example.com/path", &scopes));
        assert!(!is_in_scope("https://other.example.com/path", &scopes));
        assert!(!is_in_scope("https://example.com/path", &scopes));
    }

    #[test]
    fn test_is_in_scope_multiple() {
        let scopes = vec![
            "*.anduril.com".to_string(),
            "app.special.io".to_string(),
        ];
        assert!(is_in_scope("https://api.anduril.com/v1", &scopes));
        assert!(is_in_scope("https://app.special.io/login", &scopes));
        assert!(!is_in_scope("https://andurildev.com/x", &scopes));
        assert!(!is_in_scope("https://api.sanity.io/x", &scopes));
        assert!(!is_in_scope("https://identitytoolkit.googleapis.com", &scopes));
    }

    #[test]
    fn test_filter_urls_by_scope() {
        let urls = vec![
            "https://app.grammarly.io/api".to_string(),
            "https://coda.io/api".to_string(),
            "https://sub.grammarly.io/login".to_string(),
            "https://evil.com/hack".to_string(),
        ];
        let scopes = vec!["*.grammarly.io".to_string()];

        let (in_scope, out_of_scope) = filter_urls_by_scope(&urls, &scopes);
        assert_eq!(in_scope.len(), 2);
        assert_eq!(out_of_scope.len(), 2);
        assert!(in_scope.iter().all(|u| u.contains("grammarly.io")));
        assert!(out_of_scope.iter().all(|u| !u.contains("grammarly.io")));
    }

    #[test]
    fn test_extract_hostname() {
        assert_eq!(extract_hostname("https://app.example.com/path?q=1"), "app.example.com");
        assert_eq!(extract_hostname("http://api.test.io:8080/v1"), "api.test.io");
        assert_eq!(extract_hostname("sub.domain.com"), "sub.domain.com");
        assert_eq!(extract_hostname(""), "");
    }

    #[test]
    fn test_parse_httpx_text() {
        let lines = vec![
            "https://api.example.com [200] [API Server] [nginx]".to_string(),
            "https://admin.example.com [403] [Forbidden] [apache]".to_string(),
            "https://broken.example.com".to_string(),
        ];
        let map = parse_httpx_text(&lines);
        assert_eq!(map.get("api.example.com"), Some(&200));
        assert_eq!(map.get("admin.example.com"), Some(&403));
        assert_eq!(map.get("broken.example.com"), None);
    }

    #[test]
    fn test_parse_httpx_json() {
        let lines = vec![
            r#"{"url":"https://api.example.com","status_code":200,"title":"API","webserver":"nginx","content_type":"application/json"}"#.to_string(),
            r#"{"url":"https://admin.example.com","status_code":403,"title":"Forbidden"}"#.to_string(),
        ];
        let map = parse_httpx_json(&lines);
        assert_eq!(map.len(), 2);
        let api = map.get("api.example.com").unwrap();
        assert_eq!(api.status_code, Some(200));
        assert_eq!(api.webserver.as_deref(), Some("nginx"));
        let admin = map.get("admin.example.com").unwrap();
        assert_eq!(admin.status_code, Some(403));
    }

    #[test]
    fn test_enrich_with_json_data() {
        let mut aps = vec![AttackPoint {
            ap_id: "ap_001".to_string(),
            url: "https://api.example.com/v1/users?id=123".to_string(),
            method: "GET".to_string(),
            category: "IDOR".to_string(),
            group_id: None,
            priority: 1,
            evidence: Evidence {
                source: "gau".to_string(),
                raw: "/v1/users?id=123".to_string(),
                llm_reasoning: None,
            },
            request_sample: None,
        }];

        let mut httpx_json = HashMap::new();
        httpx_json.insert("api.example.com".to_string(), HttpxResult {
            url: Some("https://api.example.com".to_string()),
            input: None,
            status_code: Some(200),
            title: Some("API".to_string()),
            webserver: Some("nginx".to_string()),
            content_type: Some("application/json".to_string()),
            technologies: None,
            response_headers: None,
            response_body: Some("{ \"users\": [] }".to_string()),
            host: None,
            port: None,
            scheme: None,
            content_length: Some(15),
            method: None,
        });

        enrich_request_samples(&mut aps, &httpx_json, &HashMap::new());

        let sample = aps[0].request_sample.as_ref().unwrap();
        assert_eq!(sample.response_status, 200);
        assert_eq!(sample.method, "GET");
        assert_eq!(sample.params.get("id"), Some(&"123".to_string()));
        assert!(sample.response_snippet.is_some());
        assert!(sample.response_snippet.as_ref().unwrap().contains("users"));
    }

    #[test]
    fn test_enrich_fallback_to_text() {
        let mut aps = vec![AttackPoint {
            ap_id: "ap_001".to_string(),
            url: "https://other.example.com/api".to_string(),
            method: "GET".to_string(),
            category: "exposure".to_string(),
            group_id: None,
            priority: 3,
            evidence: Evidence {
                source: "gau".to_string(),
                raw: "/api".to_string(),
                llm_reasoning: None,
            },
            request_sample: None,
        }];

        let mut httpx_text = HashMap::new();
        httpx_text.insert("other.example.com".to_string(), 403u16);

        enrich_request_samples(&mut aps, &HashMap::new(), &httpx_text);

        let sample = aps[0].request_sample.as_ref().unwrap();
        assert_eq!(sample.response_status, 403);
        assert!(sample.response_snippet.is_none());
    }

    #[test]
    fn test_enrich_preserves_existing_sample() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer xyz".to_string());

        let mut aps = vec![AttackPoint {
            ap_id: "ap_001".to_string(),
            url: "https://api.example.com/v1".to_string(),
            method: "POST".to_string(),
            category: "injection_candidate".to_string(),
            group_id: Some("api_v1".to_string()),
            priority: 3,
            evidence: Evidence {
                source: "llm".to_string(),
                raw: "/v1".to_string(),
                llm_reasoning: None,
            },
            request_sample: Some(RequestSample {
                url: "https://api.example.com/v1".to_string(),
                method: "POST".to_string(),
                headers: headers.clone(),
                params: HashMap::new(),
                response_status: 0,
                response_snippet: None,
            }),
        }];

        let mut httpx_json = HashMap::new();
        httpx_json.insert("api.example.com".to_string(), HttpxResult {
            url: Some("https://api.example.com".to_string()),
            input: None,
            status_code: Some(201),
            title: None,
            webserver: None,
            content_type: None,
            technologies: None,
            response_headers: None,
            response_body: Some("created".to_string()),
            host: None,
            port: None,
            scheme: None,
            content_length: None,
            method: None,
        });

        enrich_request_samples(&mut aps, &httpx_json, &HashMap::new());

        let sample = aps[0].request_sample.as_ref().unwrap();
        assert_eq!(sample.response_status, 201);
        assert_eq!(sample.headers.get("Authorization"), Some(&"Bearer xyz".to_string()));
        assert_eq!(sample.response_snippet.as_deref(), Some("created"));
    }
}
