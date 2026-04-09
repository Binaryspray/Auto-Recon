use anyhow::{anyhow, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
    pub ap_id: String,
    pub url: String,
    pub method: String,
    pub category: String,
    pub priority: u8,
    pub evidence: Evidence,
    pub request_sample: Option<RequestSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub raw: String,
    pub llm_reasoning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSample {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub params: HashMap<String, String>,
    pub response_status: u16,
    pub response_snippet: Option<String>,
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

// ── Recon Runner ──

pub struct ReconRunner {
    pub project_dir: PathBuf,
    pub recon_dir: PathBuf,
}

impl ReconRunner {
    pub fn new(project_dir: &Path) -> Self {
        let recon_dir = project_dir.join("recon");
        Self {
            project_dir: project_dir.to_path_buf(),
            recon_dir,
        }
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

    fn run_cmd(&self, cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(cmd)
            .args(args)
            .current_dir(&self.recon_dir)
            .env("PATH", Self::extended_path())
            .output()?;

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

    /// Step 1: Subdomain enumeration with BBOT
    pub fn run_bbot(&self, targets: &[String], bbot_flags: &[String]) -> Result<Vec<String>> {
        let total = targets.len();
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[1/5] {bar:30} {pos}/{len} domains — {msg}")
                .unwrap(),
        );
        pb.set_message("BBOT subdomain enumeration");

        let mut all_subdomains = Vec::new();

        for (i, target) in targets.iter().enumerate() {
            let domain = target.trim_start_matches("*.");
            pb.set_message(domain.to_string());

            let mut args = vec![
                "-t".to_string(), domain.to_string(),
                "--silent".to_string(),
                "--fast-mode".to_string(),
                "--force".to_string(),
                "-f".to_string(), "subdomain-enum".to_string(),
                "--json".to_string(),
            ];
            args.extend(bbot_flags.iter().cloned());

            match self.run_cmd("bbot", &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()) {
                Ok(output) => {
                    for line in output.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        // Parse BBOT JSON output — extract DNS_NAME and URL_UNVERIFIED hosts
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
                                        all_subdomains.push(host.to_string());
                                    }
                                }
                            }
                        } else {
                            // Fallback: treat as plain subdomain
                            all_subdomains.push(trimmed.to_string());
                        }
                    }
                }
                Err(e) => eprintln!("\nBBOT failed for {}: {}", domain, e),
            }
            pb.set_position((i + 1) as u64);
        }

        all_subdomains.sort();
        all_subdomains.dedup();

        // Save
        std::fs::write(
            self.recon_dir.join("subdomains.txt"),
            all_subdomains.join("\n"),
        )?;

        pb.finish_with_message(format!("Found {} subdomains", all_subdomains.len()));
        Ok(all_subdomains)
    }

    /// Step 2: Filter live hosts with httpx
    pub fn run_httpx(&self, subdomains: &[String]) -> Result<Vec<String>> {
        let pb = self.progress_bar(2, 5, "Live host detection (httpx)...");

        let input = subdomains.join("\n");
        let input_path = self.recon_dir.join("subdomains_input.txt");
        std::fs::write(&input_path, &input)?;

        let _ = self.run_cmd(
            "httpx",
            &[
                "-l", &input_path.to_string_lossy(),
                "-silent",
                "-title", "-status-code", "-tech-detect",
                "-web-server", "-ip", "-cname",
                "-o", &self.recon_dir.join("live_hosts.txt").to_string_lossy(),
            ],
        );

        let live = self.read_file_lines("live_hosts.txt");
        pb.finish_with_message(format!("Found {} live hosts", live.len()));
        Ok(live)
    }

    /// Step 3: URL collection (gau + waybackurls)
    pub fn run_url_collection(&self, targets: &[String]) -> Result<Vec<String>> {
        let total = targets.len();
        let pb = ProgressBar::new(total as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[3/5] {bar:30} {pos}/{len} domains — {msg}")
                .unwrap(),
        );
        pb.set_message("URL collection");

        let mut all_urls = Vec::new();

        for (i, target) in targets.iter().enumerate() {
            let domain = target.trim_start_matches("*.");
            pb.set_message(domain.to_string());

            // gau
            if let Ok(output) = self.run_cmd("gau", &[domain, "--subs"]) {
                for line in output.lines() {
                    if !line.trim().is_empty() {
                        all_urls.push(line.trim().to_string());
                    }
                }
            }

            // waybackurls
            if let Ok(output) = self.run_cmd("sh", &["-c", &format!("echo {} | waybackurls", domain)]) {
                for line in output.lines() {
                    if !line.trim().is_empty() {
                        all_urls.push(line.trim().to_string());
                    }
                }
            }
            pb.set_position((i + 1) as u64);
        }

        all_urls.sort();
        all_urls.dedup();

        std::fs::write(
            self.recon_dir.join("urls.txt"),
            all_urls.join("\n"),
        )?;

        // Extract JS files
        let js_files: Vec<&String> = all_urls.iter().filter(|u| {
            u.to_lowercase().ends_with(".js") || u.to_lowercase().contains(".js?")
        }).collect();

        std::fs::write(
            self.recon_dir.join("js_files.txt"),
            js_files.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"),
        )?;

        // linkfinder on JS files
        let mut js_endpoints = Vec::new();
        for js_url in &js_files {
            if let Ok(output) = self.run_cmd("linkfinder", &[
                "-i", js_url, "-o", "cli",
            ]) {
                for line in output.lines() {
                    if !line.trim().is_empty() {
                        js_endpoints.push(line.trim().to_string());
                    }
                }
            }
        }
        js_endpoints.sort();
        js_endpoints.dedup();

        std::fs::write(
            self.recon_dir.join("js_endpoints.txt"),
            js_endpoints.join("\n"),
        )?;

        pb.finish_with_message(format!(
            "Collected {} URLs, {} JS endpoints",
            all_urls.len(),
            js_endpoints.len()
        ));
        Ok(all_urls)
    }

    /// Step 4: Nuclei scan
    pub fn run_nuclei(&self) -> Result<Vec<String>> {
        let live_hosts_path = self.recon_dir.join("live_hosts.txt");
        if !live_hosts_path.exists() {
            println!("[4/5] Skipped nuclei — no live hosts");
            return Ok(vec![]);
        }

        println!("[4/5] Nuclei scan running (stats every 10s)...");

        let output_path = self.recon_dir.join("nuclei.txt");
        // Run nuclei with inherited stderr so stats print to terminal
        let status = Command::new("nuclei")
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
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();

        if let Err(e) = status {
            eprintln!("Warning: nuclei failed: {}", e);
        }

        let results = self.read_file_lines("nuclei.txt");
        println!("[4/5] Nuclei found {} results", results.len());
        Ok(results)
    }

    /// Step 5: LLM AP identification
    pub fn run_ap_identification(&self) -> Result<Vec<AttackPoint>> {
        let pb = self.progress_bar(5, 5, "AP identification (claude --print)...");

        // Gather all recon data
        let live_hosts = self.read_file_lines("live_hosts.txt");
        let urls = self.read_file_lines("urls.txt");
        let js_endpoints = self.read_file_lines("js_endpoints.txt");
        let nuclei = self.read_file_lines("nuclei.txt");

        // Read the AP identifier skill (select via AP_SKILL env var)
        let skill_content = match std::env::var("AP_SKILL").as_deref() {
            Ok("boundary") => include_str!("../SKILL/ap-identifier-boundary-SKILL.md"),
            _ => include_str!("../SKILL/ap-identifier-SKILL.md"),
        };

        let prompt = format!(
            "{}\n\n---\n\n## Recon Data\n\n### Live Hosts\n{}\n\n### URLs (sample, first 200)\n{}\n\n### JS Endpoints\n{}\n\n### Nuclei Results\n{}\n\n---\n\nAnalyze the above recon data. Return ONLY a JSON array of attack points. No other text.",
            skill_content,
            live_hosts.join("\n"),
            urls.iter().take(200).cloned().collect::<Vec<_>>().join("\n"),
            js_endpoints.join("\n"),
            nuclei.join("\n"),
        );

        let response = crate::llm::query(&prompt, &self.project_dir);

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
pub async fn run_recon(project_dir: &Path) -> Result<()> {
    let runner = ReconRunner::new(project_dir);

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

    println!("\n=== Auto-Recon: {} ===\n", project_dir.file_name().unwrap_or_default().to_string_lossy());

    // 1. Subdomain enumeration
    let subdomains = runner.run_bbot(&targets, &bbot_flags)?;

    // 2. Live host detection
    let _live_hosts = runner.run_httpx(&subdomains)?;

    // 3. URL collection + JS analysis
    let _urls = runner.run_url_collection(&targets)?;

    // 4. Nuclei scan
    let _nuclei = runner.run_nuclei()?;

    // 5. LLM AP identification
    let attack_points = runner.run_ap_identification()?;

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

        let runner = ReconRunner::new(&project_dir);
        let aps = vec![AttackPoint {
            ap_id: "ap_001".to_string(),
            url: "https://api.test.com/swagger".to_string(),
            method: "GET".to_string(),
            category: "exposure".to_string(),
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
}
