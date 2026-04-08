# h1scout — CLAUDE.md

You are a Rust engineer. Work autonomously. Do not ask for confirmation.
Follow the TDD cycle strictly for every step.

---

## TDD Cycle — MANDATORY for every step

For each step below, execute this exact sequence:

```
1. WRITE TEST   — write the test code first (must compile but fail)
2. RUN FAIL     — run `cargo test <test_name>` and confirm it fails (red)
3. WRITE CODE   — implement the minimum code to make the test pass
4. RUN PASS     — run `cargo test <test_name>` and confirm it passes (green)
5. REFACTOR     — clean up if needed, run full `cargo test` to confirm no regression
6. COMMIT       — `git add -A && git commit -m "step X-X: <description>"`
```

Never write implementation code before its test exists.
Never move to the next step until current step's tests are green.
Never skip the commit.

---

## Environment

- Rust edition 2021
- No real H1 API calls — use httpmock + fixtures only
- SQLite via sqlx
- Commit after every green step

---

## Phase 1 — Data Layer

### Step 1-1: Fixtures

Create these files (no test needed, just create):

**tests/fixtures/programs_page1.json**
```json
{
  "data": [
    {"id":"1","type":"program","attributes":{"handle":"general-motors","name":"General Motors","offers_bounties":true,"submission_state":"open","fast_payments":true,"open_scope":false}},
    {"id":"2","type":"program","attributes":{"handle":"uber","name":"Uber","offers_bounties":true,"submission_state":"open","fast_payments":true,"open_scope":true}},
    {"id":"3","type":"program","attributes":{"handle":"grab","name":"Grab","offers_bounties":true,"submission_state":"open","fast_payments":false,"open_scope":false}}
  ],
  "links": {"next":"https://api.hackerone.com/v1/hackers/programs?page[number]=2"}
}
```

**tests/fixtures/programs_page2.json**
```json
{
  "data": [
    {"id":"4","type":"program","attributes":{"handle":"lyft","name":"Lyft","offers_bounties":true,"submission_state":"open","fast_payments":true,"open_scope":false}},
    {"id":"5","type":"program","attributes":{"handle":"ford","name":"Ford Motor Company","offers_bounties":true,"submission_state":"open","fast_payments":false,"open_scope":true}}
  ],
  "links": {}
}
```

**tests/fixtures/scopes_android.json**
```json
{
  "data": [
    {"id":"s1","type":"structured-scope","attributes":{"asset_type":"ANDROID","asset_identifier":"com.gm.myvehicle","eligible_for_bounty":true,"eligible_for_submission":true,"max_severity":"critical"}},
    {"id":"s2","type":"structured-scope","attributes":{"asset_type":"URL","asset_identifier":"*.gm.com","eligible_for_bounty":true,"eligible_for_submission":true,"max_severity":"high"}},
    {"id":"s3","type":"structured-scope","attributes":{"asset_type":"ANDROID","asset_identifier":"com.uber.driver","eligible_for_bounty":true,"eligible_for_submission":true,"max_severity":"critical"}}
  ],
  "links": {}
}
```

Commit: `git add -A && git commit -m "step 1-1: add test fixtures"`

---

### Step 1-2: API Models

TDD cycle:

**TEST FIRST** — in `src/api/models.rs`, write:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_program_list() {
        let json = include_str!("../../tests/fixtures/programs_page1.json");
        let result: ProgramList = serde_json::from_str(json).unwrap();
        assert_eq!(result.data.len(), 3);
        assert_eq!(result.data[0].attributes.handle, "general-motors");
        assert!(result.data[0].attributes.offers_bounties);
        assert!(result.links.as_ref().unwrap().next.is_some());
    }

    #[test]
    fn test_parse_scope_list() {
        let json = include_str!("../../tests/fixtures/scopes_android.json");
        let result: ScopeList = serde_json::from_str(json).unwrap();
        assert_eq!(result.data.len(), 3);
        assert_eq!(result.data[0].attributes.asset_type, "ANDROID");
    }
}
```

Run `cargo test` → confirm FAIL (structs don't exist yet).

**IMPLEMENT** structs: `ProgramList`, `ProgramData`, `ProgramAttributes`, `ScopeList`, `ScopeData`, `ScopeAttributes`, `Links`.

Run `cargo test` → confirm PASS.

Commit: `git add -A && git commit -m "step 1-2: api models with tests green"`

---

### Step 1-3: API Client

TDD cycle:

**TEST FIRST** — in `tests/api_mock.rs`:
```rust
#[tokio::test]
async fn test_pagination_fetches_all_programs() {
    // mock page1 → 3 programs + next link
    // mock page2 → 2 programs + no next link
    // assert total = 5
}

#[tokio::test]
async fn test_rate_limit_retries() {
    // mock first call → 429
    // mock second call → 200 with 1 program
    // assert success after retry
}

#[tokio::test]
async fn test_auth_error_returns_err() {
    // mock → 401
    // assert result.is_err()
}
```

Run `cargo test` → FAIL.

**IMPLEMENT** `src/api/client.rs`:
- `H1Client { client: reqwest::Client, username: String, api_token: String }`
- `H1Client::new(username, api_token) -> Self`
- `async fn fetch_all_programs(&self) -> anyhow::Result<Vec<ProgramData>>`
- `async fn fetch_scopes(&self, handle: &str) -> anyhow::Result<Vec<ScopeData>>`
- Pagination: loop until `links.next` is None
- Rate limit: on 429, sleep 3s, retry max 3 times

Run `cargo test` → PASS.

Commit: `git add -A && git commit -m "step 1-3: api client with pagination and retry"`

---

### Step 1-4: SQLite Cache

TDD cycle:

**TEST FIRST** — in `src/db/cache.rs` tests:
```rust
#[tokio::test]
async fn test_ttl_expired() {
    // insert with fetched_at = now - 90000
    // assert is_stale() == true
}

#[tokio::test]
async fn test_ttl_fresh() {
    // insert with fetched_at = now - 3600
    // assert is_stale() == false
}

#[tokio::test]
async fn test_upsert_idempotent() {
    // upsert same program twice
    // assert count == 1
}
```

Run `cargo test` → FAIL.

**IMPLEMENT** `src/db/cache.rs`:
- Schema (programs + scopes tables as in plan.md)
- `Cache::new(db_path) -> anyhow::Result<Self>` — creates file + tables if not exist
- `async fn upsert_programs(&self, programs: &[ProgramData])`
- `async fn upsert_scopes(&self, handle: &str, scopes: &[ScopeData])`
- `async fn is_stale(&self, ttl_secs: u64) -> bool`
- `async fn get_all_programs(&self) -> Vec<ProgramData>`
- `async fn get_scopes_for(&self, handle: &str) -> Vec<ScopeData>`

Run `cargo test` → PASS.

Phase 1 done check: `cargo test` all green.

Commit: `git add -A && git commit -m "step 1-4: sqlite cache — phase 1 complete"`

---

## Phase 2 — Scorer

### Step 2-1: Weights

**TEST FIRST**:
```rust
#[test]
fn test_weights_sum_to_one() {
    let w = Weights::default();
    let sum = w.bounty_scale + w.response_speed + w.scope_quality + w.program_health;
    assert!((sum - 1.0).abs() < 1e-9);
}

#[test]
fn test_weights_from_missing_config_uses_default() {
    let w = Weights::from_config("/nonexistent/path.toml");
    assert!((w.bounty_scale - 0.30).abs() < 1e-9);
}
```

Run → FAIL. Implement. Run → PASS.

Commit: `git add -A && git commit -m "step 2-1: weights struct"`

---

### Step 2-2: Score Engine

**TEST FIRST**:
```rust
#[test]
fn test_android_scope_gives_bonus() {
    // program with ANDROID eligible scope
    // assert score.scope_score >= 80.0
    // assert score.has_android == true
}

#[test]
fn test_closed_program_low_health() {
    // submission_state = "closed"
    // assert score.health_score <= 10.0
}

#[test]
fn test_all_scores_in_bounds() {
    // any program
    // assert bounty/response/scope/health all in 0.0..=100.0
    // assert total in 0.0..=100.0
}

#[test]
fn test_sort_order() {
    // 3 programs with different scores
    // sort by total desc
    // assert first.total >= second.total >= third.total
}
```

Run → FAIL.

**IMPLEMENT** `src/scorer/engine.rs`:
- `score_program(program, scopes, weights) -> ProgramScore`
- bounty_score: offers_bounties→60, fast_payments→+40 (max 100)
- response_score: fast_payments→80, else→40
- scope_score: eligible count×5 (max 60) + ANDROID+20 + WILDCARD+10 + mobility_keyword+15 (clamp 0..100)
- health_score: open+40, fast_payments+30, open_scope+20, offers_bounties+10
- total = Σ(score×weight), clamp 0..100

Run → PASS.

Commit: `git add -A && git commit -m "step 2-2: score engine — phase 2 complete"`

---

## Phase 3 — Filters + CLI

### Step 3-1: Mobility Filter

**TEST FIRST**:
```rust
#[test]
fn test_match_by_program_name() {
    // program name = "General Motors"
    // assert is_mobility_target() == true
}

#[test]
fn test_match_by_scope_identifier() {
    // scope identifier = "telematics.example.com"
    // assert is_mobility_target() == true
}

#[test]
fn test_no_false_positive() {
    // program = "Airbnb", scopes = ["*.airbnb.com"]
    // assert is_mobility_target() == false
}
```

Run → FAIL. Implement. Run → PASS.

Commit: `git add -A && git commit -m "step 3-1: mobility filter"`

---

### Step 3-2: Android Filter

**TEST FIRST**:
```rust
#[test]
fn test_android_detected() { /* ANDROID asset_type → true */ }

#[test]
fn test_no_android() { /* URL only → false */ }

#[test]
fn test_package_extraction() {
    // ANDROID scopes with com.gm.myvehicle, com.uber.driver
    // assert packages == ["com.gm.myvehicle", "com.uber.driver"]
}
```

Run → FAIL. Implement. Run → PASS.

Commit: `git add -A && git commit -m "step 3-2: android filter"`

---

### Step 3-3: Output

Implement `src/output/table.rs` and `src/output/json.rs`.

table.rs — tabled crate, columns: program | score | bounty | resp | scope | android | mobility
json.rs — serde_json::to_string_pretty

No TDD required for output formatting. Manual verification sufficient.

Commit: `git add -A && git commit -m "step 3-3: output formatters"`

---

### Step 3-4: CLI + main.rs

Wire everything together:

```
h1scout fetch [--force] [--dry-run]
h1scout list [--top N] [--filter android|mobility]... [--format table|json|csv]
h1scout export [--format json|csv] [--output path]
```

Config: `~/.h1scout/config.toml`
DB: `~/.h1scout/h1scout.db`
Env: `H1_USERNAME`, `H1_API_TOKEN`

After wiring, run:
```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
```

All must pass.

Commit: `git add -A && git commit -m "step 3-4: cli wired — phase 3 complete"`

---

## Phase 4 — TUI + Auto-Recon 통합

h1scout는 Auto-Recon 파이프라인의 전체 진입점이다.
사용자가 TUI로 BBP를 선택하면 BBOT 서브도메인 수집 → LLM AP 식별 → RR.json 생성까지 자동 실행된다.
완료된 RR.json에서 TUI로 AP를 선택하면 Auto-Solve로 넘긴다.

### 새로 추가할 커맨드

```
h1scout select          — TUI로 BBP 선택 → Auto-Recon 전체 실행
h1scout review          — TUI로 AP 선택 → Auto-Solve 입력 생성
```

### 새로 추가할 크레이트

```toml
dialoguer = "0.11"   # TUI 체크박스/선택
indicatif = "0.17"   # 진행 상황 프로그레스바
```

---

### Step 4-1: select TUI

**목표**: 스코어 순으로 BBP 목록을 체크박스로 표시, 선택된 BBP의 project_id와 scope CSV를 생성한다.

**TDD cycle**:

TEST FIRST — `tests/select_test.rs`:
```rust
#[test]
fn test_project_id_format() {
    // project_id = "{handle}_{YYYYMMDD}" 형식인지 검증
    // assert project_id.starts_with("playtika_")
    // assert project_id.len() == "playtika_".len() + 8
}

#[test]
fn test_scope_csv_web_only() {
    // ScopeData 목록에서 WILDCARD, URL만 필터링
    // GOOGLE_PLAY_APP_ID, APPLE_STORE_APP_ID 제외
    // eligible_for_bounty=false 제외
    // eligible_for_submission=false 제외
    // assert 결과에 웹 타겟만 포함
}

#[test]
fn test_scope_csv_instruction_parsing() {
    // instruction에 "out of scope" 포함된 항목 제외
    // instruction에 "do not test" 포함된 항목 제외
    // assert 필터링 결과 정확
}

#[test]
fn test_multi_identifier_split() {
    // identifier = "a.com,b.com,c.com" (쉼표 구분)
    // assert 3개로 분리
}
```

Run → FAIL.

**IMPLEMENT** `src/select.rs`:

```rust
// project_id 생성
pub fn make_project_id(handle: &str) -> String {
    let date = chrono::Local::now().format("%Y%m%d");
    format!("{}_{}", handle, date)
}

// 웹 scope 필터링 + rule.csv 생성
pub fn filter_web_scopes(scopes: &[ScopeData]) -> Vec<WebScope>

// project 디렉토리 초기화
pub fn init_project_dir(project_id: &str, base_dir: &Path) -> Result<PathBuf>
// 생성 구조:
// {base_dir}/{project_id}/
//   program_info.json   — BBP 정보 (handle, name, score)
//   rule.csv            — 필터링된 웹 scope
//   recon/              — Auto-Recon 결과물 저장 위치
```

Run → PASS.

**TUI 구현** (`src/tui/select.rs`):
- `dialoguer::MultiSelect`로 BBP 체크박스 표시
- 표시 형식: `[87.3] Playtika (playtika) — web:5`
  - score, name, handle, 웹 scope 개수
- Space로 다중 선택, Enter로 확정
- 선택된 BBP마다 `init_project_dir()` 호출

Commit: `git add -A && git commit -m "step 4-1: select TUI with project init"`

---

### Step 4-2: Auto-Recon 실행

**목표**: 선택된 project 디렉토리에서 BBOT → gau/waybackurls → linkfinder/secretfinder → nuclei → LLM AP 식별 순서로 실행한다.

**IMPLEMENT** `src/recon/runner.rs`:

```rust
pub struct ReconRunner {
    pub project_dir: PathBuf,
    pub scope: Vec<WebScope>,
    pub bbot_flags: Vec<String>,  // get_bbot_flags()로 결정
}

impl ReconRunner {
    // BBOT 실행
    pub async fn run_bbot(&self) -> Result<Vec<String>>  // 서브도메인 목록 반환

    // URL 수집
    pub async fn run_url_collection(&self, subdomains: &[String]) -> Result<Vec<String>>

    // JS 분석
    pub async fn run_js_analysis(&self, urls: &[String]) -> Result<JsFindings>

    // nuclei 스캔
    pub async fn run_nuclei(&self, live_hosts: &[String]) -> Result<Vec<NucleiResult>>

    // LLM AP 식별 (claude --print 호출)
    pub async fn run_ap_identification(&self, data: &ReconData) -> Result<Vec<AttackPoint>>

    // RR.json 생성
    pub async fn generate_rr(&self, attack_points: Vec<AttackPoint>) -> Result<()>
}

// scope의 instruction 필드 기반 BBOT 플래그 결정
pub fn get_bbot_flags(scopes: &[WebScope]) -> Vec<String> {
    let has_restriction = scopes.iter().any(|s| {
        let inst = s.instruction.as_deref().unwrap_or("").to_lowercase();
        ["do not test", "no automated", "no scanning", "out of scope"]
            .iter().any(|k| inst.contains(k))
    });

    if has_restriction {
        vec!["-rf".into(), "passive".into()]
    } else {
        vec!["-ef".into(), "aggressive".into()]
    }
}
```

**LLM 호출** (`src/llm.rs`):
```rust
// claude --print 또는 codex exec 자동 감지
pub async fn query(prompt: &str, cwd: &Path) -> Result<String>

// codex는 NotImplementedError — 형이 구현
fn query_codex(_prompt: &str) -> Result<String> {
    Err(anyhow::anyhow!(
        "codex provider 구현 필요: parse_codex_output() 참고"
    ))
}
```

프로그레스바 (`indicatif`):
```
[1/5] 서브도메인 수집 중... (BBOT)     ████████░░ 80%
[2/5] URL 수집 중... (gau, waybackurls) ██████████ 100%
[3/5] JS 분석 중... (linkfinder)        ████░░░░░░ 40%
[4/5] 취약점 스캔 중... (nuclei)        ██░░░░░░░░ 20%
[5/5] AP 식별 중... (claude --print)    ░░░░░░░░░░ 0%
```

Commit: `git add -A && git commit -m "step 4-2: recon runner with progress"`

---

### Step 4-3: review TUI

**목표**: 완료된 RR.json을 TUI로 표시하고, 선택된 AP를 Auto-Solve 입력 포맷으로 출력한다.

**TDD cycle**:

TEST FIRST — `tests/review_test.rs`:
```rust
#[test]
fn test_rr_loading() {
    // RR.json 파일 로드
    // assert attack_points 파싱 정확
}

#[test]
fn test_ap_display_format() {
    // AP를 "[priority] category — url" 형식으로 표시
    // assert 형식 일치
}

#[test]
fn test_solve_output_format() {
    // 선택된 AP를 SR 입력 포맷으로 변환
    // assert 필수 필드 포함 (project_id, target, ap_id)
}
```

Run → FAIL.

**IMPLEMENT** `src/tui/review.rs`:
- `~/.h1scout/projects/` 폴더에서 완료된 RR.json 목록 로드
- BBP 선택 → AP 목록 표시
- AP 표시 형식:
  ```
  [1] idor_candidate     — https://api.playtika.com/v1/users/123
  [2] exposure           — https://api.playtika.com/swagger
  [3] routing_inference  — https://api.playtika.com/api/admin (LLM 추론)
  ```
- 선택된 AP를 Auto-Solve 입력 JSON으로 stdout 출력

Commit: `git add -A && git commit -m "step 4-3: review TUI — phase 4 complete"`

---

### Step 4-4: CLI 연결

`src/cli.rs`에 추가:
```rust
/// TUI로 BBP 선택 후 Auto-Recon 전체 실행
Select {
    /// projects 저장 경로 (기본: ~/.h1scout/projects)
    #[arg(long)]
    projects_dir: Option<String>,
},

/// TUI로 AP 선택 후 Auto-Solve 입력 생성
Review {
    /// 특정 project_id 지정 (미지정 시 목록에서 선택)
    #[arg(long)]
    project_id: Option<String>,
},
```

`src/main.rs`에서 커맨드 연결.

전체 빌드 및 테스트:
```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
```

Commit: `git add -A && git commit -m "step 4-4: select/review commands wired — phase 4 complete"`

---

## 프로젝트 폴더 구조

```
~/.h1scout/
  h1scout.db              — SQLite 캐시
  config.toml             — 가중치 설정
  projects/
    {handle}_{YYYYMMDD}/
      program_info.json   — BBP 정보 (handle, name, score)
      rule.csv            — 필터링된 웹 scope
      recon/
        subdomains.txt    — BBOT 서브도메인
        live_hosts.txt    — httpx 살아있는 호스트
        urls.txt          — gau + waybackurls
        js_endpoints.txt  — linkfinder 결과
        secrets.txt       — secretfinder 결과
        nuclei.txt        — nuclei 스캔 결과
      RR.json             — 최종 Recon Result
```

---

## LLM AP 식별 프롬프트 구조

```
SKILL: auto-recon/skills/ap-identifier/SKILL.md 내용 주입
DATA:
  - live_hosts.txt (기술스택 포함)
  - urls.txt
  - js_endpoints.txt
  - secrets.txt
  - nuclei.txt
  - scope 정보 (max_severity, instruction)

OUTPUT: JSON 배열만 반환 (attack_points 포맷)
```

---

## Definition of Done

```bash
cargo test              # zero failures
cargo build --release   # zero warnings
cargo clippy -- -D warnings  # zero warnings
```

All phase checklists green. Every step has a commit.
