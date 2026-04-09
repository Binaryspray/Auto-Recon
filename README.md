# Auto-Recon

BBP 정찰 대상 선정 & 공격 표면 탐색 자동화 파이프라인

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────────┐
│                          h1scout CLI                                │
├──────────┬──────────┬──────────┬───────────────┬───────────────────┤
│  fetch   │   list   │  select  │    review     │      export       │
└────┬─────┴────┬─────┴────┬─────┴───────┬───────┴───────────────────┘
     │          │          │             │
     ▼          ▼          ▼             ▼
┌─────────┐ ┌──────┐ ┌─────────┐ ┌───────────┐
│ H1 API  │ │Score │ │  Recon  │ │  Review   │
│ Client  │ │Engine│ │ Runner  │ │   TUI     │
└────┬────┘ └──┬───┘ └────┬────┘ └─────┬─────┘
     │         │          │             │
     ▼         │          ▼             ▼
┌─────────┐   │   ┌──────────────┐ ┌──────────┐
│ SQLite  │◄──┘   │ 5-Step Recon │ │Auto-Solve│
│  Cache  │       │  Pipeline    │ │  Input   │
└─────────┘       └──────┬───────┘ └──────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   ┌─────────┐    ┌───────────┐    ┌──────────┐
   │  BBOT   │    │ gau/      │    │  nuclei  │
   │subdomain│    │waybackurls│    │  scanner │
   │  enum   │    │+linkfinder│    │          │
   └────┬────┘    └─────┬─────┘    └────┬─────┘
        │               │               │
        └───────────┬───┘───────────────┘
                    ▼
             ┌────────────┐
             │ LLM (claude│
             │  --print)  │
             │ AP 식별    │
             └──────┬─────┘
                    ▼
              ┌──────────┐
              │  RR.json │
              └──────────┘
```

## Recon 파이프라인 상세

```
[1/5] BBOT 서브도메인 수집
  │   bbot -t {domain} --silent --fast-mode --force -f subdomain-enum --json
  │   → subdomains.txt
  ▼
[2/5] httpx 라이브 호스트 필터링
  │   httpx -l subdomains.txt -silent -title -status-code -tech-detect
  │   → live_hosts.txt (호스트 + 기술스택 + 상태코드)
  ▼
[3/5] URL 수집 + JS 분석
  │   gau {domain} --subs → urls.txt
  │   waybackurls {domain} → urls.txt (합산)
  │   linkfinder -i {js_url} -o cli → js_endpoints.txt
  │   → urls.txt, js_files.txt, js_endpoints.txt
  ▼
[4/5] nuclei 취약점 스캔
  │   nuclei -l live_hosts.txt -tags exposure,config,misconfig,token,secret,...
  │   -exclude-tags dos,fuzz,intrusive -rate-limit 10 -stats
  │   → nuclei.txt
  ▼
[5/5] LLM AP 식별 (claude --print)
  │   SKILL/ap-identifier-SKILL.md + recon 데이터 → stdin
  │   카테고리: IDOR, auth_bypass, exposure, secret, injection,
  │            takeover, oauth_misconfig, jwt_attack, routing_inference
  │   → attack_points[] → RR.json
  ▼
  RR.json 생성 완료
```

## 스코어링 (5축)

BBP를 웹 Recon 관점에서 평가합니다. 높을수록 공략 가치가 높은 프로그램입니다.

```
Total = Bounty×0.20 + WebScope×0.30 + Health×0.20 + Response×0.10 + Difficulty×0.20
```

| 축 | 가중치 | 기준 | 의미 |
|---|---|---|---|
| **Bounty** | 0.20 | offers_bounties +50, fast_payments +30, open_scope +20 | 돈 잘 주는 프로그램 |
| **Web Scope** | 0.30 | web eligible×8(max40), WILDCARD +25, critical +15, no-instruction +10, multi-domain +10 | 웹 공격 표면 넓이 |
| **Health** | 0.20 | open +50, bounties +20, open_scope +20, fast_payments +10 | 프로그램 활성도 |
| **Response** | 0.10 | fast_payments → 80, else → 30 | 응답 속도 |
| **Difficulty** | 0.20 | wildcard-only +25, no-instruction +20, scope≥10 +20, open_scope +15, !fast_payments +20 | 보안 미성숙도 (높을수록 쉬움) |

> web scope가 0인 프로그램은 자동 제외됩니다.

## 설치

### 원커맨드 설치 (Linux amd64)

```bash
git clone <repo-url>
cd Auto-Recon
./setup.sh
```

Rust, Go, BBOT, gau, waybackurls, httpx, nuclei, linkfinder 전부 설치하고 `h1scout` 빌드까지 자동으로 수행합니다.
이미 설치된 도구는 스킵합니다.

### 시스템 PATH에 설치 (권장)

빌드 후 한 번만 실행하면 어디서든 `h1scout` 명령으로 호출 가능:

```bash
cd Auto-Recon
cargo install --path .   # ~/.cargo/bin/h1scout 에 설치
```

이후 `./target/release/h1scout` 대신 그냥 `h1scout`로 호출.

### 요구 사항

- Linux amd64 (Ubuntu/Debian/Kali)
- git, python3, pip, curl, wget
- HackerOne API 키 (fetch 단계)
- claude CLI (LLM AP 식별 단계)

### 수동 설치

<details>
<summary>setup.sh 없이 직접 설치하는 경우</summary>

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Go
wget -q "https://go.dev/dl/go1.23.6.linux-amd64.tar.gz" -O /tmp/go.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

# Go 도구
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python 도구
pip install pipx --break-system-packages
pipx install bbot

# linkfinder (GitHub에서 직접)
git clone https://github.com/dark-warlord14/LinkFinder.git ~/.local/share/linkfinder
cd ~/.local/share/linkfinder && python3 -m venv venv && venv/bin/pip install -r requirements.txt
# ~/.local/bin/linkfinder 래퍼 스크립트 생성 필요

# nuclei 템플릿 다운로드 (첫 실행 전 필수)
nuclei -update-templates

# 빌드
cd Auto-Recon
cargo build --release
```
</details>

## 사용법

### 빠른 시작 (2단계)

```bash
export H1_USERNAME="..." H1_API_TOKEN="..."
h1scout list --top 10           # cache 비어있으면 자동 fetch
h1scout select --skip-nuclei    # TUI 선택 → recon → 자동 review
```

### 1. 환경 변수 설정

```bash
# 필수
export H1_USERNAME="your_h1_username"
export H1_API_TOKEN="your_h1_api_token"
export PATH="$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH"
```

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `H1_USERNAME` | (필수) | HackerOne API 사용자명 |
| `H1_API_TOKEN` | (필수) | HackerOne API 토큰 |
| `SKIP_NUCLEI` | unset | (legacy, `--skip-nuclei` 권장) |
| `AP_SKILL` | `boundary` | (legacy, `--skill` 권장) |

### 2. BBP 데이터 수집

```bash
h1scout fetch              # H1 API에서 프로그램 + scope 수집
h1scout fetch --force      # 캐시 무시하고 재수집
h1scout fetch --dry-run    # 실제 수집 없이 확인만
```

> `list`, `select` 명령어는 cache가 비어있으면 자동으로 fetch를 수행합니다.
> 590개 프로그램의 scope를 동시 5개씩 수집, rate limit 실패 시 10초 대기 후 자동 재시도 (최대 5라운드).

### 3. 스코어 순 목록 확인

```bash
h1scout list --top 10                   # 상위 10개
h1scout list --top 20 --min-scopes 3    # web scope 3개 이상만
h1scout list --format json              # JSON 출력
h1scout list --format csv               # CSV 출력

# 파일로 저장
h1scout export --format json --output results.json
h1scout export --format csv --output results.csv
```

### 4. BBP 선택 → Recon 실행 → 자동 Review

```bash
h1scout select                       # 기본: boundary SKILL + nuclei + 자동 review
h1scout select --skip-nuclei         # nuclei 스킵 (WAF 차단 시 권장)
h1scout select --skill vuln          # legacy vuln SKILL 사용
h1scout select --no-review           # 자동 review TUI 비활성
```

1. 스코어 순으로 BBP 목록 표시 (web scope 없는 프로그램은 제외)
2. `↑↓` 이동, `Space` 선택, `Enter` 확정
3. 선택된 BBP마다 5단계 Recon 파이프라인 자동 실행
4. 완료 시 자동으로 review TUI 진입 (`--no-review`로 끌 수 있음)

> BBOT은 도메인당 3~10분, nuclei는 호스트 수에 따라 5~20분 소요됩니다.
> WAF(Imperva, Cloudflare 등) 뒤에 있으면 nuclei가 대부분 차단되므로 `--skip-nuclei` 권장.

### 5. recon 재실행 (실패 시 / SKILL 비교)

```bash
h1scout recon --project-id varonis_20260409              # 전체 recon 재실행
h1scout recon --project-id varonis_20260409 --only-ap    # LLM AP 식별만 재실행
h1scout recon --project-id varonis_20260409 --only-ap --skill vuln  # 다른 SKILL 비교
```

`--only-ap`는 BBOT/httpx/gau/nuclei 단계 건너뛰고 기존 recon 데이터로 LLM만 다시 호출합니다. SKILL 비교 실험에 유용.

### 6. 프로젝트 목록 조회

```bash
h1scout projects             # 완료된 프로젝트 전체
h1scout projects --latest    # 가장 최근 1개
```

### 7. 결과 리뷰 → Auto-Solve 입력 생성

`select`에서 자동 진입하지만 따로 호출도 가능:

```bash
h1scout review                                # TUI에서 프로젝트 선택
h1scout review --project-id varonis_20260409  # 특정 프로젝트 지정
```

1. RR.json의 Attack Point 목록을 TUI로 표시
2. `Space`로 AP 선택, `Enter`로 확정
3. Auto-Solve 입력 JSON이 stdout으로 출력

## 프로젝트 구조

```
~/.h1scout/
├── h1scout.db              ← SQLite 캐시 (프로그램 + scope)
├── config.toml             ← 가중치 설정 (선택사항)
└── projects/
    └── {handle}_{YYYYMMDD}/
        ├── program_info.json   ← BBP 정보 (handle, name, score)
        ├── rule.csv            ← 필터링된 웹 scope
        ├── recon/
        │   ├── subdomains.txt      ← BBOT 서브도메인
        │   ├── live_hosts.txt      ← httpx 라이브 호스트 + 기술스택
        │   ├── urls.txt            ← gau + waybackurls URL
        │   ├── js_files.txt        ← JS 파일 목록
        │   ├── js_endpoints.txt    ← linkfinder 추출 엔드포인트
        │   └── nuclei.txt          ← nuclei 스캔 결과
        └── RR.json             ← 최종 Recon Result (Auto-Solve 입력)
```

## AP 식별 SKILL

LLM이 recon 데이터를 분석할 때 사용하는 프롬프트 SKILL이 두 종류 있습니다.

### Boundary SKILL (default)

**8개 보안 경계(Boundary)** 관점으로 분류. "어떤 경계가 깨지는가"가 분류 축.

| Boundary | 핵심 | 카테고리 예시 |
|---|---|---|
| **Asset** | 운영 범위 안/밖 | `asset.takeover`, `asset.staging_exposed`, `asset.legacy_service` |
| **Entry Point** | 노출된/숨겨진 기능 | `entry.hidden_route`, `entry.graphql_exposure`, `entry.info_disclosure` |
| **Identity** | 인증된/안 된 사용자 | `identity.auth_bypass`, `identity.session_introspection`, `identity.account_takeover` |
| **Authorization** | 허용된/금지된 행위 | `authz.idor`, `authz.privilege_escalation`, `authz.tenant_bypass`, `authz.function_level` |
| **Data** | 변경 가능/불가능 상태 | `data.injection`, `data.mass_assignment`, `data.ssrf`, `data.kv_arbitrary_write` |
| **Trust** | 내부/외부 시스템 신뢰 | `trust.oauth_misconfig`, `trust.webhook_forgery`, `trust.ssrf_via_integration` |
| **Flow** | 정상/비정상 순서 | `flow.step_skip`, `flow.precondition_bypass`, `flow.race_condition` |
| **File** | 안전한/위험한 파일 처리 | `file.upload_rce`, `file.path_traversal`, `file.export_idor` |

각 boundary마다 **Recon 단서**(찾을 것)와 **Solve 검증 항목**(테스트할 것)이 분리되어 있어, LLM이 후속 Auto-Solve 단계를 위한 가이드를 함께 생성합니다.

### Vuln SKILL (legacy)

**8개 취약점 유형**으로 분류. `IDOR`, `auth_bypass`, `exposure`, `secret`, `injection`, `takeover`, `oauth_misconfig`, `jwt_attack`.

`AP_SKILL=vuln` 환경변수로 사용 가능. Boundary SKILL 대비 분류 다양성이 낮고 Asset/Trust/Flow/File 영역 누락이 있습니다.

### 비교 (Varonis BBP 기준)

| 지표 | Vuln SKILL | Boundary SKILL |
|---|---|---|
| AP 개수 | 45 | **65 (+44%)** |
| 카테고리 종류 | 6 | **29** |
| Asset 영역 | ❌ | ✅ |
| Trust 영역 | 부분 | ✅ |
| Flow 영역 | ❌ | ✅ |
| File 영역 | 부분 | ✅ |
| Solve 검증 가이드 | ❌ | ✅ |

## RR.json 스키마

```json
{
  "project_id": "varonis_20260409",
  "bbp": { "platform": "hackerone", "handle": "...", "name": "...", "score": 85.2 },
  "scope": { "identifier": "*.varonis.com", "asset_type": "WILDCARD", ... },
  "target": { "subdomain": "...", "ip": "...", "tech_stack": [...], "status_code": 200 },
  "attack_points": [
    {
      "ap_id": "ap_001",
      "url": "https://app.varonis.io/graphql",
      "method": "POST",
      "category": "exposure",
      "priority": 1,
      "evidence": {
        "source": "linkfinder",
        "raw": "/graphql",
        "llm_reasoning": "GraphQL endpoint exposed..."
      }
    }
  ],
  "created_at": "2026-04-09T12:11:30+09:00"
}
```

## 가중치 커스터마이징

`~/.h1scout/config.toml` 파일을 생성하면 스코어링 가중치를 변경할 수 있습니다:

```toml
[weights]
bounty_scale = 0.20
web_scope = 0.30
program_health = 0.20
response_speed = 0.10
difficulty = 0.20
```

## 트러블슈팅

| 증상 | 원인 | 해결 |
|---|---|---|
| `command not found: bbot` | PATH 미설정 | `export PATH="$HOME/.local/bin:$PATH"` |
| `command not found: gau` | PATH 미설정 | `export PATH="$HOME/go/bin:$PATH"` |
| `Rate limited after 5 retries` | H1 API rate limit | 자동 재시도됨, 기다리면 됨 |
| nuclei 첫 실행 느림 | 템플릿 다운로드 | `nuclei -update-templates` 미리 실행 |
| nuclei 무한 실행 / 0 matched | WAF가 nuclei 차단 | `SKIP_NUCLEI=1` 환경변수로 스킵 |
| BBOT sudo 비밀번호 요구 | 모듈 의존성 설치 | `sudo sh -c 'echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/nopasswd'` |
| linkfinder `No module named` | 잘못된 호출 방식 | `setup.sh`로 재설치 (래퍼 스크립트 생성) |
| `live hosts 0` | httpx가 PATH에 없음 | `setup.sh` 재실행 또는 PATH 확인 |

## 전체 파이프라인 흐름

```
  사용자                    h1scout                         외부 도구
    │                         │                                │
    │  h1scout fetch          │                                │
    │────────────────────────>│  H1 API 호출 (동시5개)         │
    │                         │  590개 프로그램 + scope 수집    │
    │                         │  SQLite 캐시 저장              │
    │                         │                                │
    │  h1scout list --top 10  │                                │
    │────────────────────────>│  5축 스코어링 계산              │
    │  <테이블 출력>           │  web scope 0 제외             │
    │                         │                                │
    │  h1scout select         │                                │
    │────────────────────────>│  TUI 체크박스 표시              │
    │  [Space] 선택           │                                │
    │  [Enter] 확정           │                                │
    │                         │──[1/5] BBOT──────────────────>│ 서브도메인 수집
    │                         │<────────── subdomains.txt ────│
    │                         │──[2/5] httpx─────────────────>│ 라이브 호스트
    │                         │<────────── live_hosts.txt ────│
    │                         │──[3/5] gau + linkfinder──────>│ URL + JS 분석
    │                         │<────────── urls.txt + js ─────│
    │                         │──[4/5] nuclei────────────────>│ 취약점 스캔
    │                         │<────────── nuclei.txt ────────│
    │                         │──[5/5] claude --print────────>│ LLM AP 식별
    │                         │<────────── attack_points[] ───│
    │                         │  RR.json 생성                  │
    │                         │                                │
    │  h1scout review         │                                │
    │────────────────────────>│  RR.json 로드                  │
    │  [Space] AP 선택        │  TUI 체크박스 표시              │
    │  [Enter] 확정           │                                │
    │  <Auto-Solve JSON 출력> │                                │
    │                         │                                │
    ▼                         ▼                                ▼
              Auto-Solve에 전달하여 취약점 검증 시작
```
