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

### 필수: Rust 툴체인 (cargo)

h1scout는 Rust로 빌드됩니다. **Rust 1.80 이상**이 필요합니다.

```bash
# rustup으로 설치 (권장)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 버전 확인
rustc --version   # 1.80.0 이상 필요
cargo --version
```

> **주의**: `apt install cargo`로 설치하면 1.75 등 오래된 버전이 설치되어 빌드가 실패합니다. 반드시 [rustup](https://rustup.rs/)을 사용하세요.

### 원커맨드 설치 (Linux amd64)

```bash
git clone <repo-url>
cd Auto-Recon
bash setup.sh
```

Rust, Go, BBOT, gau, waybackurls, httpx, nuclei, linkfinder 전부 설치하고 `h1scout` 빌드까지 자동으로 수행합니다.
이미 설치된 도구는 스킵합니다.

### 요구 사항

- Linux amd64 (Ubuntu/Debian/Kali)
- **Rust 1.80+** (rustup으로 설치)
- git, python3, pip, curl, wget
- HackerOne API 키 (fetch 단계)
- claude CLI (LLM AP 식별 단계)

### 수동 설치

<details>
<summary>setup.sh 없이 직접 설치하는 경우</summary>

```bash
# Rust (1.80 이상 필수)
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

### 1. 환경 변수 설정

```bash
export H1_USERNAME="your_h1_username"
export H1_API_TOKEN="your_h1_api_token"
export PATH="$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH"
```

### 2. BBP 데이터 수집

```bash
./target/release/h1scout fetch          # H1 API에서 프로그램 + scope 수집
./target/release/h1scout fetch --force   # 캐시 무시하고 재수집
./target/release/h1scout fetch --dry-run # 실제 수집 없이 확인만
```

> 590개 프로그램의 scope를 동시 5개씩 수집합니다.
> rate limit 실패 시 10초 대기 후 자동 재시도 (최대 5라운드).

### 3. 스코어 순 목록 확인

```bash
./target/release/h1scout list --top 10              # 상위 10개
./target/release/h1scout list --top 20 --min-scopes 3  # web scope 3개 이상만
./target/release/h1scout list --format json          # JSON 출력
./target/release/h1scout list --format csv           # CSV 출력

# 파일로 저장
./target/release/h1scout export --format json --output results.json
./target/release/h1scout export --format csv --output results.csv
```

### 4. BBP 선택 → Recon 실행

```bash
./target/release/h1scout select
```

1. 스코어 순으로 BBP 목록 표시 (web scope 없는 프로그램은 제외)
2. `↑↓` 이동, `Space` 선택, `Enter` 확정
3. 선택된 BBP마다 5단계 Recon 파이프라인 자동 실행
4. 완료 시 `~/.h1scout/projects/{handle}_{날짜}/RR.json` 생성

> BBOT은 도메인당 3~10분, nuclei는 호스트 수에 따라 5~20분 소요됩니다.

### 5. 결과 리뷰 → Auto-Solve 입력 생성

```bash
./target/release/h1scout review                              # TUI에서 프로젝트 선택
./target/release/h1scout review --project-id varonis_20260409  # 특정 프로젝트 지정
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
