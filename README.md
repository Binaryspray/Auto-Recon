# Auto-Recon

BBP 정찰 대상 선정 & 공격 표면 탐색

## 설치

### 1. Rust 설치

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### 2. 빌드

```bash
cd /mnt/c/Users/User/Documents/GitHub/Auto-Recon
cargo build --release
```

### 3. Recon 도구 설치 (select 단계에서 필요)

```bash
# Go 도구
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# BBOT
pipx install bbot

# JS 분석
pip install linkfinder --break-system-packages
```

> list까지는 Rust + H1 API 키만 있으면 됩니다.
> select부터 위 도구들이 PATH에 필요합니다.

## 사용법

### 1. 확인

```bash
./target/release/h1scout --help
```

### 2. BBP 수집 (H1 API 키 필요)

```bash
export H1_USERNAME="your_h1_username"
export H1_API_TOKEN="your_h1_api_token"
./target/release/h1scout fetch
```

> API 키 없이 확인만: `./target/release/h1scout fetch --dry-run`

### 3. 스코어 순 목록 확인

```bash
./target/release/h1scout list --top 10
./target/release/h1scout list --top 5 --filter android
./target/release/h1scout list --format json
```

### 4. TUI로 BBP 선택 → Recon 실행 → RR.json 생성

```bash
./target/release/h1scout select
```

Space로 다중 선택, Enter로 확정. 선택된 BBP마다 BBOT → httpx → gau/waybackurls → linkfinder → nuclei → LLM AP 식별 순서로 실행됩니다.

### 5. 결과 리뷰 → Auto-Solve 입력 생성

```bash
./target/release/h1scout review
```

RR.json의 Attack Point를 TUI로 선택하면 Auto-Solve 입력 JSON이 stdout으로 출력됩니다.

## 파이프라인

```
h1scout fetch → h1scout select → [BBOT→httpx→gau→linkfinder→nuclei→LLM] → RR.json → h1scout review → Auto-Solve
```

## 프로젝트 구조

```
~/.h1scout/
  h1scout.db              — SQLite 캐시
  config.toml             — 가중치 설정
  projects/
    {handle}_{YYYYMMDD}/
      program_info.json   — BBP 정보
      rule.csv            — 웹 scope
      recon/
        subdomains.txt
        live_hosts.txt
        urls.txt
        js_endpoints.txt
        nuclei.txt
      RR.json             — 최종 Recon Result
```
