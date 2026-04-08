---
name: subdomain-enum
description: 버그바운티 대상 도메인의 서브도메인을 수집하고 살아있는 호스트를 필터링한다. rule.csv에서 추출한 WILDCARD/URL 타겟에 대해 실행. subfinder, amass, httpx, dnsx 사용.
---

# 서브도메인 수집

## 개요
rule.csv에서 추출한 웹 타겟(WILDCARD, URL)에 대해 서브도메인을 수집하고
살아있는 호스트 + 기술스택을 탐지한다.

## 입력
- `TARGET`: 루트 도메인 (예: playtika.com)
- `PROJECT_DIR`: /projects/{project_id}/recon/

## Phase 1 — Passive 서브도메인 수집
```bash
TARGET=TARGET
OUT=$PROJECT_DIR

subfinder -d $TARGET -all -silent \
  | tee $OUT/subfinder.txt

amass enum -passive -d $TARGET \
  | tee $OUT/amass.txt

# crt.sh (인증서 투명성 로그)
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | python3 -c "
import json,sys
data=json.load(sys.stdin)
[print(e['name_value']) for e in data if '*' not in e['name_value']]
" | sort -u | tee $OUT/crtsh.txt

# 전부 합치기
cat $OUT/subfinder.txt $OUT/amass.txt $OUT/crtsh.txt \
  | sort -u > $OUT/subdomains_all.txt
```

## Phase 2 — DNS 검증
```bash
cat $OUT/subdomains_all.txt \
  | dnsx -silent -a -resp \
  | tee $OUT/subdomains_resolved.txt
```

## Phase 3 — 살아있는 호스트 필터링 + 기술스택
```bash
cat $OUT/subdomains_all.txt \
  | httpx -silent -title -status-code -tech-detect \
          -web-server -ip -cname \
  | tee $OUT/live_hosts.txt
```

## Phase 4 — 우선순위 필터 (LLM 판단 전 1차)
```bash
# admin/internal/api 키워드 포함 서브도메인 별도 추출
grep -iE "admin|internal|api|dev|staging|test|dashboard|portal" \
  $OUT/subdomains_all.txt > $OUT/priority_subdomains.txt
```

## 출력 파일
- `subdomains_all.txt` — 전체 서브도메인
- `subdomains_resolved.txt` — DNS 검증된 것
- `live_hosts.txt` — 살아있는 호스트 + 기술스택
- `priority_subdomains.txt` — 고우선순위 후보

## 주의사항
- Passive 수집만: active brute force는 BBP 규칙 위반 가능
- eligible_for_submission=false 타겟은 제외
