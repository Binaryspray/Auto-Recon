---
name: url-collection
description: 살아있는 호스트에서 URL을 수집하고 JS 파일에서 숨겨진 엔드포인트를 추출한다. gau, waybackurls, katana, linkfinder 사용. AP 식별 전 데이터 수집 단계.
---

# URL 수집 및 JS 분석

## 개요
살아있는 호스트에서 URL을 최대한 수집하고,
JS 파일에서 숨겨진 엔드포인트를 추출한다.

## 입력
- `TARGET`: 루트 도메인 또는 서브도메인
- `OUT`: 출력 디렉토리

## Phase 1 — Historical URL 수집
```bash
# gau: 여러 소스에서 과거 URL 수집
gau $TARGET --subs \
  | tee $OUT/gau_urls.txt

# waybackurls: Wayback Machine
waybackurls $TARGET \
  | tee $OUT/wayback_urls.txt

# 합치기
cat $OUT/gau_urls.txt $OUT/wayback_urls.txt \
  | sort -u > $OUT/historical_urls.txt
```

## Phase 2 — Crawling (Passive)
```bash
# katana: 실제 크롤링 (depth 제한 중요)
katana -u "https://$TARGET" \
  -depth 2 \
  -silent \
  -js-crawl \
  | tee $OUT/katana_urls.txt

# 전체 URL 합치기
cat $OUT/historical_urls.txt $OUT/katana_urls.txt \
  | sort -u > $OUT/all_urls.txt
```

## Phase 3 — JS 파일 추출 및 엔드포인트 분석
```bash
# JS 파일만 추출
grep -iE "\.js(\?|$)" $OUT/all_urls.txt \
  | sort -u > $OUT/js_files.txt

# linkfinder로 숨겨진 엔드포인트 추출
while read -r js_url; do
  python3 /opt/linkfinder/linkfinder.py \
    -i "$js_url" \
    -o cli 2>/dev/null
done < $OUT/js_files.txt \
  | sort -u > $OUT/js_endpoints.txt
```

## Phase 4 — 패턴 기반 1차 분류
```bash
# IDOR 후보: 숫자 ID 포함 경로
grep -iE "/[0-9]+(/|$|\?)" $OUT/all_urls.txt \
  > $OUT/idor_candidates.txt

# API 엔드포인트
grep -iE "/api/|/v[0-9]+/" $OUT/all_urls.txt \
  > $OUT/api_endpoints.txt

# 관리자/내부 경로
grep -iE "admin|internal|dashboard|manage|config|debug|swagger|graphql" \
  $OUT/all_urls.txt $OUT/js_endpoints.txt \
  > $OUT/sensitive_paths.txt
```

## 출력 파일
- `all_urls.txt` — 전체 수집 URL
- `js_files.txt` — JS 파일 목록
- `js_endpoints.txt` — JS에서 추출한 엔드포인트
- `idor_candidates.txt` — IDOR 후보
- `api_endpoints.txt` — API 엔드포인트
- `sensitive_paths.txt` — 민감 경로 후보

## LLM 판단으로 넘길 데이터
이 스킬 완료 후 다음을 LLM에 전달:
- `sensitive_paths.txt`
- `js_endpoints.txt`
- `api_endpoints.txt`
- live_hosts.txt의 tech_stack 정보
