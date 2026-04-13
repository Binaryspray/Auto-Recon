---
name: ap-identifier
description: 수집된 URL, JS 엔드포인트, 기술스택 데이터를 받아서 버그바운티 관점의 Attack Point를 식별하고 우선순위화한다. 해커의 직관을 흉내내어 숨겨진 라우팅 경로를 추론하고 취약점 유형별로 분류한다.
---

# AP 식별 — 해커 관점 분석

## 역할
수집된 정찰 데이터를 분석하여 실제 취약점이 있을 가능성이 높은
Attack Point를 식별하고 RR의 attack_points 배열로 출력한다.

## 분석 원칙
- **Passive 추론만**: 실제 요청 전송 금지
- **컨텍스트 기반**: 단순 패턴 매칭이 아닌 전체 구조 파악
- **포괄적으로**: 가능성 낮아도 포함 (나중에 필터링)

---

## 취약점 유형별 식별 기준

### 카테고리 규칙 (CRITICAL)

**확정 카테고리** — 직접적 증거가 있는 경우에만 사용:
- `IDOR` — URL에 숫자/UUID ID가 있고, 다른 사용자 리소스 접근 가능 정황
- `auth_bypass` — 실제 인증 우회 경로/방법이 발견된 경우 (401→200 전환 등)
- `exposure` — swagger/api-docs/env/config 등 정보 노출이 관찰된 경우
- `secret` — 실제 API 키, 토큰, 크리덴��이 JS/응답에서 발견된 경우
- `injection` — 입력 파라미터가 존재하고 필터링 부재 정황이 있는 경우
- `takeover` — CNAME이 unclaimed 서비스를 가리키는 증거가 있는 경우
- `oauth_misconfig` — redirect_uri 조작 가능, state 미사용 등 구체적 증거
- `jwt_attack` — alg=none 가능, kid 조작 가능 등 구체적 증거

**후보 카테고리 (_candidate)** — 추론만 있고 직접 증거가 없으면 반드시 접미사 `_candidate` 사용:
- `IDOR_candidate` — ID 패턴은 있지만 접근 제어 부재를 확인 못 한 경우
- `auth_bypass_candidate` — admin 패널 URL은 있지만 실제 bypass 미확인
- `injection_candidate` — 입력 파라미터는 있지만 injection 가능 여부 미확인
- `exposure_candidate` — 경로는 추론했지만 실제 노출 미확인
- `routing_inference` — LLM이 경로를 추론만 한 경우 (항상 _candidate 취급)

**절대 하지 말 것**:
- admin 로그인 페이지 노출을 `auth_bypass`로 분류 (→ `exposure` 또는 `auth_bypass_candidate`)
- 파라미터 존재만으로 `injection` 분류 (→ `injection_candidate`)
- CNAME 존재만으로 `takeover` 분류 (→ unclaimed 여부 확인 필요)

---

### 식별 기준 상세

#### IDOR / IDOR_candidate
- URL에 숫자 ID: `/users/123`, `/orders/456`
- UUID 기반: `/items/550e8400-...`
- 사용자 식별자 파라미터: `?user_id=`, `?account=`
- 추론: `/api/v1/users/123` → 타 유저 ID 접근 가능성

#### auth_bypass / auth_bypass_candidate
- 401/403 응답이 특정 조건에서 200으로 전환되는 경우 → `auth_bypass`
- 로그인 패널, admin URL 발견만 된 경우 → `exposure` 또는 `auth_bypass_candidate`
- JS에서 `adminRole`, `isAdmin` 변수 발견 → `auth_bypass_candidate`

#### exposure
- `/swagger`, `/api-docs`, `/graphql`, `/actuator`, `/metrics`
- `/.env`, `/config.json`, `.js.map`

#### secret
- JS 내 API 키 패턴: `apiKey=`, `token=`
- AWS/GCP 키 패턴, 하드코딩 크리덴셜

#### injection / injection_candidate
- 검색/필터 파라미터: `?q=`, `?search=`, `?filter=` → `injection_candidate`
- XML/JSON 입력 받는 API → `injection_candidate`
- 에러 메시지에 SQL 구문 노출 → `injection`

#### takeover
- CNAME이 unclaimed 서비스를 가리킴 + "There is no app configured" 류 응답

#### oauth_misconfig
- `/oauth/authorize`, redirect_uri 파라미터, state 미사용

#### jwt_attack
- eyJ로 시작하는 토큰, alg 헤더 조작 가능성, kid 파라미터

---

## 라우팅 경로 추론

```
발견: /api/v1/users/profile
추론: /api/v1/users/admin
      /api/v2/users/profile
      /api/internal/users/profile

JS에서 발견: const ADMIN_API = '/api/admin'
추론: /api/admin/users, /api/admin/settings, /api/admin/logs
```

추론된 경로�� 반드시 `routing_inference` 또는 `*_candidate` 카테고리 사용.

---

## AP 그룹핑

같은 서비스/API에 속하는 AP는 `group_id`로 묶어야 한다.

그룹핑 기준:
- **같은 base URL** (호스트+베이스 경로): `api.example.com/v1/*` → 같은 그룹
- **같은 외부 서비스**: Algolia 관련 AP 5개 → `group_id: "algolia_api"`
- **같은 인증 컨텍스트**: Firebase Auth 관련 → `group_id: "firebase_auth"`

group_id 형식: `{서비스명}_{기능}` (소문자, snake_case)
예: `algolia_api`, `firebase_auth`, `graphql_api`, `admin_panel`, `user_api`

그룹핑이 불필요한 단독 AP는 `group_id: null`

---

## Priority Rubric (CRITICAL — 반드시 이 기준으로 매길 것)

priority는 **접근가능성(Accessibility)** × **영향도(Impact)**로 결정한다.

### 접근가능성 (A)
| 점수 | 기준 |
|------|------|
| 3 | 인증 없이 접근 가능 (public endpoint) |
| 2 | 인증 필요하지만 일반 사용자 권한으로 접근 가능 |
| 1 | 높은 권한 필�� 또는 접근 조건이 복잡 |

### 영향도 (I)
| 점수 | 기준 |
|------|------|
| 3 | 타 사용자 데이터 접근/수정, 인증 우회, RCE 가능성 |
| 2 | 내부 정보 노출, 설정 유출, API 키 노출 |
| 1 | 경미한 정보 노출, 버전 정보, 경로 노출 |

### Priority 매핑
| A×I 점수 | Priority | 예�� |
|----------|----------|------|
| 7-9 | 1 | 인증 없�� IDOR로 타 유저 데이터 접근 |
| 5-6 | 2 | 일반 유저로 admin API 접근, public API 키 노출 |
| 3-4 | 3 | 인증 필요한 injection 후보, 추론된 admin 경로 |
| 2 | 4 | 높은 권한 필요한 설정 노출 |
| 1 | 5 | 접근 어렵고 영향도 낮은 정보 노출 |

`llm_reasoning`에 반드시 `[A={점수},I={점수}]`을 포함할 것.
예: `"[A=3,I=3] 인증 없이 접근 가능한 user API에 숫자 ID 사용. IDOR로 타 유저 정보 접근 가능."`

---

## 출력 형식

JSON 배열로만 반환. 다른 텍스트 없이:

```json
[
  {
    "ap_id": "ap_001",
    "url": "https://api.example.com/v1/users/123",
    "method": "GET",
    "category": "IDOR",
    "group_id": "user_api",
    "priority": 1,
    "evidence": {
      "source": "gau",
      "raw": "/api/v1/users/123",
      "llm_reasoning": "[A=3,I=3] 인증 없이 접근 가능한 숫자 ID 기반 user 엔드포인트. 타 유저 ID 접근 가능."
    },
    "request_sample": {
      "url": "https://api.example.com/v1/users/123",
      "method": "GET",
      "headers": {"Accept": "application/json"},
      "params": {},
      "response_status": 200,
      "response_snippet": null
    }
  }
]
```

### request_sample 규칙

recon 데이터에서 해당 URL의 정보가 있으면 반드시 채울 것:
- `response_status`: httpx live_hosts에 status code가 있으면 사용
- `headers`: 일반적인 요��� 헤더 추론 (Accept, Content-Type 등)
- `params`: URL 파라미터에서 추출
- `response_snippet`: nuclei 결과에 관련 출력이 ��으면 발췌

정보가 없는 필드는 `null`로 두되, **request_sample 자체를 null로 두지 말 것**. 최소한 url과 method는 항상 채울 것.
