---
name: ap-identifier-boundary
description: 수집된 정찰 데이터를 8개 보안 경계(Boundary) 관점으로 분석하여 경계가 깨질 수 있는 Attack Point를 식별한다. 취약점 이름이 아니라 "어디에 경계가 있는지"를 기준으로 분류한다.
---

# AP 식별 — Boundary 분석

## 역할
수집된 정찰 데이터를 8개 보안 경계(Boundary) 관점으로 분석하여
각 경계가 깨질 수 있는 Attack Point를 식별하고 RR의 attack_points 배열로 출력한다.

## 분석 원칙
- **경계 중심**: 취약점 이름(IDOR, XSS)이 아니라 "어떤 보안 경계가 깨지는가"를 본다
- **기능 의미 우선**: 경로 이름(`/admin`)보다 "권한이 달라지는 기능"이 더 중요한 단서다
- **겹침 허용**: 하나의 AP가 여러 boundary에 걸칠 수 있다 (예: search는 Entry Point + Data 동시)
- **Passive 추론만**: 실제 요청 전송 금지
- **Recon/Solve 분리**: Recon에서 찾은 단서와 Solve에서 검증할 것을 명확히 구분한다
- **포함 우선**: 한 번이라도 본 적 없는 패턴이라도 boundary 단서에 해당하면 무조건 포함한다
- **OAuth/SSO/IdP 우선**: 인증/인가 관련 엔드포인트는 절대 누락하지 않는다 (priority 1~2)
- **검색/쿼리 우선**: search, query, filter, lookup, widget 입력 엔드포인트는 절대 누락하지 않는다

---

## Boundary 1: Asset (운영 범위 안/밖)

핵심: 이 호스트가 실제 운영 범위인가? 잊힌/방치된 자산인가?

### Recon 단서
- **live_hosts**: staging, dev, test, beta, internal, corp, legacy 키워드 포함 호스트
- **live_hosts**: 메인 서비스와 기술스택이 다른 호스트 (nginx vs apache, React vs jQuery)
- **live_hosts**: 응답 403/404인데 살아있는 호스트
- **live_hosts**: CNAME이 외부 서비스(S3, Heroku, GitHub Pages, Shopify)를 가리키는데 "no such bucket" 류 응답
- **urls**: 과거 URL에만 나오고 현재 live_hosts에 없는 도메인 (abandoned)
- **nuclei**: subdomain-takeover 패턴 매칭

### 이어지는 취약점
- `asset.takeover` — dangling CNAME, unclaimed 서비스
- `asset.staging_exposed` — 인증 없는 staging/dev 환경
- `asset.legacy_service` — 패치 안 된 오래된 서비스
- `asset.cloud_exposure` — public S3 bucket, Azure blob

### Solve에서 검증할 것
- takeover 실제 가능 여부 (DNS 레코드 확인)
- staging 환경에 프로덕션 데이터가 있는지
- legacy 서비스의 실제 취약점 존재 여부

---

## Boundary 2: Entry Point (노출된/숨겨진 기능)

핵심: 문서화되지 않았지만 실제로 호출 가능한 기능이 있는가?

### Recon 단서
- **js_endpoints**: `/admin`, `/internal`, `/debug`, `/graphql`, `/api/v2` 등 숨겨진 경로
- **js_endpoints**: JS에서만 발견되고 공개 UI에 없는 엔드포인트
- **js_endpoints**: source map, webpack chunk에서 노출된 내부 경로
- **js_endpoints**: 검색/쿼리 — `/search`, `/query`, `/find`, `/lookup`, `/api/search`, `/v2/search`
- **js_endpoints**: 위젯/대시보드 — `/widget`, `/widgetdata`, `/Widgets/data`, `/dashboard/data`, `/panel`
- **js_endpoints**: bulk/batch — `/bulk`, `/batch`, `/import`, `/mass`
- **js_endpoints**: 정보/상태 — `/state.json`, `/health`, `/health/status`, `/license`, `/license-information`, `/info`, `/version`, `/system-version.json`, `/configuration`, `/page-config`
- **urls**: `/swagger`, `/api-docs`, `/openapi.json`, `/graphiql`
- **urls**: deprecated API 패턴 (`/api/v1` 존재 시 `/api/v0`, `/api/old` 추론)
- **live_hosts**: GraphQL introspection 가능한 호스트
- **nuclei**: swagger-api, graphql-playground, actuator 탐지

### 이어지는 취약점
- `entry.hidden_route` — UI에 없지만 API는 살아있는 기능
- `entry.graphql_exposure` — introspection 활성화, schema 노출
- `entry.api_docs` — swagger/openapi 무인증 접근
- `entry.deprecated_api` — 이전 버전 API에 검증 부재
- `entry.debug_endpoint` — actuator, health, metrics, pprof 노출
- `entry.info_disclosure` — state.json, license, version, configuration 노출

### Solve에서 검증할 것
- hidden route가 실제로 응답하는지
- GraphQL introspection으로 민감한 mutation 발견되는지
- deprecated API와 현재 API의 권한 검증 차이
- 정보 노출이 다음 공격의 입력이 되는지 (체인 가치)

---

## Boundary 3: Identity (인증된/인증 안 된 사용자)

핵심: 사용자의 신원을 확정하고 유지하는 흐름에서 약한 곳은 어디인가?

**중요: 이 boundary의 모든 엔드포인트는 무조건 priority 1~3으로 포함한다. 누락 금지.**

### Recon 단서
- **js_endpoints**: 기본 인증 — `/login`, `/signup`, `/logout`, `/reset-password`, `/verify-email`, `/change-email`, `/change-password`
- **js_endpoints**: MFA — `/mfa/setup`, `/mfa/verify`, `/backup-codes`, `/recovery`, `/2fa`
- **js_endpoints**: **OAuth 전체** — `/oauth/authorize`, `/oauth/callback`, `/oauth/token`, `/oauth/revoke`, `/v1/authorize`, `/v1/token`, `/v1/revoke`, `/v1/userinfo`
- **js_endpoints**: **OIDC discovery** — `/.well-known/openid-configuration`, `/.well-known/jwks.json`
- **js_endpoints**: **세션 introspection** — `/sessions/me`, `/api/sessions`, `/api/v1/sessions`, `/me`, `/whoami`, `/userinfo`, `/profile/me`
- **js_endpoints**: **IdP 통합 경로** — `/idp/`, `/idp/idx/`, `/idp/idx/introspect`, `/idp/myaccount/`, `/saml/`, `/sso/`, `/auth/saml/acs`
- **js_endpoints**: **JIT/provisioning** — `/jitnewuser`, `/scim/`, `/scim/v2/`, `/provision`, `/usermanagement/jit`
- **js_endpoints**: token 관리 — `/api/v1/authn`, `/token/refresh`, `/api-key/rotate`
- **js_endpoints**: 이메일/비번 변경 (ATO 체인) — `/idp/myaccount/emails`, `/idp/myaccount/password`, `/account/email`
- **urls**: password reset URL 패턴 (토큰 길이, 만료 시간 힌트)
- **live_hosts**: Okta, Auth0, Cognito, Azure AD, Google Workspace 등 IdP 사용 흔적

### 이어지는 취약점
- `identity.auth_bypass` — 인증 없이 보호된 리소스 접근
- `identity.session_fixation` — 로그인 전후 세션 ID 미변경
- `identity.session_introspection` — `/sessions/me` 류로 세션 정보 노출
- `identity.reset_flow_abuse` — 재설정 토큰 재사용, 예측 가능
- `identity.mfa_bypass` — 특정 흐름에서 MFA 미적용
- `identity.account_takeover` — 이메일 변경 → 비밀번호 재설정 체인
- `identity.jit_abuse` — JIT 사용자 생성 무인증
- `identity.idp_introspect` — IdP introspection으로 인증 상태 조작

### Solve에서 검증할 것
- 로그인 전후 세션 토큰이 회전되는지
- reset 토큰이 일회성인지
- MFA가 모든 인증 흐름에 적용되는지
- 재인증 없이 이메일/비밀번호 변경 가능한지
- OAuth `state` 검증 여부, redirect_uri 조작
- 세션 introspection 응답에 민감 정보 포함 여부

---

## Boundary 4: Authorization (허용된/금지된 행위)

핵심: 어떤 actor가 어떤 resource에 어떤 action을 할 수 있는가? 경계가 서버에서 강제되는가?

### Recon 단서
- **js_endpoints**: `/{resource}/{id}` 패턴 — 숫자, UUID, slug 기반 객체 참조
- **js_endpoints**: `/users/{userId}`, `/orgs/{orgId}`, `/teams/{teamId}`
- **js_endpoints**: `/usermanagement/{sidId}/roles/{roleId}` — role 변경 경로
- **js_endpoints**: admin 전용으로 보이는 경로 (`/admin/`, `/manage/`, `/settings/`)
- **js_endpoints**: DELETE, PUT 메서드를 쓰는 상태 변경 엔드포인트
- **urls**: tenant 식별자가 URL에 노출 (`/orgs/123`, `?tenant_id=`)

### 이어지는 취약점
- `authz.idor` — ID 변경으로 타 사용자 리소스 접근 (수평)
- `authz.privilege_escalation` — 낮은 role로 높은 role 기능 접근 (수직)
- `authz.tenant_bypass` — 다른 tenant의 데이터 접근
- `authz.function_level` — UI에서 숨겨진 admin 기능이 API에서 호출 가능
- `authz.field_level` — 응답에 role에 따라 필터링해야 할 필드가 그대로 노출

### Solve에서 검증할 것
- 다른 계정 ID로 바꿔서 요청했을 때 응답 차이
- 낮은 role 계정으로 admin 엔드포인트 호출
- 다른 tenant ID로 교차 접근
- 읽기/쓰기 권한이 별도로 검증되는지

---

## Boundary 5: Data (변경 가능/불가능한 상태)

핵심: 어떤 입력이 서버 상태, 권한, 금액, 대상 자원을 바꾸는가?

**중요: 검색/쿼리 엔드포인트는 무조건 포함한다. Entry Point boundary와 겹쳐도 둘 다에 분류한다.**

### Recon 단서
- **urls**: 파라미터 이름에 `role`, `isAdmin`, `permissions`, `status`, `amount`, `price` 포함
- **urls**: `redirect`, `returnUrl`, `callback`, `next` 파라미터 (open redirect 후보)
- **urls**: `?q=`, `?search=`, `?filter=`, `?query=` 검색 파라미터 (injection 후보)
- **js_endpoints**: POST/PUT/PATCH 엔드포인트 — 상태 변경 기능 (mass assignment 후보)
- **js_endpoints**: 검색/쿼리 — `/search`, `/api/search`, `/v2/search`, `/filter`, `/query`, `/find`, `/lookup`
- **js_endpoints**: 위젯 데이터 — `/WidgetData`, `/WidgetData/preview`, `/Widgets/data`, `/Widgets/datasource`
- **js_endpoints**: KV/임의 저장 — `/kv/SetValueByKey`, `/setting/save`, `/store`
- **js_endpoints**: 파라미터에 `filename`, `path`, `url`, `dest` — SSRF/LFI 후보
- **js_endpoints**: 파이프라인/proxy — `/DataMediatorPipeline/{url}`, `/proxy`, `/fetch`
- **nuclei**: open-redirect, ssrf, sql-injection 패턴

### 이어지는 취약점
- `data.mass_assignment` — 서버가 의도하지 않은 필드까지 반영
- `data.injection` — SQL, NoSQL, LDAP, template injection (검색/필터에 우선 적용)
- `data.ssrf` — 서버가 사용자 입력 URL을 요청
- `data.open_redirect` — redirect 파라미터 검증 부재
- `data.parameter_pollution` — 중복 파라미터로 로직 혼란
- `data.kv_arbitrary_write` — KV 저장 엔드포인트로 임의 값 저장

### Solve에서 검증할 것
- 요청에 필드 추가해서 mass assignment 테스트
- 검색/필터에 injection payload (SQL, NoSQL, GraphQL)
- 위젯 datasource에 임의 URL/쿼리 주입
- URL 파라미터에 내부 IP (SSRF)
- redirect 파라미터에 외부 도메인

---

## Boundary 6: Trust (내부/외부 시스템 신뢰)

핵심: 어떤 외부 시스템을 신뢰하고 어떤 데이터를 검증 없이 받아들이는가?

### Recon 단서
- **js_endpoints**: `/oauth/authorize`, `/oauth/callback`, `redirect_uri` 파라미터
- **js_endpoints**: `/webhook`, `/callback`, `/notify` 엔드포인트
- **js_endpoints**: `/saml/acs`, `/sso/`, SCIM provisioning 경로
- **js_endpoints**: 외부 서비스 연동 (`/integrations/slack`, `/connect/github`)
- **live_hosts**: Okta, Azure AD, Google Workspace 연동 흔적
- **urls**: `state`, `nonce`, `code` 파라미터 포함 OAuth URL

### 이어지는 취약점
- `trust.oauth_misconfig` — redirect_uri 조작, state 검증 부재
- `trust.webhook_forgery` — 서명 없는 webhook, replay 가능
- `trust.ssrf_via_integration` — 외부 연동에서 URL을 서버가 요청
- `trust.account_linking_abuse` — 느슨한 이메일 기반 계정 연결
- `trust.tenant_confusion` — 외부 IdP 응답으로 잘못된 tenant 매핑

### Solve에서 검증할 것
- redirect_uri에 subdomain/path 조작
- webhook에 서명 없이 위조 요청
- OAuth state 파라미터 유무
- 계정 연결 시 이메일만으로 권한 부여되는지

---

## Boundary 7: Flow (정상/비정상 순서)

핵심: 정상 흐름의 어떤 순서와 전제가 실제로 서버에서 강제되는가?

### Recon 단서
- **js_endpoints**: 순서가 있는 엔드포인트 — `/step1`, `/step2`, `/confirm`, `/approve`
- **js_endpoints**: `/payment`, `/refund`, `/cancel`, `/subscribe`, `/upgrade`
- **js_endpoints**: `/coupon/apply`, `/reward/claim`, `/credit/transfer`
- **js_endpoints**: `/invite/accept`, `/approve`, `/publish`, `/activate`
- **urls**: 주문/결제 관련 URL 패턴

### 이어지는 취약점
- `flow.step_skip` — 중간 단계 건너뛰기
- `flow.race_condition` — 동시 요청으로 이중 처리
- `flow.replay` — 같은 요청 반복으로 이중 보상
- `flow.precondition_bypass` — 전제 조건 우회 (미결제로 서비스 이용)
- `flow.state_confusion` — 비동기 처리와 동기 처리 간 상태 불일치

### Solve에서 검증할 것
- step2를 step1 없이 직접 호출
- 쿠폰/보상을 동시에 여러 번 요청
- 결제 완료 전에 서비스 접근 시도
- 취소 후 재사용 가능한지

---

## Boundary 8: File (안전한/위험한 파일 처리)

핵심: 파일 업로드부터 변환, 미리보기, 다운로드, export까지 전체 생명주기에서 어디가 위험한가?

### Recon 단서
- **js_endpoints**: `/upload`, `/import`, `/attach`, `/media`
- **js_endpoints**: `/download`, `/export`, `/report/generate`
- **js_endpoints**: `/preview`, `/thumbnail`, `/convert`
- **js_endpoints**: presigned URL 패턴 (`/upload/url`, `/s3/sign`)
- **urls**: 파일 확장자 포함 URL (`.pdf`, `.xlsx`, `.csv`, `.zip`)
- **urls**: S3/Azure blob/GCS direct URL 패턴

### 이어지는 취약점
- `file.upload_rce` — 실행 가능 파일 업로드
- `file.path_traversal` — filename으로 경로 조작
- `file.ssrf_via_parser` — SVG/PDF/DOCX 파싱 시 외부 요청
- `file.export_idor` — export 범위 필터 조작으로 타 사용자 데이터 추출
- `file.presigned_url_abuse` — 예측 가능한 presigned URL

### Solve에서 검증할 것
- 다양한 확장자/content-type으로 업로드
- filename에 `../` 포함
- SVG에 외부 리소스 참조 삽입
- export 파라미터 조작으로 범위 확대

---

## 출력 형식

JSON 배열로만 반환. 다른 텍스트 없이:

```json
[
  {
    "ap_id": "ap_001",
    "url": "https://app.example.com/usermanagement/{sidId}/roles/{roleId}",
    "method": "PUT",
    "category": "authz.privilege_escalation",
    "priority": 2,
    "evidence": {
      "source": "linkfinder",
      "raw": "/usermanagement/{sidId}/roles/{roleId}",
      "llm_reasoning": "Role 변경 엔드포인트. sidId와 roleId를 조작하면 다른 사용자의 role을 변경할 수 있다. Solve: 낮은 role 계정으로 admin role 할당 시도."
    }
  }
]
```

## priority 기준
1. **경계 부재**: 인증/권한 없이 보호된 기능 직접 접근 가능
2. **경계 우회**: 경계가 있지만 ID 변경, 파라미터 조작 등으로 우회 가능
3. **정보→공격 연결**: 노출된 정보가 다음 공격의 입력이 됨 (swagger→hidden endpoint→IDOR)
4. **확인 필요 후보**: Recon 단서만으로 판단 불가, Solve에서 검증 필요
