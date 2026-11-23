# 🔐 Vault Enterprise - 보안 0순위 엔터프라이즈 패스워드 관리 솔루션
> **완전 폐쇄망(Air-gapped) 환경 특화 Zero-Dependency 엔터프라이즈 볼트 (Security Hardened v2.0)**

본 솔루션은 외부 인터넷 연결이 완전히 차단된 금융권 및 국가 주요 기반시설, 엔터프라이즈 폐쇄망 인프라를 위해 설계된 패스워드 자산 관리 시스템입니다. 외부 패키지 설치(`pip`, `npm`, 외부 CDN 등)가 일체 불필요하며, Linux OS 기본 내장 Python 3 표준 라이브러리와 Nginx 웹서버만으로 즉시 구동됩니다.

---

## 📁 1. 프로젝트 디렉토리 구조

```text
/opt/vault-enterprise/ (권장 설치 경로)
├── app.py              # [Backend] 보안 강화 단일 파일 API 서버 (스레드 안전, 브루트포스 차단)
├── nginx.conf          # [Nginx] 무손실 금융권 보안 헤더 및 Rate Limiting 리버스 프록시
├── SPEC.md             # [Spec] 시스템 아키텍처 및 REST API 상세 명세서
├── README.md           # [Manual] 설치, 초기화, 운영 매뉴얼
├── create_admin.py     # [CLI] 터미널 초기 관리자 생성/초기화 스크립트
├── static/
│   └── index.html      # [Frontend] 무의존성 단일 파일 SPA (CSS/JS 내장, 마스터 키 검증 탑재)
└── data/
    └── vault.db        # [Database] SQLite3 데이터베이스 파일 (권한 0600 자동 적용)
```

---

## 🛡️ 2. 핵심 보안 아키텍처 (Security Hardened)

### 2.1 저장 데이터 암호화 및 키 격리 (WebCrypto AES-256-GCM)
- **종단간 암호화(E2EE):** 모든 비밀번호 및 민감 메모는 브라우저 내부에서만 평문으로 존재하며 서버는 암호문과 IV만 수신합니다.
- **키 유도 및 추출 차단 (`extractable: false`):** 마스터 비밀번호로부터 유도된 256비트 AES 키와 HMAC 서명 키는 `extractable: false`로 생성되어, XSS 등 악성 스크립트가 실행되더라도 브라우저 메모리 상에서 원본 키 바이트를 추출할 수 없습니다.
- **마스터 키 정합성 검증 토큰 (Canary Verifier):** 초기 관리자 등록 시 마스터 키로 암호화한 검증 토큰(`key_verifier`)을 `system_config` 테이블에 보관합니다. 로그인 및 잠금 해제 시 이 토큰의 복호화 성공 여부를 강제 검증함으로써, **오타로 인한 DB 영구 데이터 오염 및 잠금 우회를 100% 원천 차단**합니다.
- **핑거프린트 분리 및 정보 은닉:** 비밀번호 중복 감지용 HMAC 키는 별도의 도메인 분리 Salt(`vault-enterprise-hmac-salt-v1`)로 파생되며, `GET /api/vault` 응답 시 해시 원문을 노출하지 않고 서버에서 중복 여부 불리언(`is_duplicate`)만 계산하여 반환합니다.

### 2.2 인증 및 세션 보안 (Brute-Force & Timing Attack 차단)
- **계정 해싱:** `PBKDF2-HMAC-SHA256` (100,000회 반복) + 32바이트 랜덤 Salt.
- **상수 시간 비교:** 비밀번호 해시 검증 시 `hmac.compare_digest`를 사용하여 타이밍 공격(Timing Attack)을 방어합니다.
- **이중 Rate Limiting:**
  - 백엔드 인메모리 잠금: IP당 5회 연속 로그인 실패 시 5분(300초)간 차단 (HTTP 429).
  - Nginx 레벨 Rate Limit: `limit_req zone=login_limit:10m rate=5r/m burst=3 nodelay`.
- **5분 비활성 클라이언트 자동 잠금(Auto-Lock):** 5분간 입력이 없으면 메모리 내의 `vaultKey`와 `hmacKey`를 즉시 파기하고 화면을 잠그며, 열려 있는 모달 및 평문 히스토리를 강제 초기화합니다.

### 2.3 보안 클립보드 및 휘발성 메모리 보호
- 비밀번호 평문을 화면에 노출하지 않고도 원클릭으로 클립보드에 복사할 수 있습니다.
- 복사 완료 시 30초 카운트다운 타이머가 동작하며, **30초 경과 즉시 브라우저가 클립보드를 공백으로 덮어써서 메모리 탈취를 차단**합니다.
- 복사 행위는 클라이언트 감사 로그(`SECRET_COPIED`)로 서버에 자동 기록됩니다.

### 2.4 불변 감사 로그 (Immutable Audit Trail) 위변조 방지
- 클라이언트 감사 로그 API(`POST /api/audit/log`)는 허위 로그 주입을 막기 위해 `SECRET_COPIED`, `AUTO_LOCKED` 화이트리스트만 허용합니다.
- 접속 IP는 Nginx가 주입하는 `X-Real-IP`(`$remote_addr`)를 최우선 신뢰하여 `X-Forwarded-For` 헤더 스푸핑을 차단합니다.
- 감사 로그 조회(`GET /api/audit`) 시 관리자는 전체 로그를 조회할 수 있으나, **운영자는 본인의 행위 로그만 조회할 수 있도록 행 수준 격리**가 적용됩니다.

---

## 👥 3. 역할 기반 접근 제어(RBAC) 및 권한 우회 차단

| 기능 / 권한 | 관리자 (ADMIN) | 운영자 (OPERATOR) | 보안 통제 내용 |
|---|:---:|:---:|---|
| 볼트 항목 개별 등록 및 CSV 대량 등록 | ✅ 가능 | ✅ 가능 | 관리자/운영자 공통 등록 권한 |
| 볼트 목록 조회 | ✅ 가능 | ✅ 가능 | 비밀번호 마스킹, 핑거프린트 원문 비노출 |
| 비밀번호 즉시 열람 및 복사 | ✅ 즉시 가능 | ❌ 불가 | 운영자는 열람 요청 승인 필수 |
| 비밀번호 수정 (`PUT /api/vault/{id}`) | ✅ 가능 | ⚠️ 제한적 | **보안 패치: 운영자는 유효한 승인(APPROVED)이 있는 항목만 수정 가능** |
| 비밀번호 변경 히스토리 조회 | ✅ 가능 | ❌ 불가 | **보안 패치: 관리자 전용 API로 격상하여 이력을 통한 우회 열람 완전 차단** |
| 열람 요청 승인 / 반려 (TTL 부여) | ✅ 가능 | ❌ 불가 | 승인 시 5분~240분 유효 시간 부여 |
| 승인된 시간(TTL) 동안 비밀번호 열람/복사 | ✅ 항상 가능 | ✅ 한시적 허용 | TTL 만료 시 즉시 다시 잠김 |
| 사용자 계정 관리 | ✅ 가능 | ❌ 접근 차단 | Admin 전용 |
| 감사 로그 조회 | ✅ 전체 조회 | ⚠️ 본인 로그만 | 운영자는 타 사용자 로그 열람 불가 |

---

## 🚀 4. 폐쇄망 서버 배포 및 구동 가이드

### 4.1 사전 준비 및 최소 권한 서비스 계정 생성
웹 애플리케이션 데몬이 `root` 권한으로 실행되는 위험을 방지하기 위해 전용 보안 계정을 생성합니다:

```bash
# 1. 시스템 전용 서비스 계정 생성 (로그인 불가 쉘)
useradd -r -s /sbin/nologin -d /opt/vault-enterprise vault

# 2. 디렉토리 구성 및 권한 설정
mkdir -p /opt/vault-enterprise/static /opt/vault-enterprise/data
cp app.py create_admin.py /opt/vault-enterprise/
cp index.html /opt/vault-enterprise/static/
chmod +x /opt/vault-enterprise/app.py /opt/vault-enterprise/create_admin.py

# 3. 소유권 부여
chown -R vault:vault /opt/vault-enterprise
chmod 700 /opt/vault-enterprise/data
```

### 4.2 Python 백엔드 서비스 등록 (`/etc/systemd/system/vault-backend.service`)
```ini
[Unit]
Description=Vault Enterprise Hardened Backend Service
After=network.target

[Service]
Type=simple
User=vault
Group=vault
WorkingDirectory=/opt/vault-enterprise
ExecStart=/usr/bin/python3 /opt/vault-enterprise/app.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

서비스 시작 및 활성화:
```bash
systemctl daemon-reload
systemctl enable --now vault-backend.service
systemctl status vault-backend.service
```

### 4.3 Nginx 설정 및 적용 (보안 헤더 무손실)
1. 폐쇄망 자체 서명 인증서(SSL) 생성 (필요 시):
```bash
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/vault.key -out /etc/nginx/ssl/vault.crt \
  -subj "/C=KR/ST=Seoul/O=Enterprise/CN=vault.internal"
```
2. 제공된 `nginx.conf`를 `/etc/nginx/nginx.conf`로 복사하고 적용:
```bash
cp nginx.conf /etc/nginx/nginx.conf
nginx -t && systemctl restart nginx
```

---

## 🔑 5. 초기 관리자 계정 생성

1. 웹 브라우저에서 `https://<서버IP>`로 접속합니다.
2. 미초기화 상태인 경우 **[🔐 Vault Enterprise 초기 설정]** 화면이 열립니다.
3. 다음 항목을 입력합니다:
   - **관리자 계정명 (ID):** (예: `admin`)
   - **관리자 로그인 비밀번호:** (8자 이상)
   - **Vault 마스터 비밀번호:** (데이터 암복호화용 8자 이상 마스터 키)
4. `[초기 설정 완료]`를 누르면 브라우저에서 `key_verifier` 암호문이 자동 생성되어 서버로 전달되고 시스템이 즉시 초기화됩니다.

*(터미널에서 직접 초기화하려는 경우 `python create_admin.py admin Admin1234!` 명령을 실행하셔도 됩니다.)*

---

## 📊 6. 대량 CSV 등록 및 한글 인코딩 지원

- **RFC 4180 준수:** 따옴표 내 쉼표/줄바꿈 완벽 지원.
- **인코딩 자동 감지:** UTF-8 BOM은 물론, **국내 엑셀에서 생성된 EUC-KR / CP949 인코딩을 자동 감지**하여 한글 깨짐 없이 정상 등록됩니다.
- **사전 정합성 검증:** 미리보기 모달에서 오류 행을 붉은색으로 시각화한 후 일괄 암호화 저장합니다.
- **템플릿 다운로드:** 상단의 `[CSV 템플릿 다운로드]` 버튼으로 UTF-8 BOM 템플릿을 받을 수 있습니다.