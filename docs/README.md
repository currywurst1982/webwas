# 토큰증권(STO) 예제 — WildFly 26 + Hyperledger Fabric (Linux)

본 예제는 토큰증권(Security Token Offering, STO) 발행/유통/배당/규제 기능을
Hyperledger Fabric 체인코드와 WildFly 26 기반 REST API로 구현한 레퍼런스
구성입니다.

```
┌───────────────────────┐    REST/JSON    ┌─────────────────────────┐
│  Web / 모바일 클라이언트   │ ─────────────▶  │  WildFly 26 (sto.war)   │
└───────────────────────┘                  │  - JAX-RS, CDI          │
                                           │  - Fabric Gateway SDK   │
                                           └──────────┬──────────────┘
                                                      │ gRPC (TLS)
                                                      ▼
                                          ┌─────────────────────────┐
                                          │ Hyperledger Fabric 2.5  │
                                          │ peer + orderer + CA     │
                                          │ chaincode: securitytoken│
                                          └─────────────────────────┘
```

## 1. 프로젝트 구조

```
chaincode/securitytoken/      Fabric Java 체인코드 (STO 컨트랙트)
backend/                      WildFly 26용 REST 백엔드 (sto.war)
docs/                         설치/운영 문서
```

## 2. 사전 요구사항 (Linux, Ubuntu 22.04 기준)

- OpenJDK 17 (`sudo apt install openjdk-17-jdk`)
- Maven 3.9+
- Docker / Docker Compose v2
- WildFly 26.1.3.Final
- Hyperledger Fabric 2.5 바이너리 (`peer`, `configtxgen`, `cryptogen`)

```bash
# Fabric 샘플 + 바이너리
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.5 1.5.7
export PATH=$PWD/fabric-samples/bin:$PATH
```

## 3. Fabric 네트워크 기동 (test-network 사용)

```bash
cd fabric-samples/test-network
./network.sh up createChannel -c stochannel -ca
```

## 4. 체인코드 빌드 & 배포

```bash
cd chaincode/securitytoken
mvn -DskipTests package
# fabric-samples/test-network 경로에서:
./network.sh deployCC \
  -c stochannel \
  -ccn securitytoken \
  -ccp /path/to/chaincode/securitytoken \
  -ccl java
```

체인코드의 주요 트랜잭션:

| 함수 | 종류 | 설명 |
| --- | --- | --- |
| `initToken(symbol,name,decimals)` | submit | 발행자 MSP가 토큰 메타 초기화 |
| `registerHolder(id,kyc,country)` | submit | 투자자 등록 (KYC/국적) |
| `updateKyc(id,kyc)` | submit | KYC 상태 변경 |
| `issue(id,amount)` | submit | 신규 발행 |
| `transfer(from,to,amount)` | submit | 양수도 (KYC + 국가규제 + 잠금잔고 검증) |
| `lock/unlock(id,amount)` | submit | 양도제한 (락업) |
| `burn(id,amount)` | submit | 소각 |
| `pause(boolean)` | submit | 전체 거래 정지 |
| `distributeDividend(id,perToken)` | submit | 보유 비율 기반 배당 분배 기록 |
| `getToken / getHolder / listHolders` | evaluate | 조회 |

## 5. WildFly 26 설치 & 기동

```bash
WF=wildfly-26.1.3.Final
curl -LO https://github.com/wildfly/wildfly/releases/download/26.1.3.Final/${WF}.tar.gz
tar -xzf ${WF}.tar.gz -C /opt
sudo ln -s /opt/${WF} /opt/wildfly

/opt/wildfly/bin/standalone.sh -b 0.0.0.0 -bmanagement 0.0.0.0
```

## 6. 백엔드 빌드 & 배포

`backend/src/main/java/com/example/sto/config/FabricConfig.java`는 다음
환경변수로 오버라이드됩니다.

| 환경변수 | 기본값 |
| --- | --- |
| `FABRIC_MSP_ID` | `Org1MSP` |
| `FABRIC_CHANNEL` | `stochannel` |
| `FABRIC_CHAINCODE` | `securitytoken` |
| `FABRIC_PEER_ENDPOINT` | `localhost:7051` |
| `FABRIC_PEER_HOST` | `peer0.org1.example.com` |
| `FABRIC_TLS_CERT` | peer TLS CA 인증서 경로 |
| `FABRIC_USER_CERT` | Admin signcert 경로 |
| `FABRIC_USER_KEY_DIR` | Admin keystore 디렉터리 |

```bash
cd backend
mvn -DskipTests clean package
cp target/sto.war /opt/wildfly/standalone/deployments/
```

배포 직후 `/opt/wildfly/standalone/deployments/sto.war.deployed` 마커가
생성되면 정상.

## 7. 동작 시나리오 (curl)

```bash
BASE=http://localhost:8080/sto/api/token

# 1) 토큰 초기화
curl -XPOST $BASE/init -H 'content-type: application/json' \
  -d '{"symbol":"ABC","name":"ABC Corp Equity","decimals":0}'

# 2) 투자자 등록 (KYC 통과)
curl -XPOST $BASE/holders -H 'content-type: application/json' \
  -d '{"investorId":"INV001","kycVerified":true,"country":"KR"}'
curl -XPOST $BASE/holders -H 'content-type: application/json' \
  -d '{"investorId":"INV002","kycVerified":true,"country":"KR"}'

# 3) 발행
curl -XPOST $BASE/issue -H 'content-type: application/json' \
  -d '{"investorId":"INV001","amount":1000}'

# 4) 양도
curl -XPOST $BASE/transfer -H 'content-type: application/json' \
  -d '{"fromId":"INV001","toId":"INV002","amount":100}'

# 5) 배당 (1주당 50)
curl -XPOST $BASE/dividend -H 'content-type: application/json' \
  -d '{"dividendId":"2026Q1","perTokenAmount":50}'

# 6) 보유자 조회
curl $BASE/holders
```

## 8. 규제·컴플라이언스 포인트

본 예제 체인코드는 자본시장법/전자증권법 환경에서 STO 시스템이 요구하는
다음 항목을 단순화하여 시연합니다.

- **발행자(MSP) 권한 분리** — `requireIssuer()` 로 토큰 메타·KYC·발행·소각·
  락업 함수에 권한 검증.
- **KYC/AML** — `Holder.kycVerified` 미인증자에게는 발행/양도 불가.
- **국가별 양도제한** — `isRestrictedCountry()` 예시 (KP/IR 차단).
- **양도제한(락업)** — `lock/unlock` 으로 가용잔고와 보유잔고 분리.
- **거래정지** — `pause(true)` 시 모든 발행/양도 차단 (소각·락업은 발행자 권한
  하에 수행 가능).
- **배당 기록** — `DividendRecord` 가 분배 시점 보유 비율을 원장에 영구 기록.

운영 환경에서는 추가로
1. 채널 정책에서 발행자 MSP 별도 분리,
2. Endorsement Policy에 감독·신탁기관 MSP 포함,
3. Private Data Collection 으로 KYC 원천정보 격리,
4. WildFly의 `elytron` 보안 도메인으로 OAuth2/MTLS 인증 적용
이 권장됩니다.

## 9. 문제 해결

- `UNAVAILABLE: io exception` — 피어 TLS 인증서 경로/`overrideAuthority` 호스트
  확인.
- `chaincode definition not found` — `network.sh deployCC` 의 채널/체인코드
  이름 일치 여부 확인.
- WildFly 배포 실패 시 `standalone/log/server.log` 확인. Jakarta EE 9.1
  네임스페이스(`jakarta.*`)인지 확인 (WildFly 26).
