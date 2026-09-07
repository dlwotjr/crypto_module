# Demo Trace for Presentation Script

이 문서는 `./build/main`의 메뉴와 `./build/main --all` 실행을 코드 기준으로
추적한 발표 대본 작성용 자료다. 공개 API 선언은 `include/kcmvp.h`, 데모
진입점은 `app/main.c`, 공개 API 구현과 모듈 경계는 `lib/KCMVP_Crypto.c`에
있다.

## 실행 순서와 공통 상태 모델

`main()`은 인자가 없으면 `print_menu()`로 메뉴를 표시하고, 선택 번호를
`run_item()`에 전달한다. `--all`이면 `run_all()`이 메뉴 1부터 10까지,
그다음 12, 마지막으로 11을 실행한다. 종료/제로화 항목 11이 마지막인
이유는 실행 후 모듈이 `EXIT` 상태가 되어 추가 서비스를 실행할 수 없기
때문이다.

`ensure_initialized()`는 데모 프로세스의 `module_initialized` 플래그를
확인하고, 아직 초기화되지 않았다면 `KCMVP_Initialize()`를 한 번 호출한다.
따라서 메뉴 2~12를 먼저 선택해도 해당 메뉴가 필요한 초기화를 수행한다.

### 초기화의 정확한 순서

`KCMVP_Initialize()`의 순서는 다음과 같다.

1. 현재 상태가 `KCMVP_CM_LOAD`인지 확인한다.
2. `reset_module_data()`가 알고리즘 KAT 플래그와 전역 `module_drbg`를
   제로화한다.
3. `module_state_transition(KCMVP_EVENT_BEGIN_SELFTEST)`로
   `LOAD -> PRE_SELFTEST` 전환을 수행한다.
4. `pre_self_test()`가 `integrity_verify()`를 호출한다. 각 보호 파일을
   SHA3-256으로 다시 해시하고 `lib/integrity_manifest.h`의 값과
   `constant_time_equal()`로 비교한다.
5. `entropy_startup_health_test()`가 `entropy_get()`/Linux `getrandom()`으로
   512바이트를 수집한다. 이어 `repetition_count_test()`와
   `adaptive_proportion_test()`를 수행한다. 설정값은 RCT cutoff 5,
   APT window 64바이트, APT cutoff 16이다.
6. `selftest_run_startup()`이 `aria_kat()`, `sha3_kat()`,
   `hmac_sha3_kat()`, `hash_drbg_kat()`, `ecc_p256_kat()`,
   `mlkem768_kat()`를 순서대로 실행하고 성공한 알고리즘 플래그만 설정한다.
7. `hash_drbg_instantiate(&module_drbg, NULL, 0)`가 다시
   `entropy_get()`으로 32바이트 entropy와 16바이트 nonce를 수집하여 실제
   서비스용 SHA3 Hash_DRBG를 초기화한다.
8. 모든 단계가 성공하면
   `module_state_transition(KCMVP_EVENT_SELFTEST_PASSED)`로
   `PRE_SELFTEST -> NORMAL` 전환한다.
9. 어느 단계든 실패하면 `reset_module_data()`로 상태 데이터를 지우고
   `KCMVP_EVENT_FATAL_ERROR`로 `CRITICAL_ERROR`에 진입하여 암호 서비스를
   잠근다.

### 서비스와 조건부 시험의 FSM 전환

- 초기화 전 공개 알고리즘 API: `module_authorize_service()`가 `LOAD`를 보고
  `KCMVP_ERROR_NOT_INITIALIZED`를 반환한다.
- 일반 서비스: `authorize_algorithm()` -> `module_authorize_service()` ->
  `NORMAL -> EXECUTION`; 계산 후 `finish_service()` ->
  `module_complete_service()` -> `EXECUTION -> NORMAL`.
- ECC/ML-KEM 키 생성: 후보 키 생성 후
  `KCMVP_EVENT_BEGIN_COND_SELFTEST`로 `NORMAL -> COND_SELFTEST`; pairwise
  시험 성공 후 `KCMVP_EVENT_COND_SELFTEST_PASSED`로 `NORMAL` 복귀.
- 치명적 실패: `KCMVP_EVENT_FATAL_ERROR`로 `CRITICAL_ERROR`; 이후 공개
  알고리즘 API는 `KCMVP_ERROR_INVALID_STATE`로 차단된다.
- 제로화: `KCMVP_Zeroize()`가 알고리즘 플래그와 DRBG 상태를 지우고
  `CRITICAL_ERROR`로 전환한다.
- 종료: `KCMVP_Shutdown()`이 데이터를 지운 뒤 필요하면 먼저
  `CRITICAL_ERROR`를 거쳐 `KCMVP_EVENT_SHUTDOWN`으로 `EXIT`에 진입한다.

## Menu 1: Module initialization and startup self-tests

### 1. 메뉴 번호와 출력 제목

- 메뉴: `1. Module initialization and startup self-tests`
- 결과: `[PASS] module initialization and startup self-tests`

### 2. 관련 채점 요구사항

Startup self-test, integrity test, entropy test, FSM/state model, 모든
알고리즘의 시작 KAT.

### 3. 정확한 호출 체인

- 사전 초기화 거부:
  `demo_initialize()` -> `KCMVP_SHA3_Hash()` -> `authorize_algorithm()` ->
  `module_authorize_service()` -> `KCMVP_ERROR_NOT_INITIALIZED`.
- 초기화:
  `demo_initialize()` -> `ensure_initialized()` -> `KCMVP_Initialize()` ->
  `reset_module_data()` -> `module_state_transition(BEGIN_SELFTEST)` ->
  `pre_self_test()` -> `integrity_verify()` -> `hash_file()` ->
  `sha3_init/update/final`.
- 그다음 `entropy_startup_health_test()` -> `entropy_get()` -> `getrandom()` ->
  `repetition_count_test()` -> `adaptive_proportion_test()`.
- 그다음 `selftest_run_startup()` -> `aria_kat()` / `sha3_kat()` /
  `hmac_sha3_kat()` / `hash_drbg_kat()` / `ecc_p256_kat()` /
  `mlkem768_kat()`.
- 마지막으로 `hash_drbg_instantiate()` -> `entropy_get()` ->
  `hash_drbg_instantiate_seed()` -> `hash_df()`, 이후
  `module_state_transition(SELFTEST_PASSED)`.
- 파일: `app/main.c`, `include/kcmvp.h`, `lib/KCMVP_Crypto.c`,
  `lib/module_state.c`, `lib/integrity.c`, `lib/integrity_manifest.h`,
  `lib/entropy.c`, `lib/selftest.c`, `lib/hash_drbg.c`, `lib/ecc.c`,
  `lib/mlkem.c`, `lib/aria.c`, `lib/sha3.c`, `lib/KISA_HMAC_SHA3.c`.

### 4. 입력과 시험 벡터

- 사전 호출: ASCII `abc` (`61 62 63`), SHA3-256 출력 버퍼 32바이트.
- 무결성: `tools/generate_integrity_manifest.c`의 `selected_files[]`에 등록된
  25개 보호 파일과 각 SHA3-256 manifest digest.
- 엔트로피: Linux `getrandom()`의 512바이트 시작 표본.
- 시작 KAT: ARIA-128 고정 키/평문/암호문, SHA3-256 `abc`,
  HMAC-SHA3-224 고정 키와 `Hi There`, DRBG 48바이트 seed와 64바이트
  기대 출력, P-256 private 2/3과 알려진 공개키/공유 비밀,
  ML-KEM 고정 key/encapsulation coins와 기대 공유 비밀.

### 5. 확인 조건

초기화 전 SHA3 호출 결과가 정확히 `KCMVP_ERROR_NOT_INITIALIZED(-2)`이고,
그 후 `KCMVP_Initialize()`가 `KCMVP_SUCCESS`를 반환해야 한다.

### 6. PASS의 의미

PASS는 공개 서비스가 초기화 전에 차단되었고, 무결성 -> 엔트로피 건강성 ->
6개 알고리즘 KAT -> 실제 DRBG 초기화의 전체 순서가 모두 성공하여 모듈이
서비스 가능한 상태가 되었음을 뜻한다.

### 7. 실패 검증

메뉴 자체는 실제 고장을 주입하지 않는다. `./build/module_state_test`가
`integrity_force_manifest_failure()`, `selftest_force_failure()`,
`entropy_set_test_provider()`를 테스트 전용 컴파일 매크로로 사용한다.
손상 manifest, RCT 실패, APT 실패, entropy provider 실패, ARIA/DRBG/ECC/
ML-KEM KAT 실패가 `CRITICAL_ERROR`와 서비스 잠금으로 이어지는지 확인한다.

### 8. 권장 한국어 내레이션

“먼저 초기화 전 SHA3 호출이 마이너스 2로 거부되는 것을 확인합니다.
그다음 초기화 과정에서 소스 무결성, 운영체제 엔트로피 건강성, ARIA,
SHA3, HMAC, DRBG, P-256, ML-KEM 시작 KAT를 순서대로 수행하고 실제 DRBG를
초기화합니다. 모든 단계가 성공해야만 NORMAL 상태로 진입하므로 이 PASS는
시험 전 서비스 차단과 안전한 시작 절차가 모두 동작함을 의미합니다.”

## Menu 2: FSM and status query

### 1. 메뉴 번호와 출력 제목

- 메뉴: `2. FSM and status query`
- 결과: `[PASS] FSM is in NORMAL and operational`

### 2. 관련 채점 요구사항

FSM/state model.

### 3. 정확한 호출 체인

`demo_status()` -> `ensure_initialized()` -> `KCMVP_GetStatus()` ->
`module_state_get()`, 그리고 `KCMVP_GetState()` -> `module_state_get()`.
파일은 `app/main.c`, `include/kcmvp.h`, `lib/KCMVP_Crypto.c`,
`lib/module_state.c`다.

### 4. 입력과 시험 벡터

암호 벡터는 없다. `KCMVP_MODULE_STATUS status` 출력 구조체를 사용한다.

### 5. 확인 조건

`KCMVP_GetStatus()` 성공, `KCMVP_GetState() == KCMVP_CM_NORMAL`,
`status.state == NORMAL`, `status.initialized != 0`,
`status.operational != 0`을 모두 확인한다. 현재 enum 값으로 NORMAL은 1002다.

### 6. PASS의 의미

초기화가 단순 성공 코드만 반환한 것이 아니라, 비공개 FSM의 실제 상태와
공개 상태 구조체가 일관되게 서비스 가능 상태를 나타냄을 증명한다.

### 7. 실패 검증

`module_state_test`가 초기화 전 거부, 치명적 오류 후 모든 알고리즘 서비스
거부, zeroize 후 `CRITICAL_ERROR`, shutdown 후 `EXIT`와 non-operational
상태를 확인한다.

### 8. 권장 한국어 내레이션

“공개 상태 조회 API와 내부 FSM 상태가 모두 NORMAL을 가리키고,
initialized와 operational 플래그도 참입니다. 즉 시작 시험을 통과한 뒤에만
정상 서비스 상태가 공개됨을 확인할 수 있습니다.”

## Menu 3: ARIA-128 ECB encryption and decryption

### 1. 메뉴 번호와 출력 제목

- 메뉴: `3. ARIA-128 ECB encryption and decryption`
- 결과: `[PASS] ARIA encrypt/decrypt known-answer test`

### 2. 관련 채점 요구사항

Algorithm normal operation, startup self-test, FSM/state model.

### 3. 정확한 호출 체인

`demo_aria()` -> `KCMVP_ARIA_Crypt()` -> `authorize_algorithm(aria_passed)` ->
`module_authorize_service()` (`NORMAL -> EXECUTION`) -> `ARIA_ECB()` ->
`EncKeySetup()`/`DecKeySetup()`와 `Crypt()` -> `finish_service()` ->
`module_complete_service()` (`EXECUTION -> NORMAL`). 암호화와 복호화 각각 이
경로를 실행한다. 파일은 `app/main.c`, `lib/KCMVP_Crypto.c`,
`lib/module_state.c`, `lib/aria_Mode.c`, `lib/aria.c`, `lib/aria.h`다.

### 4. 입력과 시험 벡터

- 128비트 키: `000102030405060708090a0b0c0d0e0f`
- 평문: `00112233445566778899aabbccddeeff`
- 기대 암호문: `d718fbd6ab644c739da95f3be6451778`
- 모드: ECB, 입력 길이 16바이트, IV 없음.

### 5. 확인 조건

두 공개 API 호출이 성공하고, 계산 암호문이 기대 암호문과 일치하며,
복호화 결과가 원래 평문과 일치해야 한다.

### 6. PASS의 의미

단순 round-trip만이 아니라 독립된 known-answer ciphertext까지 일치하므로
ARIA-128 키 스케줄과 ECB 암호화가 맞고, 역 키 스케줄과 복호화도 원문을
복원함을 함께 확인한다.

### 7. 실패 검증

`module_state_test`가 초기화 전 호출, 잘못된 방향/키 크기/길이/null 인자,
CBC 비블록 길이, 오류 상태 호출을 거부하는지 확인한다. 시작 ARIA KAT의
강제 실패는 초기화를 막는다.

### 8. 권장 한국어 내레이션

“ARIA-128 ECB 알려진 답 시험입니다. 고정 키와 평문을 암호화한 결과가
기대 암호문과 정확히 같고, 다시 복호화하면 원문이 복원됩니다. 따라서
암호화와 복호화의 정상 동작을 독립 기대값과 함께 검증합니다.”

## Menu 4: SHA3-256 hash

### 1. 메뉴 번호와 출력 제목

- 메뉴: `4. SHA3-256 hash`
- 결과: `[PASS] SHA3-256 known-answer test`

### 2. 관련 채점 요구사항

Algorithm normal operation, startup self-test, FSM/state model.

### 3. 정확한 호출 체인

`demo_sha3()` -> `KCMVP_SHA3_Hash()` ->
`authorize_algorithm(sha3_passed)` -> `module_authorize_service()` ->
`sha3_hash()` -> `sha3_init()`/`sha3_update()`/`sha3_final()` ->
`finish_service()` -> `module_complete_service()`. 파일은 `app/main.c`,
`lib/KCMVP_Crypto.c`, `lib/module_state.c`, `lib/sha3.c`, `lib/sha3.h`다.

### 4. 입력과 시험 벡터

입력은 ASCII `abc`, 기대 SHA3-256은
`3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532`다.

### 5. 확인 조건

공개 API가 성공하고 32바이트 digest가 기대값과 byte-for-byte 같아야 한다.

### 6. PASS의 의미

고정 메시지의 공개 known answer와 일치하므로 SHA3 padding, Keccak 처리,
출력 추출이 올바르게 결합되었음을 확인한다.

### 7. 실패 검증

`module_state_test`가 초기화 전/오류 상태 거부, null과 잘못된 출력 길이,
독립 SHA3 context 동작을 확인한다. `./build/sha3_vs`는 SHA3-224/256/384/512
ShortMsg, LongMsg, Monte Carlo 응답 벡터를 공개 API로 검증한다.

### 8. 권장 한국어 내레이션

“문자열 abc의 SHA3-256 결과를 표준 known answer와 비교합니다. 출력된
32바이트가 기대값과 완전히 일치하므로 SHA3 서비스가 정상 동작합니다.”

## Menu 5: HMAC-SHA3-224

### 1. 메뉴 번호와 출력 제목

- 메뉴: `5. HMAC-SHA3-224`
- 결과: `[PASS] HMAC-SHA3 known-answer test`

### 2. 관련 채점 요구사항

Algorithm normal operation, startup self-test, FSM/state model.

### 3. 정확한 호출 체인

`demo_hmac()` -> `KCMVP_HMAC_SHA3()` ->
`authorize_algorithm(hmac_sha3_passed)` -> `module_authorize_service()` ->
`HMAC_SHA3()` -> 내부 `sha3_hash()` 호출 -> `finish_service()` ->
`module_complete_service()`. 파일은 `app/main.c`, `lib/KCMVP_Crypto.c`,
`lib/module_state.c`, `lib/KISA_HMAC_SHA3.c`, `lib/sha3.c`다.

### 4. 입력과 시험 벡터

- 키: `0x0b` 20바이트.
- 메시지: ASCII `Hi There` 8바이트.
- HMAC-SHA3-224 기대값:
  `3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7`.

### 5. 확인 조건

공개 API 성공과 28바이트 MAC의 기대값 일치를 확인한다.

### 6. PASS의 의미

키 정규화, ipad/opad, inner/outer SHA3 계산을 포함한 최종 인증 태그가
독립 기대값과 같으므로 HMAC-SHA3-224 정상 동작을 증명한다.

### 7. 실패 검증

`module_state_test`가 초기화 전/오류 상태 거부를 확인한다.
`./build/sha3_vs`의 `run_hmac_test()`는
`vectors/sha3/sha-3bytetestvectors/HMAC/HMAC_SHA3.rsp`를 읽어 SHA3
변형과 tag 길이에 따른 결과를 비교한다.

### 8. 권장 한국어 내레이션

“고정 키와 Hi There 메시지로 HMAC-SHA3-224를 계산합니다. 결과가 알려진
28바이트 태그와 일치하므로 키 처리와 두 단계 SHA3 기반 MAC 계산이
정상임을 확인합니다.”

## Menu 6: Hash_DRBG generation and reseed

### 1. 메뉴 번호와 출력 제목

- 메뉴: `6. Hash_DRBG generation and reseed`
- 결과: `[PASS] Hash_DRBG generate/reseed/generate`

### 2. 관련 채점 요구사항

Algorithm normal operation, entropy test, startup self-test, FSM/state model.

### 3. 정확한 호출 체인

- 생성: `demo_rng()` -> `KCMVP_RNG_Generate()` ->
  `authorize_algorithm(hash_drbg_passed)` -> `module_authorize_service()` ->
  `hash_drbg_generate()` -> `hashgen()`/`hash_with_prefix()` ->
  `finish_service()`.
- reseed: `KCMVP_RNG_Reseed()` -> `authorize_algorithm()` ->
  `hash_drbg_reseed()` -> `entropy_get()` -> `hash_drbg_instantiate_seed()` ->
  `hash_df()` -> `finish_service()`.
- 파일: `app/main.c`, `lib/KCMVP_Crypto.c`, `lib/module_state.c`,
  `lib/hash_drbg.c`, `lib/hash_drbg.h`, `lib/entropy.c`, `lib/sha3.c`.

### 4. 입력과 시험 벡터

라이브 데모는 32바이트를 생성하고 추가 입력 없이 reseed한 뒤 다시
32바이트를 생성한다. 엔트로피는 Linux `getrandom()`에서 온다. 시작 KAT는
`00..2f`의 48바이트 seed와 고정 64바이트 기대 출력을 사용한다.

### 5. 확인 조건

첫 generate, reseed, 두 번째 generate가 모두 성공하고 두 32바이트 출력이
서로 달라야 한다.

### 6. PASS의 의미

PASS는 이미 시작 KAT로 결정론적 DRBG 계산을 검증한 상태에서, 실제 전역
DRBG가 출력 생성과 새 엔트로피 기반 reseed를 수행하고 상태가 갱신되었음을
보여 준다. 출력 불일치만으로 난수 품질 전체를 증명하는 것은 아니며,
알고리즘 정확성 근거는 시작 KAT와 상태 시험을 함께 봐야 한다.

### 7. 실패 검증

`module_state_test`가 최대 요청 65,536바이트 제한, uninstantiate 후 생성
거부, 강제 DRBG KAT 실패, reseed entropy 실패를 확인한다. reseed entropy
실패 시 `KCMVP_RNG_Reseed()`가 DRBG를 지우고 `CRITICAL_ERROR`로 전환하며
이후 RNG를 차단한다.

### 8. 권장 한국어 내레이션

“초기 KAT로 검증된 SHA3 Hash_DRBG에서 32바이트를 생성하고, 운영체제의
새 엔트로피로 reseed한 뒤 다시 생성합니다. 두 API 경로가 성공하고 상태
갱신 후 출력이 달라져 generate와 reseed 흐름이 정상임을 확인합니다.”

## Menu 7: P-256 ECDH key agreement

### 1. 메뉴 번호와 출력 제목

- 메뉴: `7. P-256 ECDH key agreement`
- 결과: `[PASS] P-256 reciprocal shared secrets match`

### 2. 관련 채점 요구사항

Algorithm normal operation, conditional self-test, startup self-test,
FSM/state model.

### 3. 정확한 호출 체인

- 각 키 생성: `demo_ecdh()` -> `KCMVP_ECC_GenerateKeyPair()` ->
  `KCMVP_RNG_Generate()` -> `hash_drbg_generate()` ->
  `ecc_p256_compute_public_key()` -> micro-ecc `uECC_compute_public_key()` ->
  `module_state_transition(BEGIN_COND_SELFTEST)` ->
  `ecc_p256_pairwise_test()` -> `ecc_p256_shared_secret()` ->
  `uECC_valid_public_key()`/`uECC_shared_secret()` ->
  `module_state_transition(COND_SELFTEST_PASSED)`.
- 공유 비밀: `KCMVP_ECC_ComputeSharedSecret()` -> `authorize_algorithm()` ->
  `ecc_p256_shared_secret()` -> `ecc_p256_validate_public_key()` ->
  `uECC_valid_public_key()` -> `uECC_shared_secret()` -> `finish_service()`.
- 파일: `app/main.c`, `lib/KCMVP_Crypto.c`, `lib/ecc.c`, `lib/hash_drbg.c`,
  `lib/module_state.c`, `third_party/micro-ecc/uECC.c`.

### 4. 입력과 시험 벡터

라이브 데모는 DRBG로 두 개의 32바이트 private key를 만들고 각각 64바이트
`X || Y` public key를 계산한다. 조건부 시험은 고정 peer private key 2와
그 공개키를 사용한다. 시작 KAT는 private 2/3, 두 알려진 공개키와
`b01a172a...3c2291a9` 공유 비밀을 사용한다.

### 5. 확인 조건

두 키 쌍 생성과 양방향 ECDH 호출이 성공하고,
`secret(private_a, public_b) == secret(private_b, public_a)`여야 한다.

### 6. PASS의 의미

각 후보 키가 공개되기 전에 고정 peer와 pairwise consistency 시험을
통과했고, 실제로 독립 생성된 두 참여자가 동일한 32바이트 P-256 ECDH
x-coordinate를 계산했음을 증명한다.

### 7. 실패 검증

`module_state_test`가 all-zero invalid public key 거부와 공유 비밀 제로화,
초기화 전/오류 상태 거부를 확인한다. `ecc_force_conditional_failure(1)`은
키 생성이 `KCMVP_ERROR_CONDITIONAL_TEST`를 반환하고 후보 키를 제로화하며
모듈을 `CRITICAL_ERROR`로 잠그는지 검증한다.

### 8. 권장 한국어 내레이션

“DRBG로 두 P-256 키 쌍을 생성합니다. 각 키는 반환 전에 내부 pairwise
시험을 통과해야 합니다. 이후 서로의 공개키로 계산한 두 공유 비밀이
완전히 같으므로 실제 ECDH 상호 합의가 정상임을 확인합니다.”

## Menu 8: ML-KEM-768 encapsulation and decapsulation

### 1. 메뉴 번호와 출력 제목

- 메뉴: `8. ML-KEM-768 encapsulation and decapsulation`
- 결과: `[PASS] ML-KEM-768 shared secrets match`

### 2. 관련 채점 요구사항

Algorithm normal operation, conditional self-test, startup self-test,
FSM/state model.

### 3. 정확한 호출 체인

- 키 생성: `demo_mlkem()` -> `KCMVP_MLKEM_Keypair()` ->
  `mlkem768_keypair()` -> PQClean
  `PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair()`; PQClean randombytes는
  `lib/mlkem_randombytes.c`를 통해 `kcmvp_internal_randombytes()`와 전역
  Hash_DRBG를 사용한다. 이후 `NORMAL -> COND_SELFTEST` ->
  `mlkem768_pairwise_test()` -> `crypto_kem_enc_derand()`/`crypto_kem_dec()` ->
  `COND_SELFTEST -> NORMAL`.
- 캡슐화: `KCMVP_MLKEM_Encaps()` -> `authorize_algorithm()` ->
  `mlkem768_encaps()` -> `crypto_kem_enc()` -> `finish_service()`.
- 디캡슐화: `KCMVP_MLKEM_Decaps()` -> `authorize_algorithm()` ->
  `mlkem768_decaps()` -> `crypto_kem_dec()` -> `finish_service()`.
- 파일: `app/main.c`, `lib/KCMVP_Crypto.c`, `lib/mlkem.c`,
  `lib/mlkem_randombytes.c`, `lib/hash_drbg.c`, `lib/module_state.c`,
  `third_party/PQClean/common/fips202.c`,
  `third_party/PQClean/crypto_kem/ml-kem-768/clean/*.c`.

### 4. 입력과 시험 벡터

라이브 데모는 1,184바이트 public key, 2,400바이트 secret key,
1,088바이트 ciphertext, 32바이트 shared secret을 사용한다. 조건부 시험은
`20..3f`의 고정 32바이트 coins로 결정론적 encapsulation을 수행한다. 시작
KAT는 `00..3f` key coins, `40..5f` encaps coins와
`9cddd089...3084aea1` 기대 공유 비밀을 사용한다.

### 5. 확인 조건

keypair, encaps, decaps가 모두 성공하고 encapsulation 측과 decapsulation
측의 32바이트 공유 비밀이 일치해야 한다.

### 6. PASS의 의미

시작 KAT의 독립 기대값 검증, 생성 키의 pairwise 시험, 실제 공개 API의
encaps/decaps 상호운용을 모두 통과하므로 ML-KEM-768 정상 키 설정 흐름을
증명한다.

### 7. 실패 검증

`module_state_test`가 잘못된 포인터/길이를 거부하는지 확인한다.
`mlkem_force_conditional_failure(1)`은 후보 공개키/비밀키 제로화,
`KCMVP_ERROR_CONDITIONAL_TEST`, `CRITICAL_ERROR`, 이후 ML-KEM 서비스 잠금을
확인한다. 시작 ML-KEM KAT 강제 실패도 초기화를 차단한다.

### 8. 권장 한국어 내레이션

“ML-KEM-768 키 쌍을 만들고 캡슐화와 디캡슐화를 수행합니다. 키 쌍은 반환
전에 내부 pairwise 시험을 통과하며, 최종적으로 양쪽 32바이트 공유 비밀이
같으므로 양자내성 키 설정 기능이 정상 동작함을 확인합니다.”

## Menu 9: Integrity and startup self-test failure behavior

### 1. 메뉴 번호와 출력 제목

- 메뉴: `9. Integrity and startup self-test failure behavior`
- 결과: `[PASS] fault-injection coverage is available in the test binary`

### 2. 관련 채점 요구사항

Integrity test, entropy test, startup self-test, conditional self-test,
FSM/state model.

### 3. 정확한 호출 체인

메뉴 경로 자체는 `demo_failure_tests()` ->
`fopen("build/module_state_test", "rb")`뿐이다. 생산 공개 API에는 의도적으로
fault-injection hook이 없기 때문이다. 실제 실패 경로는 별도 바이너리
`./build/module_state_test`의 `main()`이 테스트 전용 내부 함수와 공개 API를
호출한다. 파일은 `app/main.c`, `test/module_state_test.c`,
`lib/integrity.c`, `lib/entropy.c`, `lib/selftest.c`, `lib/ecc.c`,
`lib/mlkem.c`, `lib/KCMVP_Crypto.c`, `lib/module_state.c`다.

### 4. 입력과 시험 벡터

- 무결성: `integrity_force_manifest_failure(1)`로 첫 기대 digest 1비트를
  뒤집는다.
- 엔트로피: `repeated_entropy()`는 전부 `0x55`, `biased_entropy()`는 APT
  window 안에서 `0xaa`를 과다 발생, `failing_entropy()`는 오류를 반환한다.
- KAT: `selftest_force_failure()`로 ARIA, DRBG, ECC, ML-KEM 결과를 강제로
  실패시킨다.
- 조건부 시험: `ecc_force_conditional_failure(1)`,
  `mlkem_force_conditional_failure(1)`.
- reseed: `reseed_failing_entropy()`가 초기화 호출은 허용하고 이후 entropy
  요청에서 실패한다.

### 5. 확인 조건

메뉴 9의 PASS 조건은 테스트 바이너리 파일이 존재하는 것뿐이다. 실제 실패
검증 PASS 조건은 각 child process에서 초기화/API 오류 코드, 상태
`CRITICAL_ERROR`, 후보 출력 제로화, 후속 서비스의
`KCMVP_ERROR_INVALID_STATE`가 모두 기대와 일치하는 것이다.

### 6. PASS의 의미

메뉴 9 PASS만으로 실패 처리가 올바름을 증명하지 않는다. 이는 검증
바이너리가 빌드되었다는 뜻이다. 실패 처리의 실질적 증거는
`./build/module_state_test`가 각 항목에 `PASS:`를 출력하고 마지막에
`module state tests: PASS`를 출력하는 것이다.

### 7. 실패 검증

이 항목 자체가 실패 검증 안내다. 별도 바이너리를 사용하는 이유는 production
shared library에 manifest 손상, 가짜 entropy provider, KAT 강제 실패 같은
위험한 테스트 hook을 공개하지 않기 위해서다. Makefile은 테스트 바이너리에만
`KCMVP_*_TESTING` 매크로를 정의한다.

### 8. 권장 한국어 내레이션

“생산용 공개 API에는 고장을 강제로 만드는 인터페이스를 노출하지 않습니다.
따라서 이 메뉴는 별도 테스트 바이너리의 존재를 확인합니다. 실제 검증은
module_state_test에서 손상된 무결성 값, RCT와 APT 실패, KAT 실패,
조건부 시험 실패를 주입하고, 모두 CRITICAL_ERROR와 서비스 잠금으로
이어지는지 확인합니다.”

## Menu 10: Pairwise conditional self-tests

### 1. 메뉴 번호와 출력 제목

- 메뉴: `10. Pairwise conditional self-tests`
- 결과: `[PASS] conditional self-tests passed and returned to NORMAL`

### 2. 관련 채점 요구사항

Conditional self-test, algorithm normal operation, FSM/state model.

### 3. 정확한 호출 체인

`demo_conditional_tests()` -> `KCMVP_ECC_GenerateKeyPair()` ->
`ecc_p256_pairwise_test()` 및 `KCMVP_MLKEM_Keypair()` ->
`mlkem768_pairwise_test()` -> `KCMVP_GetStatus()`.
각 keypair 함수는 `NORMAL -> COND_SELFTEST -> NORMAL` 전환을 수행한다.
파일은 `app/main.c`, `lib/KCMVP_Crypto.c`, `lib/module_state.c`,
`lib/ecc.c`, `lib/mlkem.c`, `lib/hash_drbg.c`와 두 third-party 구현이다.

### 4. 입력과 시험 벡터

ECC 후보 키는 Hash_DRBG로 생성되며 pairwise 시험은 고정 P-256 peer key를
사용한다. ML-KEM 후보 키도 Hash_DRBG 기반 randomness로 생성되고 pairwise
시험은 고정 coins `20..3f`를 사용한다.

### 5. 확인 조건

두 공개 keypair API가 성공하고, 이후 `KCMVP_GetStatus()`의 state가
`KCMVP_CM_NORMAL`, operational이 참이어야 한다.

### 6. PASS의 의미

두 후보 키 쌍이 내부 pairwise consistency 검사를 통과한 후에만 반환되었고,
FSM이 조건부 시험 상태에 머물지 않고 정상 상태로 복귀했음을 증명한다.

### 7. 실패 검증

강제 실패는 메뉴에서 실행하지 않고 `./build/module_state_test`가 수행한다.
ECC/ML-KEM pairwise 실패 시 후보 키를 전부 제로화하고 모듈을
`CRITICAL_ERROR`로 잠그며 후속 서비스를 거부하는지 확인한다.

### 8. 권장 한국어 내레이션

“ECC와 ML-KEM 키 생성 API는 후보 키를 바로 반환하지 않고 먼저 내부
pairwise consistency 시험을 수행합니다. 두 시험이 성공하고 상태가 다시
NORMAL로 돌아왔으므로 검증되지 않은 키가 외부로 나가지 않음을 확인합니다.”

## Menu 11: Zeroize and shutdown

### 1. 메뉴 번호와 출력 제목

- 메뉴: `11. Zeroize and shutdown`
- 결과: `[PASS] zeroize, service lockout, and shutdown`

### 2. 관련 채점 요구사항

FSM/state model, zeroization, CRITICAL_ERROR lockout.

### 3. 정확한 호출 체인

`demo_shutdown()` -> `KCMVP_Zeroize()` -> `reset_module_data()` ->
`secure_zero(algTestedFlag)` + `hash_drbg_uninstantiate(module_drbg)` ->
`module_state_transition(FATAL_ERROR)` (`NORMAL -> CRITICAL_ERROR`).
그다음 `KCMVP_RNG_Generate()` -> `module_authorize_service()` ->
`KCMVP_ERROR_INVALID_STATE`. 마지막으로 `KCMVP_Shutdown()` ->
`reset_module_data()` -> `module_state_transition(SHUTDOWN)` -> `EXIT`, 이후
`KCMVP_GetState()`. 파일은 `app/main.c`, `lib/KCMVP_Crypto.c`,
`lib/hash_drbg.c`, `lib/module_state.c`다.

### 4. 입력과 시험 벡터

암호 벡터는 없다. zeroize 후 16바이트 RNG 출력 요청을 잠금 확인용으로
사용한다.

### 5. 확인 조건

`KCMVP_Zeroize() == KCMVP_SUCCESS`, RNG 호출이
`KCMVP_ERROR_INVALID_STATE(-3)`, `KCMVP_Shutdown() == KCMVP_SUCCESS`, 최종
상태가 `KCMVP_CM_EXIT(1008)`이어야 한다.

### 6. PASS의 의미

민감한 DRBG 상태와 KAT 승인 플래그가 제거되고, zeroize 직후 서비스가
실제로 잠기며, 종료 상태까지 전환됨을 한 흐름에서 확인한다.

### 7. 실패 검증

`module_state_test`가 zeroize 후 SHA3, HMAC, ARIA, ECDH, ML-KEM 전체를
거부하는지 추가로 확인하고, shutdown 후 status가 initialized/operational
모두 거짓인지 확인한다.

### 8. 권장 한국어 내레이션

“제로화를 호출하면 DRBG 상태와 알고리즘 승인 정보가 지워지고 모듈은
CRITICAL_ERROR로 이동합니다. 바로 이어진 RNG 요청이 마이너스 3으로
차단되고, shutdown 후 최종 상태가 EXIT가 되므로 제로화, 잠금, 종료가
정상적으로 연결됨을 확인합니다.”

## Menu 12: Complete supplied ARIA vector suite

### 1. 메뉴 번호와 출력 제목

- 메뉴: `12. Complete supplied ARIA vector suite`
- 결과: `[PASS] 3,342 ARIA encryption/decryption vectors`

### 2. 관련 채점 요구사항

Algorithm normal operation, supplied vector verification, FSM/state model.

### 3. 정확한 호출 체인

`demo_aria_vectors()` -> 각 파일에 `kat_run_file()` -> `parse_field()` /
`hex_to_bytes()` -> 각 vector마다 암호화 `KCMVP_ARIA_Crypt()`와 복호화
`KCMVP_ARIA_Crypt()` -> `ARIA_ECB()`/`ARIA_CBC()`/`ARIA_CTR()` -> ARIA core.
파일은 `app/main.c`, `app/kat.c`, `lib/KCMVP_Crypto.c`,
`lib/aria_Mode.c`, `lib/aria.c`, `vectors/aria/*.txt`다.

### 4. 입력과 시험 벡터

다음 9개 KAT 파일을 사용한다: ARIA-128/192/256 각각의 ECB, CBC, CTR.
각 레코드의 `KEY`, 선택적 `IV`, `PT`, `CT`를 파싱한다. 파일별 건수는
키 크기별 276, 338, 400이며 세 모드 합계는 3,342건이다.

### 5. 확인 조건

각 vector에서 encrypt/decrypt API가 성공하고, 계산 ciphertext가 파일의
`CT`와 같으며, 파일의 `CT`를 복호화한 결과가 `PT`와 같아야 한다. 모든
파일의 failed count가 0이어야 최종 PASS다.

### 6. PASS의 의미

단일 예제가 아니라 세 키 크기와 세 공개 모드의 전체 제공 벡터에서
암호화와 복호화가 모두 기대값과 일치함을 증명한다.

### 7. 실패 검증

파일 열기 실패는 `kat_run_file()`이 -1을 반환하고, 잘못된 hex/길이 또는
암복호 결과 불일치는 failed count를 증가시켜 최종 FAIL로 이어진다.
추가 매개변수 실패는 `module_state_test`가 담당한다.

### 8. 권장 한국어 내레이션

“마지막 알고리즘 검증으로 제공된 ARIA ECB, CBC, CTR 벡터를 128, 192,
256비트 키에 대해 전부 실행합니다. 각 항목에서 기대 암호문과 복호 원문을
모두 비교하며, 총 3,342건의 실패가 0이므로 지원 범위 전체의 정상 동작을
확인합니다.”

## `./build/main --all` 단계별 추적

`--all`은 별도의 암호 경로가 아니라 `run_all()`이 위 메뉴 함수를 정해진
순서로 호출하는 자동 시연 모드다.

1. `run_item(1)` / `demo_initialize()`: 초기화 전 SHA3 거부, 무결성,
   엔트로피, 시작 KAT, DRBG 초기화, `NORMAL` 진입.
2. `run_item(2)` / `demo_status()`: `NORMAL`, initialized, operational 확인.
3. `run_item(3)` / `demo_aria()`: ARIA-128 ECB known-answer 암복호.
4. `run_item(4)` / `demo_sha3()`: SHA3-256(`abc`) known-answer.
5. `run_item(5)` / `demo_hmac()`: HMAC-SHA3-224 known-answer.
6. `run_item(6)` / `demo_rng()`: generate -> reseed -> generate.
7. `run_item(7)` / `demo_ecdh()`: 두 P-256 keypair의 reciprocal ECDH.
8. `run_item(8)` / `demo_mlkem()`: ML-KEM keypair -> encaps -> decaps.
9. `run_item(9)` / `demo_failure_tests()`: `module_state_test` 존재 확인과
   별도 실패 검증 안내.
10. `run_item(10)` / `demo_conditional_tests()`: ECC/ML-KEM pairwise 시험 후
    `NORMAL` 복귀 확인.
11. `run_item(12)` / `demo_aria_vectors()`: 3,342개 ARIA 암복호 vector.
12. `run_item(11)` / `demo_shutdown()`: zeroize -> 서비스 잠금 -> shutdown.
13. 각 함수의 반환 실패 수를 합산하고 0이면
    `FINAL DEMO RESULT: PASS (0 failures)`를 출력한다.

`--all`에서 메뉴 9의 반환값은 테스트 바이너리 존재 여부만 반영한다.
따라서 영상에서 강제 실패 결과까지 주장하려면 `make audit` 출력 또는
`./build/module_state_test`의 `module state tests: PASS`를 함께 보여 주어야
한다.

## 별도 검증 바이너리

### `./build/module_state_test`

생산 API에 노출하지 않은 fault-injection hook을 테스트 전용 빌드에서만
활성화한다. 다음을 실제로 검증한다.

- 정상 entropy, RCT 실패, APT 실패, provider 실패.
- 정상 integrity manifest와 강제 손상 manifest.
- ARIA, Hash_DRBG, ECC, ML-KEM 시작 KAT 강제 실패.
- ECC/ML-KEM conditional failure 시 후보 키 zeroization과 lockout.
- reseed entropy 실패 시 `CRITICAL_ERROR`와 RNG lockout.
- 모든 알고리즘의 초기화 전 거부와 오류 상태 거부.
- SHA3/HMAC/ARIA/DRBG/ECDH/ML-KEM 정상 동작과 잘못된 인자 거부.
- `NORMAL`, `COND_SELFTEST`, `CRITICAL_ERROR`, `EXIT` 전환.

별도 바이너리가 필요한 이유는 테스트용 entropy provider와 forced failure
함수를 production shared library의 공개 `KCMVP_*` API에 포함시키지 않기
위해서다.

### `./build/sha3_vs`

`KCMVP_Initialize()` 후 `KCMVP_SHA3_Hash()`와 `KCMVP_HMAC_SHA3()` 공개 API를
사용하여 SHA3-224/256/384/512 ShortMsg, LongMsg, Monte Carlo와 HMAC-SHA3
response vectors를 검증한다. 각 계산값을 `.rsp`의 `MD` 또는 `Mac`과
비교하며 마지막 total failed가 0이어야 성공한다.

## 최종 발표 요약표

| Menu item | Requirement | Public API | Internal files | PASS condition | What to say in video |
|---|---|---|---|---|---|
| 1 | Startup self-test, integrity, entropy, FSM | `KCMVP_SHA3_Hash`, `KCMVP_Initialize` | `KCMVP_Crypto.c`, `integrity.c`, `entropy.c`, `selftest.c`, `hash_drbg.c`, `module_state.c` | Pre-init call is -2; full init succeeds | “무결성, 엔트로피, KAT, DRBG 초기화 후에만 NORMAL로 진입합니다.” |
| 2 | FSM/state model | `KCMVP_GetStatus`, `KCMVP_GetState` | `KCMVP_Crypto.c`, `module_state.c` | State NORMAL, initialized and operational true | “공개 상태와 내부 FSM이 모두 정상 서비스 상태입니다.” |
| 3 | ARIA normal operation | `KCMVP_ARIA_Crypt` | `KCMVP_Crypto.c`, `aria_Mode.c`, `aria.c` | Expected ciphertext and recovered plaintext both match | “알려진 암호문과 역변환 원문을 모두 비교합니다.” |
| 4 | SHA3 normal operation | `KCMVP_SHA3_Hash` | `KCMVP_Crypto.c`, `sha3.c` | SHA3-256(`abc`) equals expected digest | “표준 known answer와 32바이트 전체가 일치합니다.” |
| 5 | HMAC-SHA3 normal operation | `KCMVP_HMAC_SHA3` | `KCMVP_Crypto.c`, `KISA_HMAC_SHA3.c`, `sha3.c` | 28-byte HMAC equals expected tag | “키와 메시지에 대한 알려진 MAC과 일치합니다.” |
| 6 | DRBG normal operation, entropy | `KCMVP_RNG_Generate`, `KCMVP_RNG_Reseed` | `KCMVP_Crypto.c`, `hash_drbg.c`, `entropy.c`, `sha3.c` | Generate/reseed/generate succeed and outputs differ | “시작 KAT 후 실제 엔트로피 기반 reseed와 상태 갱신을 확인합니다.” |
| 7 | P-256 ECDH, conditional self-test | `KCMVP_ECC_GenerateKeyPair`, `KCMVP_ECC_ComputeSharedSecret` | `KCMVP_Crypto.c`, `ecc.c`, `hash_drbg.c`, `micro-ecc/uECC.c` | Both reciprocal shared secrets match | “키 반환 전 pairwise 시험과 실제 양방향 ECDH 일치를 확인합니다.” |
| 8 | ML-KEM-768, conditional self-test | `KCMVP_MLKEM_Keypair`, `KCMVP_MLKEM_Encaps`, `KCMVP_MLKEM_Decaps` | `KCMVP_Crypto.c`, `mlkem.c`, `mlkem_randombytes.c`, PQClean ML-KEM files | Encapsulated and decapsulated secrets match | “시작 KAT, 키 pairwise 시험, encaps/decaps 일치를 함께 검증합니다.” |
| 9 | Integrity/entropy/KAT/conditional failure | Production API 없음; separate test hooks | `module_state_test.c`, `integrity.c`, `entropy.c`, `selftest.c`, `ecc.c`, `mlkem.c` | Menu only checks test binary exists; real proof is `module state tests: PASS` | “고장 주입은 생산 API가 아닌 별도 테스트 바이너리에서 수행합니다.” |
| 10 | Conditional self-test, FSM | `KCMVP_ECC_GenerateKeyPair`, `KCMVP_MLKEM_Keypair`, `KCMVP_GetStatus` | `KCMVP_Crypto.c`, `ecc.c`, `mlkem.c`, `module_state.c` | Both pairwise tests pass and state returns to NORMAL | “검증된 키만 반환되고 조건부 시험 후 NORMAL로 복귀합니다.” |
| 11 | Zeroize, lockout, shutdown | `KCMVP_Zeroize`, `KCMVP_RNG_Generate`, `KCMVP_Shutdown`, `KCMVP_GetState` | `KCMVP_Crypto.c`, `hash_drbg.c`, `module_state.c` | Zeroize succeeds, RNG is -3, final state EXIT | “민감 상태 제거 후 서비스가 잠기고 안전하게 종료됩니다.” |
| 12 | ARIA vector coverage | `KCMVP_ARIA_Crypt` | `app/kat.c`, `KCMVP_Crypto.c`, `aria_Mode.c`, `aria.c`, `vectors/aria/` | All 3,342 encrypt/decrypt checks pass | “세 키 크기와 ECB/CBC/CTR 전체 벡터가 실패 0건입니다.” |
