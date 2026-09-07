# 설계 문서

이 디렉터리는 교과 프로젝트 SW 암호모듈의 LaTeX 설계 문서를 포함합니다.
본 프로젝트는 공식 KCMVP/FIPS 검증 모듈이 아니라 교육용 구현입니다.

## 문서 구성

- `basic_design.tex`: 프로젝트 개요, 요구사항 충족 현황, 전체 아키텍처,
  FSM 개요, 지원 알고리즘, 시험 전략, 실행 방법과 주요 한계를 설명합니다.
- `detailed_design.tex`: 파일 구조, 공개 API, 상태 전이, 오류 처리, 시작
  자가시험, 무결성 및 엔트로피 흐름, Hash_DRBG, P-256, ML-KEM, 영점화,
  심볼 통제와 세부 시험 사례를 설명합니다.

## PDF 빌드

한국어 처리를 위해 XeLaTeX와 `kotex` 패키지를 권장합니다. 프로젝트
루트에서 다음과 같이 실행합니다.

```bash
xelatex -output-directory=docs docs/basic_design.tex
xelatex -output-directory=docs docs/basic_design.tex

xelatex -output-directory=docs docs/detailed_design.tex
xelatex -output-directory=docs docs/detailed_design.tex
```

두 번 실행하면 목차와 내부 참조가 갱신됩니다. TeX Live 환경에서는 보통
`texlive-xetex`, `texlive-lang-korean`, `texlive-latex-extra` 패키지가
필요합니다.

`latexmk`가 설치되어 있으면 다음 명령도 사용할 수 있습니다.

```bash
latexmk -xelatex -outdir=docs docs/basic_design.tex
latexmk -xelatex -outdir=docs docs/detailed_design.tex
```

생성되는 PDF와 보조 파일은 `docs/` 아래에 위치합니다.
