import os
import subprocess
import shutil


LLM_PROVIDER = os.getenv("LLM_PROVIDER", "claude")


def query(prompt: str) -> str:
    """
    LLM CLI를 호출하여 응답을 반환합니다.
    
    환경변수 LLM_PROVIDER로 provider 선택:
    - "claude" (기본값): claude --print 사용 (Anthropic MAX 구독)
    - "codex": codex exec 사용 (ChatGPT 구독) — 구현 필요
    """
    provider = _detect_provider()

    if provider == "claude":
        return _query_claude(prompt)
    elif provider == "codex":
        return _query_codex(prompt)

    raise RuntimeError(
        "LLM CLI를 찾을 수 없습니다. claude 또는 codex를 설치해주세요."
    )


def _detect_provider() -> str:
    if LLM_PROVIDER == "claude" and shutil.which("claude"):
        return "claude"
    if LLM_PROVIDER == "codex" and shutil.which("codex"):
        return "codex"
    if shutil.which("claude"):
        return "claude"
    if shutil.which("codex"):
        return "codex"
    return ""


def _query_claude(prompt: str) -> str:
    result = subprocess.run(
        ["claude", "--print", "--dangerously-skip-permissions", prompt],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"claude 호출 실패: {result.stderr}")
    return result.stdout.strip()


def _query_codex(prompt: str) -> str:
    # TODO: 형이 구현
    # codex exec 출력 파싱 필요:
    #   헤더 (workdir, model, ...) 제거
    #   "codex\n" 이후 ~ "tokens used" 이전 텍스트 추출
    raise NotImplementedError(
        "codex provider 구현 필요\n"
        "parse_codex_output() 함수로 stdout 파싱 후 반환하면 됩니다.\n"
        "참고: echo 'hello' | codex exec --full-auto --skip-git-repo-check"
    )