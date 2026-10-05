from ..telemetry import Recorder
from .base import LLM
from .stub import StubLLM


def make_llm(name: str, recorder: Recorder) -> LLM:
    if name == "stub":
        return StubLLM(recorder)
    if name == "gemini":
        from .gemini import GeminiLLM

        return GeminiLLM(recorder)
    raise ValueError(f"unknown llm: {name!r} (expected 'stub' or 'gemini')")


__all__ = ["LLM", "StubLLM", "make_llm"]
