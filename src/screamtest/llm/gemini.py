"""Gemini via the google-genai SDK. Works against AI Studio or Vertex AI.

AI Studio:  set GEMINI_API_KEY.
Vertex AI:  set GOOGLE_GENAI_USE_VERTEXAI=true, GOOGLE_CLOUD_PROJECT and
            GOOGLE_CLOUD_LOCATION, and authenticate with
            `gcloud auth application-default login`. Usage bills to the project,
            so GCP trial credits apply.
"""

from __future__ import annotations

import os

from ..models import Evidence, EvidencePlan, Judgement, Role
from ..telemetry import Recorder
from .base import judge_prompt, plan_prompt

DEFAULT_MODEL = "gemini-2.5-flash"


class GeminiLLM:
    provider = "gemini"

    def __init__(self, recorder: Recorder, model: str | None = None):
        from google import genai  # optional dependency: pip install -e '.[gemini]'

        self.rec = recorder
        self.model = model or os.environ.get("SCREAMTEST_GEMINI_MODEL", DEFAULT_MODEL)
        self.client = genai.Client()

    def propose_plan(self, resource_class: str) -> EvidencePlan:
        system, user = plan_prompt(resource_class)
        return self._structured("plan", system, user, EvidencePlan)

    def judge(self, role: Role, evidence: list[Evidence]) -> Judgement:
        system, user = judge_prompt(role, evidence)
        return self._structured("judge", system, user, Judgement, role=role.name)

    def _structured(self, stage: str, system: str, user: str, schema, **attrs):
        from google.genai import types

        with self.rec.span(stage, "llm", provider=self.provider, model=self.model, **attrs) as span:
            resp = self.client.models.generate_content(
                model=self.model,
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    temperature=0,
                    response_mime_type="application/json",
                    response_schema=schema,
                ),
            )
            usage = resp.usage_metadata
            span.attrs["input_tokens"] = getattr(usage, "prompt_token_count", 0) or 0
            span.attrs["output_tokens"] = getattr(usage, "candidates_token_count", 0) or 0
            # Re-validate rather than trusting resp.parsed: the schema is enforced
            # by us, not by the provider.
            return schema.model_validate_json(resp.text)
