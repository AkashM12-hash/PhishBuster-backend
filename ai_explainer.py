# ai_explainer.py
"""
AI explanation layer
- No raw email content
- No personal data
- Explanation only (no decisions)
"""

import os
from typing import List, Optional

# Groq is OPTIONAL
try:
    from groq import Groq
except ImportError:
    Groq = None

MODEL_NAME = "llama-3.1-8b-instant"


def _build_prompt(
    category: str,
    ml_confidence: Optional[float],
    rule_hits: List[str],
    is_internal: bool,
    has_trusted_links: bool
) -> str:
    return f"""
You are a cybersecurity assistant.

Explain WHY an email was categorized using ONLY the metadata below.
Do NOT speculate.
Do NOT mention missing data.
Do NOT give advice.
Do NOT change the category.

Metadata:
- Final category: {category}
- Rule hits: {", ".join(rule_hits) if rule_hits else "None"}
- ML confidence score: {ml_confidence if ml_confidence is not None else "Not used"}
- Internal email: {is_internal}
- Trusted links present: {has_trusted_links}

Guidelines:
- Be clear and neutral
- Use simple language suitable for HR or employees
- If confidence is high but rules are weak, mention possible false positive
- Keep explanation under 3 sentences
"""


def generate_ai_explanation(
    category: str,
    ml_confidence: Optional[float],
    rule_hits: List[str],
    is_internal: bool,
    has_trusted_links: bool
) -> str:
    """
    Generate explanation using Groq.
    FAIL-SAFE: never affects detection flow.
    """

    # 🔒 AI is optional
    if Groq is None:
        return "Explanation unavailable (AI module not installed)."

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "Explanation unavailable (AI service not configured)."

    try:
        client = Groq(api_key=api_key)

        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "system",
                    "content": "You explain security decisions. You do not judge."
                },
                {
                    "role": "user",
                    "content": _build_prompt(
                        category,
                        ml_confidence,
                        rule_hits,
                        is_internal,
                        has_trusted_links
                    )
                }
            ],
            temperature=0.2,
        )

        return completion.choices[0].message.content.strip()

    except Exception:
        # 🔒 Absolute fail-safe
        return "This email was categorized based on detected security indicators."
