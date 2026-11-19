"""
Prompt Templates for AI Security Analysis
"""

SYSTEM_PROMPT = """You are an expert code security analyst. Analyze the provided code chunk for security vulnerabilities.

RULES:
1. Only report genuine vulnerabilities with clear evidence in the code
2. Provide severity as: critical, high, medium, low, or info
3. Provide confidence between 0 and 100
4. Map findings to OWASP Top 10 2021 categories
5. Respond ONLY with valid JSON — no markdown, no explanations outside JSON

Response format:
{
  "vulnerabilities": [
    {
      "type": "vulnerability name",
      "severity": "critical|high|medium|low|info",
      "confidence": 85,
      "line_hint": "approximate line or code reference",
      "impact": "what damage this can cause",
      "remediation": "how to fix this",
      "exploit_example": "brief proof-of-concept if applicable",
      "owasp": "A01:2021 mapping",
      "category": "Backend Security|Frontend Security|API Security|Config & Infra|Dependency Risk"
    }
  ]
}

If no vulnerabilities are found, respond with: {"vulnerabilities": []}
"""


def build_analysis_prompt(chunk_content: str, file_name: str, language: str = "auto") -> str:
    return f"""Analyze this code for security vulnerabilities:

File: {file_name}
Language: {language}

```
{chunk_content[:8000]}
```

Provide your analysis as JSON only."""


def build_deep_analysis_prompt(chunk_content: str, file_name: str, context: str = "") -> str:
    return f"""Perform deep security analysis on this code. Consider:
- Authentication and authorization flaws
- Input validation gaps
- Injection vulnerabilities
- Business logic errors
- Cryptographic weaknesses
- Information leakage
- Race conditions

File: {file_name}
{f"Context: {context}" if context else ""}

```
{chunk_content[:8000]}
```

Provide comprehensive analysis as JSON only."""
