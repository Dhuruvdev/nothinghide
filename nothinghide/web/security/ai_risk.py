import os
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

AI_INTEGRATIONS_OPENROUTER_API_KEY = os.environ.get("AI_INTEGRATIONS_OPENROUTER_API_KEY")
AI_INTEGRATIONS_OPENROUTER_BASE_URL = os.environ.get("AI_INTEGRATIONS_OPENROUTER_BASE_URL")

# Using Replit's AI Integrations with OpenRouter
# This provides access to advanced models including Nvidia Nemotron
client = OpenAI(
    api_key=AI_INTEGRATIONS_OPENROUTER_API_KEY,
    base_url=AI_INTEGRATIONS_OPENROUTER_BASE_URL
)

def is_rate_limit_error(exception: BaseException) -> bool:
    return "429" in str(exception) or "RATELIMIT_EXCEEDED" in str(exception)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception(is_rate_limit_error),
    reraise=True
)
def analyze_risk_with_ai(biometrics: dict, fingerprint: dict) -> dict:
    """Uses Nvidia's Nemotron model to analyze bot-like behavioral patterns."""
    model = "nvidia/llama-3.1-nemotron-70b-instruct"
    
    prompt = f"""
    Analyze the following browser security signals and determine the risk level (LOW, MEDIUM, HIGH).
    
    Biometrics: {biometrics}
    Fingerprint: {fingerprint}
    
    Respond in JSON format with:
    {{
        "risk": "LOW|MEDIUM|HIGH",
        "score": 0-100,
        "reasoning": "brief explanation"
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        import json
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        # Fallback if AI fails
        return {"risk": "LOW", "score": 0, "reasoning": "AI Analysis Unavailable"}
