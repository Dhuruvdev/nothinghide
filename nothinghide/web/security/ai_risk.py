import os
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

AI_INTEGRATIONS_OPENROUTER_API_KEY = os.environ.get("AI_INTEGRATIONS_OPENROUTER_API_KEY")
AI_INTEGRATIONS_OPENROUTER_BASE_URL = os.environ.get("AI_INTEGRATIONS_OPENROUTER_BASE_URL")

# This is using Replit's AI Integrations service, which provides OpenRouter-compatible API access without requiring your own OpenRouter API key.
# We initialize the client inside the risk check function to handle environment changes gracefully.

def get_ai_client():
    if not AI_INTEGRATIONS_OPENROUTER_BASE_URL:
        return None
    return OpenAI(
        api_key=AI_INTEGRATIONS_OPENROUTER_API_KEY or "dummy",
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
    client = get_ai_client()
    if not client:
        return {"risk": "LOW", "score": 0, "reasoning": "AI Engine Offline"}
        
    model = "nvidia/llama-3.1-nemotron-70b-instruct"
    
    # Advanced 2026 Detection Heuristics
    entropy = biometrics.get("entropy", {})
    variance = entropy.get("velocity_variance", 0)
    
    prompt = f"""
    Analyze the following 2026-standard security signals for bot-like behavioral patterns.
    
    Biometrics Data:
    - Mouse Velocity Variance (Entropy): {variance}
    - Total Mouse Movements: {biometrics.get("mouse_moves")}
    - Teleportation Detected: {biometrics.get("teleport_detected")}
    - Reaction Time: {biometrics.get("hesitation_time")}s
    
    Fingerprint Data:
    - Webdriver Flag: {fingerprint.get("webdriver")}
    - Hardware Concurrency: {fingerprint.get("hardware_concurrency")}
    - Platform: {fingerprint.get("platform")}
    
    Instruction: 
    Evaluate if this is an automated agent or a human user. 
    Low entropy (< 1.5) + high movements + webdriver true = HIGH risk.
    
    Respond in JSON format with:
    {{
        "risk": "LOW|MEDIUM|HIGH",
        "score": 0-100,
        "reasoning": "brief explaination"
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        import json
        result = json.loads(response.choices[0].message.content)
        
        # 2026 Semantic Hybrid Analysis: 
        # Combine AI reasoning with entropy verification
        entropy = biometrics.get("entropy", {})
        variance = entropy.get("velocity_variance", 0)
        
        if variance < 1.0 and result.get("risk") == "LOW":
             # Downgrade risk if AI is unsure but entropy is unnaturally low
             result["risk"] = "MEDIUM"
             result["reasoning"] += " (Low behavioral entropy detected)"
             
        return result
    except Exception as e:
        # Fallback if AI fails
        print(f"AI Risk analysis failed: {str(e)}")
        return {"risk": "LOW", "score": 0, "reasoning": "AI Analysis Unavailable"}
