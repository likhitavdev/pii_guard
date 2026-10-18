"""
example.py — PII Guard in action

Shows the full input-layer protection flow:
  user prompt → PII scan → tokenize → send CLEAN prompt to LLM → print response

Loads OpenAI API key from .env file (never hardcoded).
Falls back to a mock LLM if no key is found.
"""
import os
from dotenv import load_dotenv
from pii_guard import sanitize

# Load API key from .env
load_dotenv()
_api_key = os.environ.get("OPENAI_API_KEY")

if _api_key:
    import openai
    _client = openai.OpenAI(api_key=_api_key)
    USE_REAL_LLM = True
    print("[INFO] OpenAI API key loaded — using real LLM (gpt-4o-mini)")
else:
    USE_REAL_LLM = False
    print("[INFO] No API key found — using mock LLM")


def llm_call(prompt: str) -> str:
    if USE_REAL_LLM:
        response = _client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    else:
        return (
            f"[Mock LLM Response] Received {len(prompt)} chars. "
            f"No PII reached the model."
        )


def main():
    user_prompt = """
    Hi, I need help reviewing my account details.
    My name is Jane Smith.
    SSN: 123-45-6789
    Credit card: 4532-0151-1283-0366
    Email: jane.smith@example.com
    Phone: 732-555-0101
    Please confirm everything looks correct.
    """

    print("=" * 60)
    print("ORIGINAL PROMPT (contains PII — never send this to LLM)")
    print("=" * 60)
    print(user_prompt)

    clean_prompt, vault = sanitize(user_prompt)

    print("=" * 60)
    print("SANITIZED PROMPT (safe to send to LLM)")
    print("=" * 60)
    print(clean_prompt)

    print("=" * 60)
    print(f"AUDIT LOG — {vault.count()} PII item(s) detected")
    print("(masked display values — raw PII never appears in logs)")
    print("=" * 60)
    for token, masked_display in vault.all_detections().items():
        print(f"  {token:20s}  →  {masked_display}")

    print()
    print("=" * 60)
    print("LLM RESPONSE (received clean prompt with tokens, not raw PII)")
    print("=" * 60)
    response = llm_call(clean_prompt)
    print(response)
    print()


if __name__ == "__main__":
    main()