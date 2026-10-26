"""Demo: protect a prompt, call a model, get the answer back with real values.

    python example.py                 # mock model, no key needed
    OPENAI_API_KEY=... python example.py   # real gpt-4o-mini call

For the real call: pip install -r requirements-example.txt
"""
import os

from pii_guard import protect

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

PROMPT = """\
Customer record for support ticket 4821:
Name: Jane Smith
SSN: 123-45-6789
Card on file: 4532-0151-1283-0366
Email: jane.smith@example.com
Phone: (732) 555-0101

Write a two-sentence internal note saying we verified this customer's identity.
Refer to the SSN, card, email and phone by the exact placeholder text shown in the record.
"""
LOG_PATH = "example_audit.jsonl"


def make_llm():
    if os.environ.get("OPENAI_API_KEY"):
        import openai

        client = openai.OpenAI()
        print("[INFO] OPENAI_API_KEY found: calling gpt-4o-mini")

        def call(prompt: str) -> str:
            reply = client.chat.completions.create(
                model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}]
            )
            return reply.choices[0].message.content

        return call

    print("[INFO] No OPENAI_API_KEY: using a mock model that echoes the placeholders")

    def mock(prompt: str) -> str:
        placeholders = [w.strip(",.:") for w in prompt.split() if w.startswith("[")]
        return "I received: " + ", ".join(placeholders)

    return mock


def banner(title: str) -> None:
    print("\n" + "=" * 64 + f"\n{title}\n" + "=" * 64)


def main() -> None:
    result = protect(PROMPT, make_llm(), log_path=LOG_PATH)

    banner("SENT TO THE MODEL (no raw PII)")
    print(result.clean_prompt)

    banner(f"AUDIT LOG ({len(result.audit)} items, masked, safe to store)")
    for rec in result.audit:
        print(f"  {rec['token']:<28} {rec['type']:<12} {rec['display']}")

    banner("MODEL REPLY, as returned (still tokenized)")
    print(result.raw_response)

    banner("MODEL REPLY, after de-tokenization (shown to the user only)")
    print(result.response)

    rec = result.record
    banner(f"WHAT THE LOG SAYS (appended to {LOG_PATH})")
    print(f"  masked and sent as tokens : {len(rec['sent']['tokens_present'])}")
    print(f"  raw PII still in prompt   : {rec['sent']['residual_pii'] or 'none'}")
    print(f"  tokens the model returned : {len(rec['reply']['tokens_returned'])}")
    print(f"  tokens restored for user  : {len(rec['reply']['restored'])}")
    if rec["reply"]["tokens_not_returned"]:
        print(f"  not returned by the model : {rec['reply']['tokens_not_returned']}")


if __name__ == "__main__":
    main()
