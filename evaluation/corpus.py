"""Labeled evaluation corpus (synthetic, written by the author).

This is a regression guard, not a benchmark: every string was written to
exercise a specific rule, so the scores say "the rules do what they were
designed to do", not "this is the accuracy you will see on real traffic".
"""

# Sentence templates the positive values are dropped into.
TEMPLATES = (
    "My value is {v}.",
    "{v} is what you need to verify, ok?",
    "Details: ({v}) attached.",
)

POSITIVES = {
    "SSN": [
        "123-45-6789", "234-56-7890", "321-54-9876", "456-78-1234",
        "555-12-3456", "001-01-0001", "899-12-3456", "123 45 6789",
    ],
    "CREDIT_CARD": [
        "4532015112830366", "4532-0151-1283-0366", "4111 1111 1111 1111",
        "5555555555554444", "5105-1051-0510-5100", "378282246310005",
        "3782 822463 10005", "371449635398431", "6011111111111117",
        "6011000990139424", "30569309025904", "3530111333300000",
    ],
    "EMAIL": [
        "jane@example.com", "jane.smith@example.co.uk", "jane+tag@sub.example.org",
        "J_Smith-99@mail.example.io", "a@b.co", "first.last@company-name.com",
    ],
    "PHONE": [
        "732-555-0101", "(732) 555-0101", "(732)555-0101", "+1-732-555-0101",
        "+1 732 555 0101", "732.555.0101", "1-800-555-0199", "+17325550101",
        "732 555 0101",
    ],
}

# Strings that must produce no detections at all.
NEGATIVES = [
    # numbers that look like SSNs
    "000-12-3456", "666-12-3456", "900-12-3456", "123-00-6789", "123-45-0000",
    "Date 2024-05-1234", "Part 123-4-6789", "Serial 1234-56-7890",
    # numbers that look like cards
    "Card 4532015112830367", "Order 1234567890123456", "Ref 1000000000000001",
    "Id 0000000000000000", "Timestamp 1697712345678", "Tracking 9400111899223197",
    # numbers that look like phone numbers
    "Order 2345678901 shipped", "At 2024-05-12 10:30", "Host 192.168.100.200",
    "Version 3.2.1 released", "ISBN 978-3-16-148410-0", "Zip 08901-1234",
    "Call 732-055-0101", "Call 132-555-0101",
    # things that look like emails
    "bad-email@", "Write to @example.com", "user@localhost", "name@example",
    "a..b@example.com", "foo@bar..com",
    # plain text
    "This is a completely clean message with no PII.",
    "The meeting is at 3pm on Tuesday in room 204.",
]

# Realistic multi-type sentences: (text, [(type, value), ...])
MIXED = [
    (
        "Hi, I'm Jane. SSN 123-45-6789, card 4532-0151-1283-0366, "
        "email jane.smith@example.com, phone (732) 555-0101.",
        [("SSN", "123-45-6789"), ("CREDIT_CARD", "4532-0151-1283-0366"),
         ("EMAIL", "jane.smith@example.com"), ("PHONE", "(732) 555-0101")],
    ),
    (
        "Ship order 2345678901 to jane@example.com, call +1-732-555-0101 if late.",
        [("EMAIL", "jane@example.com"), ("PHONE", "+1-732-555-0101")],
    ),
    (
        "Two cards: 378282246310005 and 5555555555554444. Neither is 1234567890123456.",
        [("CREDIT_CARD", "378282246310005"), ("CREDIT_CARD", "5555555555554444")],
    ),
]

# Real PII the detectors intentionally do not catch. Reported separately so the
# headline recall number is not flattering.
KNOWN_MISSES = [
    ("SSN", "my ssn is 123456789", "123456789"),
    ("PHONE", "call 7325550101 tonight", "7325550101"),
    ("EMAIL", "reach me at jane [at] example [dot] com", "jane [at] example [dot] com"),
    ("PHONE", "UK number +44 20 7946 0958", "+44 20 7946 0958"),
]
