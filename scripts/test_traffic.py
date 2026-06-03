import httpx
import time
import random
import string

TARGETS = [
    "https://httpbin.org/post",
    "https://httpbin.org/get",
    "https://httpbin.org/anything",
]

LEAK_PAYLOADS = [
    {"password": "supersecret123!", "email": "test@example.com"},
    {"api_key": "sk-live-abc123def456ghi789jkl", "user": "admin"},
    {"credit_card": "4111111111111111", "expiry": "12/28"},
    {"ssn": "123-45-6789", "name": "John Doe"},
    {
        "username": "bob",
        "password": "P@ssw0rd!",
        "secret_key": "abcdef1234567890abcdef1234567890",
    },
]


def random_payload():
    return random.choice(LEAK_PAYLOADS)


def main():
    print("Starting test traffic generation...")

    client = httpx.Client(verify=False)

    for i in range(15):
        target = random.choice(TARGETS)
        payload = random_payload()
        print(f"[{i+1}/15] POST {target}")

        try:
            resp = client.post(target, json=payload, timeout=10.0)
            print(f"  -> {resp.status_code}")
        except Exception as e:
            print(f"  -> FAILED: {e}")

        time.sleep(0.5)

        get_target = random.choice(TARGETS).replace("/post", "/get").replace("/anything", "/get")
        print(f"[{i+1}/15] GET {get_target}")
        try:
            resp = client.get(get_target, timeout=10.0)
            print(f"  -> {resp.status_code}")
        except Exception as e:
            print(f"  -> FAILED: {e}")

        time.sleep(1.0)

    print("Test traffic complete. Check dashboard at http://localhost:8000")


if __name__ == "__main__":
    main()
