import base64
import argparse
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SALT = b"Sz9isKUcavFN33"
TARGET_HASH = "Pye28w411Wc/2byQhN3yMBQ/aPOp4qsi2Da1Vk0oP9s"
WORDLIST = Path("/Users/tristan/Dev/Cryptography Labs/Lab 8 - User Authentication/rockyou.txt")

CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
STD64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TARGET_RAW = base64.b64decode(TARGET_HASH.translate(str.maketrans(CRYPT64, STD64)) + "=")

BATCH_SIZE = 5000
WORKERS = 8
FAST_LINES = 100_000

QUICK_CANDIDATES = [
    "admin",
    "cisco",
    "password",
    "Password123",
    "admin123",
    "cisco123",
    "letmein",
    "qwerty",
    "123456",
    "supersecret",
]


def is_match(password: str) -> bool:
    derived = hashlib.scrypt(
        password.encode("utf-8", errors="ignore"),
        salt=SALT,
        n=2**14,
        r=1,
        p=1,
        dklen=32,
    )
    return derived == TARGET_RAW


def crack_candidates(candidates: list[str]) -> tuple[str | None, int]:
    checked = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for password, ok in zip(candidates, pool.map(is_match, candidates, chunksize=64)):
            checked += 1
            if ok:
                return password, checked
    return None, checked


def crack_wordlist(max_lines: int | None) -> tuple[str | None, int, float]:
    start = time.time()
    checked = 0
    found = None
    batch: list[str] = []

    with ThreadPoolExecutor(max_workers=WORKERS) as pool, WORDLIST.open(
        "r", encoding="latin-1", errors="ignore"
    ) as f:
        for line in f:
            if max_lines is not None and checked + len(batch) >= max_lines:
                break

            batch.append(line.rstrip("\r\n"))

            if len(batch) < BATCH_SIZE:
                continue

            for password, ok in zip(batch, pool.map(is_match, batch, chunksize=64)):
                checked += 1
                if ok:
                    found = password
                    break

            if found:
                break

            batch.clear()

        if not found and batch and (max_lines is None or checked < max_lines):
            for password, ok in zip(batch, pool.map(is_match, batch, chunksize=64)):
                checked += 1
                if ok:
                    found = password
                    break

    return found, checked, time.time() - start


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Crack Cisco Type 9 hash with fast staged strategy."
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Scan full rockyou list if not found in quick stages.",
    )
    parser.add_argument(
        "--fast-lines",
        type=int,
        default=FAST_LINES,
        help="Number of top rockyou lines to check in fast mode (default: 100000).",
    )
    args = parser.parse_args()

    total_checked = 0
    overall_start = time.time()

    # Stage 1: immediate high-probability candidates.
    found, checked = crack_candidates(QUICK_CANDIDATES)
    total_checked += checked
    if found:
        elapsed = time.time() - overall_start
        print("STAGE=quick-candidates")
        print(f"FOUND={found}")
        print(f"CHECKED={total_checked}")
        print(f"SECONDS={elapsed:.2f}")
        print(f"RATE={total_checked / elapsed:.2f}")
        return

    # Stage 2: top entries from rockyou for faster turnaround.
    found, checked, elapsed_stage = crack_wordlist(args.fast_lines)
    total_checked += checked
    if found:
        elapsed = time.time() - overall_start
        print(f"STAGE=rockyou-top-{args.fast_lines}")
        print(f"FOUND={found}")
        print(f"CHECKED={total_checked}")
        print(f"SECONDS={elapsed:.2f}")
        print(f"RATE={total_checked / elapsed:.2f}")
        return

    # Stage 3: optional full scan fallback.
    if args.full:
        found, checked, elapsed_stage = crack_wordlist(None)
        total_checked += checked
        elapsed = time.time() - overall_start
        print("STAGE=rockyou-full")
        print(f"FOUND={found}")
        print(f"CHECKED={total_checked}")
        print(f"SECONDS={elapsed:.2f}")
        print(f"RATE={total_checked / elapsed:.2f}")
        return

    elapsed = time.time() - overall_start
    print(f"STAGE=rockyou-top-{args.fast_lines}")
    print("FOUND=None")
    print(f"CHECKED={total_checked}")
    print(f"SECONDS={elapsed:.2f}")
    print(f"RATE={total_checked / elapsed:.2f}")
    print("TIP=Re-run with --full to scan the entire wordlist.")


if __name__ == "__main__":
    main()
