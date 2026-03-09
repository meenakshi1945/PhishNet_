import argparse
import os
import random
import re
from urllib.parse import quote

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URLS_PATH = os.path.join(BASE_DIR, "urls.csv")
BACKUP_PATH = os.path.join(BASE_DIR, "urls_seed_backup.csv")

PHISH_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "signin",
    "password",
    "confirm",
    "billing",
    "wallet",
    "payment",
    "alert",
]

BRANDS = [
    "google",
    "microsoft",
    "amazon",
    "paypal",
    "apple",
    "netflix",
    "github",
    "facebook",
    "instagram",
    "whatsapp",
]

HIGH_RISK_TLDS = ["xyz", "top", "click", "zip", "work", "support", "gq", "tk"]
PATH_PARTS = ["verify", "secure", "account", "auth", "update", "session", "billing"]
REDIRECT_KEYS = ["next", "url", "redirect", "continue", "return", "dest"]

LEET = {
    "o": "0",
    "i": "1",
    "l": "1",
    "e": "3",
    "a": "4",
    "s": "5",
    "t": "7",
}


def _normalize(url: str) -> str:
    value = str(url).strip()
    if not value:
        return ""
    if "://" not in value:
        return f"http://{value}"
    return value


def _seed_benign_domains(df: pd.DataFrame):
    domains = set()
    for url in df[df["label"] == 0]["url"].tolist():
        m = re.match(r"^[a-z]+://([^/]+)", _normalize(url).lower())
        if m:
            domains.add(m.group(1).replace("www.", ""))
    domains.update(
        {
            "wikipedia.org",
            "python.org",
            "stackoverflow.com",
            "mozilla.org",
            "openai.com",
            "linkedin.com",
            "cloudflare.com",
            "bbc.com",
            "nytimes.com",
            "reddit.com",
            "youtube.com",
            "apple.com",
            "microsoft.com",
            "amazon.com",
        }
    )
    return sorted(domains)


def _leet_variant(text: str) -> str:
    chars = list(text)
    idxs = [i for i, c in enumerate(chars) if c in LEET]
    if not idxs:
        return text
    for i in random.sample(idxs, k=max(1, min(2, len(idxs)))):
        chars[i] = LEET[chars[i]]
    return "".join(chars)


def _make_benign(domain: str) -> str:
    scheme = random.choice(["https", "https", "https", "http"])
    path_count = random.choice([0, 1, 1, 2, 2, 3])
    vocab = [
        "about",
        "docs",
        "blog",
        "help",
        "products",
        "contact",
        "support",
        "community",
        "updates",
        "careers",
        "pricing",
        "news",
    ]
    path = "/".join(random.choices(vocab, k=path_count))
    query = ""
    if random.random() < 0.35:
        query = f"?page={random.randint(1,600)}&lang={random.choice(['en','en-us','en-in'])}"
    if path:
        return f"{scheme}://{domain}/{path}{query}"
    return f"{scheme}://{domain}{query}"


def _make_phish() -> str:
    brand = random.choice(BRANDS)
    mode = random.choice(["typo", "brand-plus", "ip", "subdomain-mask"])
    scheme = random.choice(["http", "http", "https"])
    tld = random.choice(HIGH_RISK_TLDS)
    kw = random.sample(PHISH_KEYWORDS, k=3)
    path = random.choice(PATH_PARTS)

    if mode == "ip":
        ip = ".".join(str(random.randint(10, 250)) for _ in range(4))
        qkey = random.choice(REDIRECT_KEYS)
        target = quote(f"https://{brand}.com")
        return f"http://{ip}/{path}?{qkey}={target}"

    if mode == "typo":
        fake = _leet_variant(brand)
        host = f"{fake}-{kw[0]}-{kw[1]}.{tld}"
    elif mode == "subdomain-mask":
        host = f"{brand}.com.{kw[0]}-{kw[1]}-{kw[2]}.{tld}"
    else:
        host = f"{kw[0]}-{brand}-{kw[1]}-{kw[2]}.{tld}"

    q = ""
    if random.random() < 0.65:
        qkey = random.choice(REDIRECT_KEYS)
        target = quote(f"http://{random.choice(BRANDS)}.{random.choice(HIGH_RISK_TLDS)}/{random.choice(PATH_PARTS)}")
        q = f"?{qkey}={target}"
    return f"{scheme}://{host}/{path}{q}"


def expand_dataset(target_per_class: int, output_path: str):
    df = pd.read_csv(URLS_PATH)
    df["url"] = df["url"].map(_normalize)
    df["label"] = df["label"].astype(int)
    df = df[["url", "label"]].dropna().drop_duplicates()

    if not os.path.exists(BACKUP_PATH):
        df.to_csv(BACKUP_PATH, index=False)

    benign_domains = _seed_benign_domains(df)
    benign = set(df[df["label"] == 0]["url"].tolist())
    phish = set(df[df["label"] == 1]["url"].tolist())

    attempts = 0
    max_attempts = target_per_class * 40
    while len(benign) < target_per_class and attempts < max_attempts:
        benign.add(_make_benign(random.choice(benign_domains)))
        attempts += 1

    attempts = 0
    while len(phish) < target_per_class and attempts < max_attempts:
        phish.add(_make_phish())
        attempts += 1

    if len(benign) < target_per_class or len(phish) < target_per_class:
        raise RuntimeError(
            f"Could not reach target_per_class={target_per_class}. "
            f"Generated benign={len(benign)}, phishing={len(phish)}."
        )

    out = pd.DataFrame(
        [{"url": u, "label": 0} for u in benign] + [{"url": u, "label": 1} for u in phish]
    ).drop_duplicates(subset=["url"])

    # Ensure balanced classes after dedupe
    legit = out[out["label"] == 0].sample(target_per_class, random_state=42)
    bad = out[out["label"] == 1].sample(target_per_class, random_state=42)
    final_df = pd.concat([legit, bad], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)

    final_df.to_csv(output_path, index=False)
    print(f"Saved expanded dataset: {output_path}")
    print(f"Rows: {len(final_df)} (legitimate={target_per_class}, phishing={target_per_class})")
    print(f"Backup of original seed saved at: {BACKUP_PATH}")


def main():
    parser = argparse.ArgumentParser(description="Expand tiny seed URL dataset into larger balanced dataset.")
    parser.add_argument("--target-per-class", type=int, default=3000, help="Rows per class to generate")
    parser.add_argument("--output", default=URLS_PATH, help="Output CSV path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    random.seed(args.seed)
    expand_dataset(args.target_per_class, args.output)


if __name__ == "__main__":
    main()
