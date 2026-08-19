# Script to backfill history.json with dummy data
import json
import os
import random
from datetime import UTC, datetime, timedelta


def main() -> None:
    history_path = os.path.join("reports", "history.json")
    os.makedirs("reports", exist_ok=True)
    history = []
    start_date = datetime.now(UTC) - timedelta(days=365)
    critical = 45
    high = 60
    medium = 30
    low = 15
    print("[SEED] Generating 1 year of historical security data...")
    for i in range(365):
        current_date = start_date + timedelta(days=i)
        if random.random() < 0.05:
            critical += random.randint(1, 5)
            high += random.randint(2, 8)
        if random.random() < 0.15 and critical > 7:
            critical -= random.randint(1, 3)
        if random.random() < 0.2 and high > 5:
            high -= random.randint(1, 4)
        if random.random() < 0.15 and medium > 2:
            medium -= random.randint(1, 3)
        if random.random() < 0.1 and low > 0:
            low -= random.randint(1, 2)
        critical = max(critical, 7)
        high = max(high, 5)
        medium = max(medium, 2)
        low = max(low, 0)
        total = critical + high + medium + low
        history.append(
            {
                "date": current_date.strftime("%Y-%m-%d"),
                "timestamp": current_date.isoformat(),
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
        )
    with open(history_path, "w") as f:
        json.dump(history, f, indent=2)
    print(f"[SEED] Successfully wrote {len(history)} days of data to {history_path}")
    print(
        f"[SEED] Trend went from {history[0]['total']} vulnerabilities down to {history[-1]['total']}.",
    )


if __name__ == "__main__":
    main()
