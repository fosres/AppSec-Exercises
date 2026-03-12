import json
from datetime import datetime, timedelta
from collections import defaultdict

RAW_FILE = "data/clones_raw.json"

def load_clones(filepath):
    """Load and deduplicate clone entries by timestamp."""
    seen = {}
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                batch = json.loads(line)
                for entry in batch.get("clones", []):
                    ts = entry["timestamp"]
                    # dedup: keep the most recent fetch's value for each day
                    seen[ts] = {
                        "date": ts[:10],
                        "count": entry["count"],
                        "uniques": entry["uniques"]
                    }
            except json.JSONDecodeError:
                continue
    return list(seen.values())

def aggregate(clones, period):
    """Aggregate clones by week, month, year, or all-time."""
    buckets = defaultdict(lambda: {"count": 0, "uniques": 0})

    for entry in clones:
        date = datetime.strptime(entry["date"], "%Y-%m-%d")

        if period == "week":
            # ISO week: e.g. "2026-W10"
            key = f"{date.isocalendar()[0]}-W{date.isocalendar()[1]:02d}"
        elif period == "month":
            key = date.strftime("%Y-%m")
        elif period == "year":
            key = date.strftime("%Y")
        elif period == "all_time":
            key = "all_time"

        buckets[key]["count"]   += entry["count"]
        buckets[key]["uniques"] += entry["uniques"]

    return dict(sorted(buckets.items()))

def main():
    clones = load_clones(RAW_FILE)
    print(f"\nTotal data points: {len(clones)}\n")

    for period in ["week", "month", "year", "all_time"]:
        print(f"=== By {period.upper().replace('_', ' ')} ===")
        results = aggregate(clones, period)
        for key, vals in results.items():
            print(f"  {key}: {vals['count']} clones, {vals['uniques']} unique cloners")
        print()

if __name__ == "__main__":
    main()
