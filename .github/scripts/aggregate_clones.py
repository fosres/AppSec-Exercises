'''
Usage:

cd SecEng-Exercises
python3 .github/scripts/aggregate_clones.py
'''
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_FILE = os.path.join(SCRIPT_DIR, "..", "data", "clones_raw.json")
VIEWS_FILE = os.path.join(SCRIPT_DIR, "..", "data", "views_raw.json")
VIEWS_FILE = os.path.join(SCRIPT_DIR, "..", "data", "views_raw.json")

def load_views(filepath):
    """Load and deduplicate view entries by timestamp."""
    seen = {}
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                batch = json.loads(line)
                for entry in batch.get("views", []):
                    ts = entry["timestamp"]
                    seen[ts] = {
                        "date": ts[:10],
                        "count": entry["count"],
                        "uniques": entry["uniques"]
                    }
            except json.JSONDecodeError:
                continue
    return list(seen.values())

def main():
    print("=== CLONES ===")
    clones = load_clones(RAW_FILE)
    for period in ["week", "month", "year", "all_time"]:
        print(f"\n--- By {period.upper().replace('_', ' ')} ---")
        results = aggregate(clones, period)
        for key, vals in results.items():
            print(f"  {key}: {vals['count']} clones, {vals['uniques']} unique cloners")

    print("\n=== VISITORS ===")
    views = load_views(VIEWS_FILE)
    for period in ["week", "month", "year", "all_time"]:
        print(f"\n--- By {period.upper().replace('_', ' ')} ---")
        results = aggregate(views, period)
        for key, vals in results.items():
            print(f"  {key}: {vals['count']} views, {vals['uniques']} unique visitors")
