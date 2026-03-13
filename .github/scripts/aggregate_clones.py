'''
Usage:

cd SecEng-Exercises
python3 .github/scripts/aggregate_clones.py
'''
import os
import json
from datetime import datetime
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_FILE = os.path.join(SCRIPT_DIR, "../..", "data", "clones_raw.json")
VIEWS_FILE = os.path.join(SCRIPT_DIR, "../..", "data", "views_raw.json")

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
					seen[ts] = {
						"date": ts[:10],
						"count": entry["count"],
						"uniques": entry["uniques"]
					}
			except json.JSONDecodeError:
				continue
	return list(seen.values())

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

def aggregate(entries, period):
	"""Aggregate entries by week, month, year, or all-time."""
	buckets = defaultdict(lambda: {"count": 0, "uniques": 0})

	for entry in entries:
		date = datetime.strptime(entry["date"], "%Y-%m-%d")

		if period == "week":
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
	print("=== CLONES ===")
	clones = load_clones(RAW_FILE)
	print(f"Total data points: {len(clones)}")
	for period in ["week", "month", "year", "all_time"]:
		print(f"\n--- By {period.upper().replace('_', ' ')} ---")
		results = aggregate(clones, period)
		for key, vals in results.items():
			print(f"  {key}: {vals['count']} clones, {vals['uniques']} unique cloners")

	print("\n=== VISITORS ===")
	views = load_views(VIEWS_FILE)
	print(f"Total data points: {len(views)}")
	for period in ["week", "month", "year", "all_time"]:
		print(f"\n--- By {period.upper().replace('_', ' ')} ---")
		results = aggregate(views, period)
		for key, vals in results.items():
			print(f"  {key}: {vals['count']} views, {vals['uniques']} unique visitors")

if __name__ == "__main__":
	main()
