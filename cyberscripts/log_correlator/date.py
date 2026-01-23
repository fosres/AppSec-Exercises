from dateutil import parser

primary_date = parser.parse("2024-01-15T10:00:00Z")

secondary_date = parser.parse("2024-01-15T10:05:00Z")

diff = secondary_date - primary_date

print(diff.total_seconds())
