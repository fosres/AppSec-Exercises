COUNTRIES = [('Canada', 9984670, 38250000),
             ('Italy', 301340, 59110000),
             ('United Kingdom', 242495, 67220000),
             ('France', 551695, 67390000),
             ('Germany', 357022, 83200000),
             ('Japan', 377975, 125700000),
             ('United States', 9833517, 331900000)
            ]


sorted_countries = sorted(COUNTRIES)

for record in sorted_countries:
	print(f"{record[0]}\t\t\t{record[1]}\t\t{record[2]}\n")

