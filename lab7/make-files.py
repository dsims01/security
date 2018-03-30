f = open("four-letter.txt", "w+")

chars = []

for a in range(48,58):
	chars.append(chr(a))
for a in range(65,91):
	chars.append(chr(a))
for a in range(97,123):
	chars.append(chr(a))

print len(chars)

for a in chars:
	f.write(a + "\n")
	for b in chars:
		f.write(a + b + "\n")
		for c in chars:
			f.write(a + b + c + "\n")
			for d in chars:
				f.write(a + b + c + d +"\n")
# 				for e in chars:
# 					f.write(a + b + c + d + e + "\n")
# 					for f in chars:
# 						f.write(a + b + c + d + e + f + "\n")





f.close()