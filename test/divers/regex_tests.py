import re

texte1 = "Du texte avec ${PLACEHOLDER1} pour des ${PLACEHOLDER2} importants."

result = re.findall('\\${([A-Z0-9_]+)}', texte1)

for group in result:
    print(group)
