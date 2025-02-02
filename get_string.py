import os
from collections import Counter

malware_dir = './EffectiveYara_password_is_infected/EffectiveYara'
all_unique_strings = []

for filename in os.listdir(malware_dir):
    file_path = os.path.join(malware_dir, filename)
    with os.popen(f"strings {file_path}") as file:
        # 파일 내 중복 제거
        unique_strings = set(file.read().splitlines())
        all_unique_strings.extend(unique_strings)

# 빈도
string_counts = Counter(all_unique_strings)
most_common_strings = string_counts.most_common()

with open('strings.txt', 'w') as f:
    for string, count in most_common_strings:
        f.write(f"{count}: {string}\n")
