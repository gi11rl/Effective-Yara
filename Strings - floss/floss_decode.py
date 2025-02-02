import os
import subprocess
from collections import Counter
import pandas as pd

pe_dir = './EffectiveYara_password_is_infected/EffectiveYara'
output_file = 'floss_extracted_strings.csv'

all_unique_strings = []

for filename in os.listdir(pe_dir):
    if filename.endswith('.exe') or filename.endswith('.dll'):
        file_path = os.path.join(pe_dir, filename)
        result = subprocess.run(['floss', file_path], capture_output=True, text=True)
        # 한 파일 내 중복 제거
        unique_strings = set(result.stdout.strip().splitlines())
        all_unique_strings.extend(unique_strings)
        
        print(f"[+] Processed: {filename} ({len(unique_strings)} unique strings)")

# 빈도
string_counts = Counter(all_unique_strings)
sorted_strings = string_counts.most_common()

df = pd.DataFrame(sorted_strings, columns=['String', 'File_Count'])
df.to_csv(output_file, index=False)
