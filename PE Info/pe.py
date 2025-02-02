import os
import pefile
from collections import Counter
import pandas as pd

pe_dir = './EffectiveYara_password_is_infected/EffectiveYara'

imported_functions = []
imported_libraries = []
version_info = []
resource_names = []

for filename in os.listdir(pe_dir):
    if filename.endswith('.exe') or filename.endswith('.dll'):
        file_path = os.path.join(pe_dir, filename)
        pe = pefile.PE(file_path)

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imported_libraries.append(entry.dll.decode('utf-8', errors='ignore'))
                for imp in entry.imports:
                    if imp.name:
                        imported_functions.append(imp.name.decode('utf-8', errors='ignore'))

        if hasattr(pe, 'VS_VERSIONINFO'):
            for fileinfo in pe.FileInfo:
                for info in fileinfo:
                    if hasattr(info, 'StringTable'):
                        for st in info.StringTable:
                            for key, value in st.entries.items():
                                version_info.append(f"{key.decode('utf-8', errors='ignore')}: {value.decode('utf-8', errors='ignore')}")

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name:
                    resource_names.append(str(resource_type.name))
                elif resource_type.struct.Id:
                    resource_names.append(f"ID_{resource_type.struct.Id}")


# 빈도
function_counts = Counter(imported_functions)
library_counts = Counter(imported_libraries)
version_counts = Counter(version_info)
resource_counts = Counter(resource_names)

df_functions = pd.DataFrame(function_counts.items(), columns=['Function', 'Count']).sort_values(by='Count', ascending=False)
df_libraries = pd.DataFrame(library_counts.items(), columns=['Library', 'Count']).sort_values(by='Count', ascending=False)
df_versions = pd.DataFrame(version_counts.items(), columns=['Version Info', 'Count']).sort_values(by='Count', ascending=False)
df_resources = pd.DataFrame(resource_counts.items(), columns=['Resource', 'Count']).sort_values(by='Count', ascending=False)
df_functions.to_csv('most_common_functions.csv', index=False)
df_libraries.to_csv('most_common_libraries.csv', index=False)
df_versions.to_csv('most_common_versions.csv', index=False)
df_resources.to_csv('most_common_resources.csv', index=False)
