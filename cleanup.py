import os
import shutil

files_to_remove = [
    'STATUS.md', 
    'IMPLEMENTATION_SUMMARY.md', 
    'QUICKSTART.md', 
    'vulnerability_cache.json', 
    'the_ultimate_report.json', 
    'supply_chain_report.json'
]

dirs_to_remove = [
    'supply_chain_analyzer.egg-info', 
    'analyzer/__pycache__', 
    'analyzer/parsers/__pycache__', 
    'analyzer/scanners/__pycache__', 
    'analyzer/reporters/__pycache__', 
    'tests/__pycache__'
]

for f in files_to_remove:
    if os.path.exists(f):
        try:
            os.remove(f)
            print(f"Deleted {f}")
        except Exception as e:
            print(f"Error deleting {f}: {e}")

for d in dirs_to_remove:
    if os.path.exists(d):
        try:
            shutil.rmtree(d, ignore_errors=True)
            print(f"Deleted {d}")
        except Exception as e:
            print(f"Error deleting {d}: {e}")
