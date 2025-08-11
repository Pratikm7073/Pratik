# fix_main_leading.py — backup then remove BOM / leading whitespace
import shutil, os, re
src = 'main.py'
bak = src + '.bak'
if not os.path.exists(src):
    print("main.py not found in current directory.")
    raise SystemExit(1)

shutil.copy2(src, bak)
print("Backup written to", bak)

data = open(src, 'rb').read()

# remove UTF-8 BOM if present
if data.startswith(b'\xef\xbb\xbf'):
    print("Removing UTF-8 BOM")
    data = data[3:]

# find first non-whitespace byte
m = re.search(rb'\S', data)
if m and m.start() > 0:
    print("Removing", m.start(), "leading whitespace bytes")
    data = data[m.start():]
elif not m:
    print("File is empty or all whitespace. Restoring backup and exiting.")
    shutil.copy2(bak, src)
    raise SystemExit(1)

open(src, 'wb').write(data)
print("Fixed main.py — leading whitespace/BOM removed.")
