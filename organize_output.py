from pathlib import Path
import shutil
import re

OUTPUT = Path("Output")

# Match folders like 20260811
pattern = re.compile(r"^(\d{4})(\d{2})(\d{2})$")

for item in OUTPUT.iterdir():
    if item.is_dir():
        match = pattern.match(item.name)
        if match:
            year, month, day = match.groups()
            target_dir = OUTPUT / year / f"{year}-{month}"
            target_dir.mkdir(parents=True, exist_ok=True)

            destination = target_dir / item.name

            if not destination.exists():
                print(f"Moving {item.name} → {target_dir}/")
                shutil.move(str(item), str(destination))
            else:
                print(f"Skipping {item.name} (already exists)")
