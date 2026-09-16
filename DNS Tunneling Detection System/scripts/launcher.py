import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
detector = os.path.join(ROOT, "scripts", "dns_detector.py")

print("Starting DNS Security Project...")
print("Project:", os.path.basename(ROOT))
print("Detector:", detector)
print()

subprocess.call([sys.executable, detector])
