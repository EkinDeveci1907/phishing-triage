# measure.py
#
# Measures what the triage tool costs to run, so the README numbers can be
# checked on any machine:
#   - peak memory of the biggest process: one email, then the whole samples folder
#   - disk used by the project folder and by its .venv
#
# Run it inside the venv:  python3 measure.py

import os
import platform
import resource
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def megabytes_from_maxrss(value):
    # ru_maxrss is in bytes on macOS but in kilobytes on Linux
    if sys.platform == "darwin":
        return value / 1024 / 1024
    return value / 1024


def folder_size_mb(path, skip=None):
    total = 0
    for root, dirs, files in os.walk(path):
        if skip in dirs:
            dirs.remove(skip)
        for name in files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                total += os.path.getsize(full)
    return total / 1024 / 1024


def run(args):
    subprocess.run([sys.executable] + args, cwd=HERE, check=True, stdout=subprocess.DEVNULL)


run(["triage.py", "samples/01_phish_it_helpdesk.eml"])
run(["triage.py", "samples"])

peak = megabytes_from_maxrss(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
project = folder_size_mb(HERE, skip=".venv")
venv_path = os.path.join(HERE, ".venv")
venv = folder_size_mb(venv_path) if os.path.isdir(venv_path) else 0

print("Machine:          ", platform.system(), platform.machine(), "| Python", platform.python_version())
print("Peak memory:      ", round(peak, 1), "MB (largest single process)")
print("Project folder:   ", round(project, 1), "MB (without .venv)")
print(".venv:            ", round(venv, 1), "MB")
print("Total disk:       ", round(project + venv, 1), "MB")
