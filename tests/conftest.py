# Ensure tests can import project modules when running from repository root
import os
import sys

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
