"""Run fixed security regressions without external HTTP or scanners."""
from pathlib import Path
import unittest

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / 'tests'), pattern='test_security.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
