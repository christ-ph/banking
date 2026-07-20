#!/usr/bin/env python3
import sys
from datetime import datetime

try:
    import pytest
except ImportError:
    print("pytest non trouvé. Installez-le avec : pip install --break-system-packages pytest pytest-html pytest-flask")
    sys.exit(1)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
report_file = f"rapport_tests_{timestamp}.html"

args = [
    "tests/",
    f"--html={report_file}",
    "--self-contained-html",
    "-v",
    "--tb=short",
    "--maxfail=5"
]

print(f"🚀 Lancement des tests - Rapport : {report_file}")
exit_code = pytest.main(args)

if exit_code == 0:
    print(f"\n✅ Tous les tests ont réussi. Rapport généré : {report_file}")
else:
    print(f"\n❌ Des tests ont échoué. Rapport généré : {report_file}")

sys.exit(exit_code)