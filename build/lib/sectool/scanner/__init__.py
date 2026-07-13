"""CodeChecker integration: running scans and normalizing their output.

`codechecker.Scanner` drives the three CodeChecker CLI stages (log ->
analyze -> parse) and converts the resulting JSON into `Finding` objects.
`cert_mapping.CertRuleMapper` supplies the checker-name -> SEI CERT rule id
mapping those Finding objects are tagged with.
"""

from sectool.scanner.cert_mapping import CertRuleMapper, CertMappingError
from sectool.scanner.codechecker import Scanner, parse_report_json

__all__ = ["CertRuleMapper", "CertMappingError", "Scanner", "parse_report_json"]
