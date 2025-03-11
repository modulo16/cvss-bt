# cvss-bt-e
Enriching the NVD CVSS scores to include Temporal/Threat Metrics and Environmental Context

## Overview

The Common Vulnerability Scoring System (CVSS) is an industry standard for assessing the severity of computer system security vulnerabilities. CVSS attempts to establish a measure of how severe a vulnerability is based on its attributes.

The National Vulnerability Database includes CVSS Base scores in its catalog, but base scores alone are not enough to effectively prioritize or contextualize vulnerabilities. This repository continuously enriches CVSS scores in three ways:

1. **Base Scores (B)**: The original NVD CVSS base scores
2. **Temporal Metrics (T)**: Using the Exploit Code Maturity/Exploitability (E) Temporal Metric
3. **Environmental Context (E)**: Using OCSF data to provide asset-specific environmental context (optional)

### Temporal Metric - Exploit Code Maturity/Exploitability (E)

Sources:
- https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf
- https://www.first.org/cvss/v3.1/specification-document
- https://www.first.org/cvss/v3.0/specification-