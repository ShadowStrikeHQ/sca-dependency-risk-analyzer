# sca-Dependency-Risk-Analyzer
Analyzes a project's software dependencies (using `pip freeze`) and flags dependencies with known vulnerabilities (using `safety` and the CVE database). Outputs a report of vulnerable dependencies and their associated risk scores. - Focused on Tools for assessing the security posture of third-party dependencies and supply chain components. Includes functionalities for identifying known vulnerabilities, license compliance issues, and suspicious code patterns within external libraries.

## Install
`git clone https://github.com/ShadowStrikeHQ/sca-dependency-risk-analyzer`

## Usage
`./sca-dependency-risk-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Path to the requirements.txt file.
- `-o`: Path to the output report file.
- `--ignore`: Comma-separated list of vulnerability IDs to ignore.

## License
Copyright (c) ShadowStrikeHQ
