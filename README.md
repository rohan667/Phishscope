# PhishScope

**Local phishing-email triage for learning and defensive analysis.** PhishScope reads .eml files, gives each finding a transparent score, defangs URLs/domains for safer ticket handling, hashes attachments without opening or saving them, and suggests analyst follow-up.

It uses Python's standard library. Default analysis is offline: links are never opened, attachments are never executed, and message content is not sent to a service. VirusTotal lookups are an optional, explicit network action for URL and SHA-256 indicators only.

> **Limitations:** This is an educational prototype, not a mail security product. Rule-based scores can miss sophisticated phishing and can flag benign messages. Always verify with trusted mail-gateway evidence. Do not analyze messages you are not authorized to handle.

## Open and run in VS Code

1. Download and unzip the project, then open the **phishscope** folder in VS Code (**File → Open Folder**).
2. Open **Terminal → New Terminal**.
3. Check Python is available: type **python3 --version** on Mac/Linux or **py --version** on Windows. Python 3.9 or later is recommended.
4. Run the bundled example:

   **Mac/Linux**
   ~~~bash
   python3 phishscope.py samples/sample_phish.eml
   ~~~

   **Windows**
   ~~~powershell
   py phishscope.py samples/sample_phish.eml
   ~~~

5. Try the benign sample by changing the file name to samples/sample_benign.eml.

No server needs to be started and no packages need to be installed. Keep .eml files inside the project or provide their full path. Reports are printed in the terminal unless the -o option is used.

## Examples

~~~bash
# Analyze one email; show a Markdown report
python3 phishscope.py samples/sample_phish.eml

# Analyze multiple messages and write a JSON report
python3 phishscope.py samples/sample_phish.eml samples/sample_benign.eml -f json -o results.json

# Exit with code 2 when any email is suspicious or malicious
python3 phishscope.py samples/sample_phish.eml --fail-on suspicious

# Optional VirusTotal lookups of up to ten URLs and attachment hashes
export VT_API_KEY="your-api-key"
python3 phishscope.py samples/sample_phish.eml --enrich
~~~

On Windows PowerShell, set an optional key for the current terminal with:

~~~powershell
$env:VT_API_KEY = "your-api-key"
py phishscope.py samples/sample_phish.eml --enrich
~~~

VirusTotal enrichment sends URL indicators and attachment hashes to VirusTotal. It never uploads attachments or full email bodies. Use it only when your organization's policy permits external lookups. The default mode does not make network requests.

## Scoring

The score is capped at 100. Each rule contributes at most once to an email, even if there are several matching links or attachments.

| Score | Verdict |
|---:|---|
| 0–29 | LIKELY BENIGN |
| 30–59 | SUSPICIOUS |
| 60–100 | LIKELY MALICIOUS |

Every finding includes a rule ID, points, evidence, and (where applicable) a MITRE ATT&CK technique. Current checks include SPF/DKIM/DMARC results from the message's Authentication-Results header, sender and Reply-To/Return-Path mismatches, display-name brand claims, link text mismatch, IP-based links, common URL shorteners, punycode and selected risky TLDs, risky/double-extension attachments, and urgency or credential-request language.

Authentication results are read from the message header; PhishScope does not perform DNS lookups. Domain comparison uses a simple last-two-label heuristic, so domains with public suffixes such as .co.uk need additional handling.

## Project files

~~~text
phishscope/
├── phishscope.py              # Easy command to run from VS Code
├── phishscope/
│   ├── parser.py              # .eml parsing and attachment hashing
│   ├── scoring.py             # Explainable detection rules
│   ├── enrich.py              # Optional VirusTotal read-only lookups
│   ├── report.py              # Markdown and JSON output
│   └── cli.py                 # Arguments and exit codes
├── samples/                   # Synthetic safe demo messages
├── tests/                     # Standard-library unittest suite
└── .github/workflows/ci.yml   # Run tests on pushes and pull requests
~~~

## Tests

Run from this folder:

~~~bash
python3 -m unittest discover -s tests -v
~~~

On Windows use py -m unittest discover -s tests -v.

## Publish to your GitHub repository

Create an empty public GitHub repository named **phishscope**. If your repository already contains a README, use the pull-and-merge instructions from your setup guide before pushing. From the VS Code terminal opened in this folder, the first push to an empty repository is:

~~~bash
git init
git add .
git commit -m "Build PhishScope email triage tool"
git branch -M main
git remote add origin https://github.com/YOUR-GITHUB-USERNAME/phishscope.git
git push -u origin main
~~~

Replace YOUR-GITHUB-USERNAME with your account name. GitHub stores the code and runs the CI tests; it does not run this command-line tool as a public website. Never commit real emails, API keys, secrets, or personal data.

## Safe-use notes

- The bundled .eml files use made-up domains and the documentation IP range 192.0.2.0/24.
- The parser does not follow links, execute attachments, or write attachment contents to disk.
- Output indicators are defanged for safer copying, but still review them before sharing.
- VirusTotal is disabled unless the --enrich option is used with VT_API_KEY.
