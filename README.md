[![Python3.11](https://img.shields.io/badge/Python-3.11-green.svg?style=flat-square)](https://www.python.org/downloads/release/python-2714/) 
![OS](https://img.shields.io/badge/Tested%20On-Linux%20|%20Windows%20|%20Android-yellowgreen.svg?style=flat-square)

Ninja Probe is a powerful tool developed to assist developers and security professionals in identifying and mitigating security vulnerabilities present in web applications. With its extensive range of vulnerability tests and user-friendly interface, NinjaProbe makes it easy to perform comprehensive security assessments and strengthen the security posture of web applications.

```
 _   _ _       _        ______          _          
| \ | (_)     (_)       | ___ \        | |         
|  \| |_ _ __  _  __ _  | |_/ / __ ___ | |__   ___ 
|     | |    \| |/ _` | |  __/ '__/ _ \| '_ \ / _ \
| |\  | | | | | | (_| | | |  | | | (_) | |_) |  __/
\_| \_/_|_| |_|_|\__,_| \_|  |_|  \___/|_.__/ \___|
             _/ |                                  
            |__/                                   
+ https://github.com/sambitpoddar/ninjaprobe +
```

## Features

- **Comprehensive Vulnerability Testing:** NinjaProbe offers a wide range of vulnerability tests, including SQL injection, XSS, CSRF, directory traversal, remote code execution, and many more.
- **Customizable Scans:** Users can customize their scans by selecting specific vulnerability tests to run, allowing for targeted assessments based on individual requirements.
- **Proxy Support:** NinjaProbe supports the use of proxies, allowing users to route their scans through proxy servers for enhanced anonymity and network flexibility.
- **Results Reporting:** Vulnerability scan results are presented in a clear and organized manner, making it easy to identify and prioritize remediation efforts.
- **Save Results to File:** Users have the option to save scan results to a text file, providing a convenient way to document findings and share reports with stakeholders.

## List of Vulnerability Tests

| Feature                                     | Description                                                     |
|---------------------------------------------|-----------------------------------------------------------------|
| SQL Injection                               | Injects SQL syntax into URL parameters to detect vulnerabilities |
| Cross-Site Scripting (XSS)                  | Tests for XSS vulnerabilities by injecting script tags          |
| Cross-Site Request Forgery (CSRF)           | Checks for CSRF token presence in responses                     |
| Directory Traversal                         | Attempts to access sensitive files using directory traversal    |
| Remote Code Execution                      | Executes arbitrary code on the server                            |
| Insecure File Upload                       | Uploads a malicious file to detect insecure file upload          |
| Insecure Direct Object References (IDOR)    | Tests for IDOR vulnerabilities in URL parameters                |
| XML External Entities (XXE)                | Checks for XXE vulnerabilities by injecting XML entities        |
| Insecure Cryptographic Implementations     | Identifies insecure cryptographic algorithms or implementations |
| Insecure Deserialization                   | Checks for vulnerabilities related to deserialization           |
| Insecure Redirect                          | Detects insecure redirects in HTTP responses                    |
| Weak Password Policy                       | Tests for weak password policies in login forms                  |
| Sensitive Data Exposure                    | Identifies exposure of sensitive data like API keys or passwords|
| SSL/TLS Issues                             | Checks for SSL/TLS-related vulnerabilities                       |
| Insecure CORS Policy                       | Identifies insecure CORS configurations                          |
| Missing Security Headers                   | Detects absence of security headers like X-Frame-Options         |
| Server-Side Request Forgery (SSRF)         | Tests for SSRF vulnerabilities by sending internal requests     |
| XML Injection                              | Injects XML payloads to detect injection vulnerabilities        |
| File Inclusion                             | Tests for file inclusion vulnerabilities                         |
| OS Command Injection                       | Attempts to execute arbitrary commands on the server            |
| Server-Side Template Injection (SSTI)      | Identifies vulnerabilities related to server-side templates      |
| Server-Side Request (SSR)                 | Tests for SSR vulnerabilities by sending server-side requests   |
| Mass Assignment                            | Checks for mass assignment vulnerabilities in forms              |
| XPath Injection                           | Injects XPath queries to detect injection vulnerabilities        |
| Local File Inclusion (LFI)                | Tests for local file inclusion vulnerabilities                   |
| Clickjacking                              | Identifies clickjacking vulnerabilities                          |
| Insecure Cookies                          | Checks for insecure cookie configurations                         |
| Insecure Login Page                      | Tests for insecure login pages                                    |
| Misconfigured Security Headers          | Identifies misconfigured security headers in HTTP responses       |
| Weak Cryptography                       | Tests for weak cryptographic algorithms or practices              |
| Session Fixation                       | Detects vulnerabilities related to session management             |

## Installation

1. Clone the repository:

```bash
git clone https://github.com/sambitpoddar/ninjaprobe.git
```

2. Navigate to the project directory:

```bash
cd ninjaprobe
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Run the `ninja.py` script:

```bash
python ninja.py
```

2. Follow the on-screen prompts to enter the website URL, choose whether to use a proxy, and select the tests to run.

3. Review the scan results displayed on the console and/or saved in the `vulnerability_scan_results_<date>.txt` file.

## Tests

To run tests for NinjaProbe, execute the `test_ninja.py` file located in the `tests` directory:

```bash
python tests/test_ninja.py
```
## Author
- Email: [sambitpoddar@yahoo.com](mailto:sambitpoddar@yahoo.com)
- LinkedIn: [Sambit Poddar](https://linkedin.com/in/sambitpoddar)

## Contribute

Contributions to Ninja Probe are welcome! If you'd like to contribute to the project, please follow these steps:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with descriptive commit messages.
4. Push your changes to your fork.
5. Submit a pull request to the main repository.

## License

NinjaProbe is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

Ninja Probe is intended for educational purposes only. The use of this tool for any malicious or illegal activities is strictly prohibited. The author of Ninja Probe shall not be liable for any damages or legal consequences resulting from the misuse of this tool.

---

If you find a bug or have a suggestion? [Open an issue](https://github.com/sambitpoddar/ninjaprobe/issues) and let us know!
