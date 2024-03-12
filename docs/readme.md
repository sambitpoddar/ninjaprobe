# NinjaProbe Usage Guide

## Setting Up NinjaProbe

Before using NinjaProbe, ensure you have Python installed on your system. Clone the repository from GitHub and install the required dependencies using pip:

```bash
git clone https://github.com/sambitpoddar/ninjaprobe.git
cd ninjaprobe
pip install -r requirements.txt
```

## Customizable Parameters

NinjaProbe allows users to customize various parameters before conducting vulnerability scans:

- **Target URL**: Specify the URL of the website to be scanned.
- **Optional Proxy Settings**: Optionally configure a proxy server to anonymize your requests. Users can choose whether to use a proxy server for their requests. If selected, they need to provide the proxy IP address and port.
- **Tests Selection**: Choose to run all tests or select specific tests based on their numbers.
- **Custom Tests**: Input the numbers of custom tests separated by commas.
- **HTTP and HTTPS Support**: NinjaProbe supports both HTTP and HTTPS websites, allowing users to scan websites with different security configurations.
- **Backdoor File**: Replace the `backdoor.php` file with a file containing actual compromised code for testing insecure file uploads.
- **Scan Results Storage**: After completing the scan, the results get saved into a text file for future reference.

## Running a Vulnerability Scan

To run a vulnerability scan with NinjaProbe, follow these steps:

1. Navigate to the cloned repository directory.
2. Execute the `ninja.py` script with Python:
    ```bash
    python ninja.py
    ```
3. Input the required parameters, such as the target URL and proxy settings (if applicable).
4. Choose whether to run all tests or select custom tests.
5. Review the scan results to identify any vulnerabilities.

## Best Practices

- **Permission**: Ensure you have permission to conduct security tests on the target website.
- **Ethical Use**: Use NinjaProbe for educational purposes and ethical security testing only.
- **Malicious Code**: Replace the `backdoor.php` file with genuine malicious code only for testing purposes.
- **Data Handling**: Handle scan results responsibly and securely. Avoid sharing sensitive information without proper authorization.

## Example Tests

Here are two example tests you can conduct with NinjaProbe:

1. **SQL Injection**: Identify SQL injection vulnerabilities by injecting SQL syntax into URL parameters.
2. **Cross-Site Scripting (XSS)**: Test for XSS vulnerabilities by injecting a script tag into URL parameters.

## Max Workers Configuration

Make sure to configure the number of `max_workers` in the `ThreadPoolExecutor` according to your system's capabilities and the target website's server capacity. The default is 10. Adjusting this parameter can optimize the scan performance and prevent overloading the server.

---
By following these guidelines and examples, you can effectively use NinjaProbe to assess the security posture of your web applications and mitigate potential vulnerabilities.
