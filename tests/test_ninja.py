import unittest
from src.ninja import WebsiteVulnerabilityScanner

class TestWebsiteVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        # Initialize WebsiteVulnerabilityScanner with a target URL and proxy settings
        self.scanner = WebsiteVulnerabilityScanner("https://example.com/hello.php", proxy={"http": "", "https": ""})
        # Open the result file in append mode
        self.result_file = open("tests/test_result.txt", "a")       # Sample file doesn't actually records result. Only for sample purpose.

    def tearDown(self):
        # Clean up resources after each test
        self.result_file.close()

    def test_sql_injection(self):
        # Test SQL Injection vulnerability
        result = self.scanner.test_sql_injection("https://example.com/hello.php", 1)
        if result:
            self.result_file.write(result + "\n")

    def test_xss(self):
        # Test Cross-Site Scripting (XSS) vulnerability
        result = self.scanner.test_xss("https://example.com/hello.php", 2)
        if result:
            self.result_file.write(result + "\n")

    def test_csrf(self):
        # Test Cross-Site Request Forgery (CSRF) vulnerability
        result = self.scanner.test_csrf("https://example.com/hello.php", 3)
        if result:
            self.result_file.write(result + "\n")

    # Add other test methods for remaining vulnerabilities if required.

if __name__ == '__main__':
    unittest.main()
