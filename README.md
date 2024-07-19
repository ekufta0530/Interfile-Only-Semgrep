## gin-mongo-nosqli-taint

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query::mongo
- db::source::sql-or-nosql-query::mongo
- web::source::cookie::gin
- web::source::form-data::gin
- web::source::header::gin
- web::source::http-body::gin
- web::source::http-params::gin
- web::source::url-path-params::gin

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- gin
- gin-gonic/gin
- mongo

**Languages:** go

**Mode:** taint



## tainted-flask-http-request-pycurl

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::pycurl
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- flask
- flask-wtf
- pycurl
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-httpx

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::httpx
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- flask
- flask-wtf
- httpx
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-boto3

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::boto3
- net::sink::http-request::botocore
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- boto3
- botocore
- flask
- flask-wtf
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-aiohttp

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::aiohttp
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- aiohttp
- flask
- flask-wtf
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-requests

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::requests
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- flask
- flask-wtf
- requests
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-httplib2

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::httplib2
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- flask
- flask-wtf
- httplib2
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-paramiko

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::paramiko
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- flask
- flask-wtf
- paramiko
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-http-request-urllib3

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::urllib3
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- flask
- flask-wtf
- urllib3
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-path-traversal-stdlib-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fileinput
- file::sink::file-access::io
- file::sink::file-access::linecache
- file::sink::file-access::os
- file::sink::file-access::shutil
- file::sink::file-access::stdlib
- file::sink::file-access::stdlib2
- file::sink::file-access::stdlib3
- file::sink::file-access::tempfile
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- codecs
- fileaccess
- fileinput
- flask
- flask-wtf
- io
- linecache
- os
- shutil
- stdlib
- stdlib2
- stdlib3
- tempfile
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-path-traversal-pillow-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::pillow
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- PIL
- flask
- flask-wtf
- pillow
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-path-traversal-openpyxl-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::openpyxl
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- file
- flask
- flask-wtf
- openpyxl
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-shelve-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::shelve
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- file
- flask
- flask-wtf
- pickle
- shelve
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-path-traversal-toml-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::toml
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- flask
- flask-wtf
- toml
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-path-traversal-fs-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fs
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- flask
- flask-wtf
- fs
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-pickleshare-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::pickleshare
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- file
- flask
- flask-wtf
- pickle
- pickleshare
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-path-traversal-aiofile-flask

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In Flask apps, consider using the Werkzeug util `werkzeug.utils.secure_filename()` to sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::aiofile
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- aiofile
- flask
- flask-wtf
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-code-stdlib-flask

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval::stdlib
- code::sink::eval::stdlib2
- code::sink::eval::stdlib3
- expression-lang::sink::expression::stdlib
- expression-lang::sink::expression::stdlib2
- expression-lang::sink::expression::stdlib3
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://www.stackhawk.com/blog/command-injection-python/

**Technology:**

- flask
- flask-wtf
- stdlib
- stdlib2
- stdlib3
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-regex-stdlib-flask

**Message:** The regular expression identified appears vulnerable to Regular Expression Denial of Service (ReDoS) through catastrophic backtracking. If the input is attacker controllable, this vulnerability can lead to systems being non-responsive or may crash due to ReDoS. Where possible, re-write the regex so as not to leverage backtracking or use a library that offers default protection against ReDoS.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1333: Inefficient Regular Expression Complexity

**Functional-categories:**

- regex::sink::regex::libxml2
- regex::sink::regex::re
- regex::sink::regex::regex
- regex::sink::regex::stdlib
- regex::sink::regex::stdlib2
- regex::sink::regex::stdlib3
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- https://www.regular-expressions.info/catastrophic.html

**Technology:**

- flask
- flask-wtf
- libxml2
- re
- regex
- stdlib
- stdlib2
- stdlib3
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-xml-libxml2

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask
- xml::sink::xml-parser::libxml2
- xml::sink::xpath::libxml2

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://github.com/vingd/libxml2-python/blob/libxml2-python-2.9.1/libxml2.py
- https://gitlab.gnome.org/GNOME/libxml2/-/wikis/Python-bindings
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- flask
- flask-wtf
- libxml2
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-flask-xml-lxml

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask
- xml::sink::xml-parser::lxml
- xml::sink::xpath::lxml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
- https://github.com/lxml/lxml/blob/master/src/lxml/etree.pyx
- https://lxml.de/parsing.html
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

**Technology:**

- flask
- flask-wtf
- lxml,
- web
- wtforms
- xml
- xpath

**Languages:** python

**Mode:** taint



## prompt-injection-flask

**Message:** A prompt is created and user-controlled data reaches that prompt. This can lead to prompt injection. Make sure the user inputs are properly segmented from the system's in your prompts.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)

**Functional-categories:**

- ai::sink::prompt::huggingface
- ai::sink::prompt::langchain
- ai::sink::prompt::openai
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- ai
- flask
- flask-wtf
- huggingface
- langchain
- openai
- web
- wtforms

**Languages:** python

**Mode:** taint



## generic-sql-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. The driver API has the ability to bind parameters to the query in a safe way. Make sure not to dynamically create SQL queries from user-influenced inputs. If you cannot avoid this, either escape the data properly or create an allowlist to check the value.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::aiomysql
- db::sink::sql-or-nosql-query::aiopg
- db::sink::sql-or-nosql-query::mysql-connector
- db::sink::sql-or-nosql-query::mysqldb
- db::sink::sql-or-nosql-query::pep249
- db::sink::sql-or-nosql-query::psycopg2
- db::sink::sql-or-nosql-query::pymssql
- db::sink::sql-or-nosql-query::pymysql
- db::sink::sql-or-nosql-query::pyodbc
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- aiomysql
- aiopg
- db-api
- flask
- flask-wtf
- mssql
- mysql
- mysql-connector
- mysqldb
- pep249
- postgres
- psycopg2
- pymssql
- pymysql
- pyodbc
- sql
- web
- wtforms

**Languages:** python

**Mode:** taint



## sqlalchemy-flask-relationship

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. Don't pass untrusted data to this relationship argument, it's getting passed to `eval`.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A03:2021 - Injection

**References:**

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- flask
- flask-wtf
- sql
- sqlalchemy
- web
- wtforms

**Languages:** python

**Mode:** taint



## ponyorm-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Use generator expressions syntax provided by Pony ORM to build SQL queries instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::ponyorm
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.ponyorm.org/queries.html
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- flask
- flask-wtf
- ponyorm
- sql
- web
- wtforms

**Languages:** python

**Mode:** taint



## sqlobject-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use SQLBuilder instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlobject
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://sqlobject.org/SQLBuilder.html
- https://sqlobject.org/SQLObject.html

**Technology:**

- flask
- flask-wtf
- sql
- sqlobject
- web
- wtforms

**Languages:** python

**Mode:** taint



## pymongo-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::pymongo
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- flask
- flask-wtf
- mongodb
- pymongo
- sql
- web
- wtforms

**Languages:** python

**Mode:** taint



## aiosqlite-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure not to dynamically create SQL queries from user-influenced inputs. If you cannot avoid this, either escape the data properly or create an allowlist to check the value.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::aiosqlite
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://aiosqlite.omnilib.dev/en/stable/api.html
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- aiosqlite
- flask
- flask-wtf
- sql
- sqlite
- web
- wtforms

**Languages:** python

**Mode:** taint



## sqlalchemy-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Use the SQLAlchemy ORM provided functions to build SQL queries instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- flask
- flask-wtf
- sql
- sqlalchemy
- web
- wtforms

**Languages:** python

**Mode:** taint



## sqlobject-connection-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use SQLBuilder instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlobject
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://sqlobject.org/SQLBuilder.html
- https://sqlobject.org/SQLObject.html

**Technology:**

- flask
- flask-wtf
- sql
- sqlobject
- web
- wtforms

**Languages:** python

**Mode:** taint



## peewee-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Peewee provides a query builder which should allow to create the SQL query in a safe way. If you cannot use it, make sure to check the value exists in an allowlist, such that no user-controllable value can influence the eventual SQL query.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::peewee
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- flask
- flask-wtf
- peewee
- sql
- web
- wtforms

**Languages:** python

**Mode:** taint



## sqlalchemy-connection-flask

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- flask
- flask-wtf
- sql
- sqlalchemy
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-log-injection-stdlib-flask

**Message:** Detected a logger that logs user input without properly neutralizing the output. The log message could contain characters like ` ` and ` ` and cause an attacker to forge log entries or include malicious content into the logs. Use proper input validation and/or output encoding to prevent log entries from being forged.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-117: Improper Output Neutralization for Logs

**Functional-categories:**

- log::sink::log::stdlib
- log::sink::log::stdlib2
- log::sink::log::stdlib3
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A09:2021 - Security Logging and Monitoring Failures

**References:**

- https://cwe.mitre.org/data/definitions/117.html
- https://flask.palletsprojects.com/en/2.3.x/logging/
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures

**Technology:**

- flask
- flask-wtf
- log
- logging
- stdlib
- stdlib2
- stdlib3
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-log-injection-log-formatter-flask

**Message:** Detected a logger that logs user input without properly neutralizing the output. The log message could contain characters like ` ` and ` ` and cause an attacker to forge log entries or include malicious content into the logs. Use proper input validation and/or output encoding to prevent log entries from being forged.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-117: Improper Output Neutralization for Logs

**Functional-categories:**

- log::sink::log::flask
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A09:2021 - Security Logging and Monitoring Failures

**References:**

- https://cwe.mitre.org/data/definitions/117.html
- https://flask.palletsprojects.com/en/2.3.x/logging/
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures

**Technology:**

- flask
- flask-wtf
- log
- logging
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-os-command-paramiko-flask

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::paramiko
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.paramiko.org/en/latest/api/client.html#paramiko.client.SSHClient.exec_command
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/

**Technology:**

- flask
- flask-wtf
- paramiko
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-dotenv-variable-flask

**Message:** The application is using variables or data stores that are defined or modified by untrusted input. To prevent this vulnerability perform strict input validation of the data against an allowlist of approved options.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-454: External Initialization of Trusted Variables or Data Stores

**Functional-categories:**

- os::sink::environment::dotenv
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- dotenv
- flask
- flask-wtf
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-os-command-stdlib-flask

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::commands
- os::sink::os-command-or-thread::os
- os::sink::os-command-or-thread::popen2
- os::sink::os-command-or-thread::stdlib
- os::sink::os-command-or-thread::stdlib2
- os::sink::os-command-or-thread::stdlib3
- os::sink::os-command-or-thread::subprocess
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.python.org/3/library/os.html
- https://docs.python.org/3/library/subprocess.html#subprocess.Popen
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/
- https://stackless.readthedocs.io/en/v2.7.16-slp/library/commands.html

**Technology:**

- commands
- flask
- flask-wtf
- os
- popen2
- stdlib
- stdlib2
- stdlib3
- subprocess
- web
- wtforms

**Languages:** python

**Mode:** taint



## active-debug-code-flask

**Message:** The application is running debug code or has debug mode enabled. This may expose sensitive information, like stack traces and environment variables, to attackers. It may also modify application behavior, potentially enabling attackers to bypass restrictions. To remediate this finding, ensure that the application's debug code and debug mode are disabled or removed from the production environment.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-489: Active Debug Code

**Functional-categories:**

- debug::search::active-debug-code

**References:**

- https://flask.palletsprojects.com/en/3.0.x/debugging/

**Technology:**

- flask
- python

**Languages:** python

**Mode:** N/A



## debug-flask-passthrough-errors

**Message:** The application is running debug code or has debug mode enabled. This may expose sensitive information, like stack traces and environment variables, to attackers. It may also modify application behavior, potentially enabling attackers to bypass restrictions. To remediate this finding, ensure that the application's debug code and debug mode are disabled or removed from the production environment.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-489: Active Debug Code

**Functional-categories:**

- debug::search::active-debug-code

**References:**

- https://flask.palletsprojects.com/en/3.0.x/debugging/

**Technology:**

- flask
- python

**Languages:** python

**Mode:** N/A



## tainted-jsonpickle-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `jsonpickle` module can execute arbitrary Python code. Do not load `jsonpickles` from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::jsonpickle
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://github.com/jsonpickle/jsonpickle#jsonpickle
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- flask
- flask-wtf
- jsonpickle
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-torch-pickle-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. A number of functions and packages in the `torch` module rely on the `pickle` module and should not be used to unpackage data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::torch
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/
- https://davidhamann.de/2020/04/05/exploiting-python-pickle/;
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pytorch.org/docs/stable/_modules/torch/distributed/distributed_c10d.html#broadcast_object_list:~:text=.BytesIO()-,_pickler,-(f)
- https://pytorch.org/docs/stable/generated/torch.load.html

**Technology:**

- deserialization
- flask
- flask-wtf
- torch
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-marshal-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `marshal` module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- flask
- flask-wtf
- marhsal
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-ruamel-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. Starting from `ruamel.yaml` version 0.15.0 the default loader (`typ='rt'`) is a direct derivative of the safe loader. Before this version, use the optional argument `Loader` with value `SafeLoader` or `CSafeLoader`, or use the `safe_load` function.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::ruamel
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://yaml.readthedocs.io/en/latest/api/

**Technology:**

- deserialization
- flask
- flask-wtf
- ruamel
- ruamel.yaml
- web
- wtforms
- yaml

**Languages:** python

**Mode:** taint



## tainted-pandas-hdf-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_hdf()` function uses `pickle` when the `fixed` format is used during serializing. This function should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_hdf.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- flask
- flask-wtf
- hdf
- pandas
- pickle
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-pandas-pickle-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_pickle()` function uses `pickle` for object deserialization and should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- flask
- flask-wtf
- pandas
- pickle
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-pyyaml-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. PyYAML's `yaml` module is as powerful as `pickle` and so may call auny Python function. It is recommended to secure your application by using `yaml.SafeLoader` or `yaml.CSafeLoader`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pyyaml
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- flask
- flask-wtf
- pyyaml
- web
- wtforms
- yaml

**Languages:** python

**Mode:** taint



## tainted-numpy-pickle-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `numpy.load()` function allows `pickle` for object deserialization. This behaviour is turned off by default in version 1.16.3. Do not turn this on with `allow_pickle=True` when loading data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::numpy
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://numpy.org/doc/stable/reference/generated/numpy.load.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- flask
- flask-wtf
- numpy
- pickle
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-dill-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `dill` module allows arbitrary user defined classes and functions to be serialized. We do not recommend using it for unpickling data from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::dill
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://dill.readthedocs.io/en/latest/index.html
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pypi.org/project/dill/

**Technology:**

- deserialization
- dill
- flask
- flask-wtf
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-pickle-flask

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The C implementations of the `pickle` module, called `cPickle` or `_pickle`, are also considered insecure.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::flask
- web::source::form-data::flask
- web::source::form-data::flask-wtf
- web::source::form-data::wtforms
- web::source::header::flask
- web::source::http-body::flask
- web::source::http-params::flask
- web::source::url-path-params::flask

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- flask
- flask-wtf
- pickle
- web
- wtforms

**Languages:** python

**Mode:** taint



## tainted-shelve-aws-lambda

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::shelve
- serverless::source::function-params::aws-lambda

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- aws
- aws-lambda
- cloud
- file
- pickle
- serverless
- shelve

**Languages:** python

**Mode:** taint



## tainted-path-traversal-stdlib-aws-lambda

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fileinput
- file::sink::file-access::io
- file::sink::file-access::linecache
- file::sink::file-access::os
- file::sink::file-access::shutil
- file::sink::file-access::stdlib
- file::sink::file-access::stdlib2
- file::sink::file-access::stdlib3
- file::sink::file-access::tempfile
- serverless::source::function-params::aws-lambda

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- aws
- aws-lambda
- cloud
- codecs
- fileaccess
- fileinput
- io
- linecache
- os
- serverless
- shutil
- stdlib
- stdlib2
- stdlib3
- tempfile

**Languages:** python

**Mode:** taint



## tainted-code-stdlib-aws-lambda

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval::stdlib
- code::sink::eval::stdlib2
- code::sink::eval::stdlib3
- expression-lang::sink::expression::stdlib
- expression-lang::sink::expression::stdlib2
- expression-lang::sink::expression::stdlib3
- serverless::source::function-params::aws-lambda

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://www.stackhawk.com/blog/command-injection-python/

**Technology:**

- aws
- aws-lambda
- cloud
- serverless
- stdlib
- stdlib2
- stdlib3

**Languages:** python

**Mode:** taint



## tainted-os-command-stdlib-aws-lambda

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::commands
- os::sink::os-command-or-thread::os
- os::sink::os-command-or-thread::popen2
- os::sink::os-command-or-thread::stdlib
- os::sink::os-command-or-thread::stdlib2
- os::sink::os-command-or-thread::stdlib3
- os::sink::os-command-or-thread::subprocess
- serverless::source::function-params::aws-lambda

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.python.org/3/library/os.html
- https://docs.python.org/3/library/subprocess.html#subprocess.Popen
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/
- https://stackless.readthedocs.io/en/v2.7.16-slp/library/commands.html

**Technology:**

- aws
- aws-lambda
- cloud
- commands
- os
- popen2
- serverless
- stdlib
- stdlib2
- stdlib3
- subprocess

**Languages:** python

**Mode:** taint



## tainted-marshal-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `marshal` module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- marhsal
- serverless

**Languages:** python

**Mode:** taint



## tainted-numpy-pickle-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `numpy.load()` function allows `pickle` for object deserialization. This behaviour is turned off by default in version 1.16.3. Do not turn this on with `allow_pickle=True` when loading data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::numpy
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://numpy.org/doc/stable/reference/generated/numpy.load.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- numpy
- pickle
- serverless

**Languages:** python

**Mode:** taint



## tainted-pyyaml-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. PyYAML's `yaml` module is as powerful as `pickle` and so may call auny Python function. It is recommended to secure your application by using `yaml.SafeLoader` or `yaml.CSafeLoader`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pyyaml
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- pyyaml
- serverless
- yaml

**Languages:** python

**Mode:** taint



## tainted-pandas-hdf-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_hdf()` function uses `pickle` when the `fixed` format is used during serializing. This function should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_hdf.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- hdf
- pandas
- pickle
- serverless

**Languages:** python

**Mode:** taint



## tainted-torch-pickle-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. A number of functions and packages in the `torch` module rely on the `pickle` module and should not be used to unpackage data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::torch
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/
- https://davidhamann.de/2020/04/05/exploiting-python-pickle/;
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pytorch.org/docs/stable/_modules/torch/distributed/distributed_c10d.html#broadcast_object_list:~:text=.BytesIO()-,_pickler,-(f)
- https://pytorch.org/docs/stable/generated/torch.load.html

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- serverless
- torch

**Languages:** python

**Mode:** taint



## tainted-ruamel-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. Starting from `ruamel.yaml` version 0.15.0 the default loader (`typ='rt'`) is a direct derivative of the safe loader. Before this version, use the optional argument `Loader` with value `SafeLoader` or `CSafeLoader`, or use the `safe_load` function.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::ruamel
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://yaml.readthedocs.io/en/latest/api/

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- ruamel
- ruamel.yaml
- serverless
- yaml

**Languages:** python

**Mode:** taint



## tainted-pandas-pickle-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_pickle()` function uses `pickle` for object deserialization and should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- pandas
- pickle
- serverless

**Languages:** python

**Mode:** taint



## tainted-dill-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `dill` module allows arbitrary user defined classes and functions to be serialized. We do not recommend using it for unpickling data from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::dill
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://dill.readthedocs.io/en/latest/index.html
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pypi.org/project/dill/

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- dill
- serverless

**Languages:** python

**Mode:** taint



## tainted-pickle-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The C implementations of the `pickle` module, called `cPickle` or `_pickle`, are also considered insecure.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- pickle
- serverless

**Languages:** python

**Mode:** taint



## tainted-jsonpickle-aws-lambda

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `jsonpickle` module can execute arbitrary Python code. Do not load `jsonpickles` from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::jsonpickle
- serverless::source::function-params::aws-lambda

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://github.com/jsonpickle/jsonpickle#jsonpickle
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- aws
- aws-lambda
- cloud
- deserialization
- jsonpickle
- serverless

**Languages:** python

**Mode:** taint



## tainted-shelve

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::shelve
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- file
- http
- http.server
- pickle
- shelve
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-stdlib

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fileinput
- file::sink::file-access::io
- file::sink::file-access::linecache
- file::sink::file-access::os
- file::sink::file-access::shutil
- file::sink::file-access::stdlib
- file::sink::file-access::stdlib2
- file::sink::file-access::stdlib3
- file::sink::file-access::tempfile
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- codecs
- fileaccess
- fileinput
- http
- http.server
- io
- linecache
- os
- shutil
- stdlib
- stdlib2
- stdlib3
- tempfile
- web

**Languages:** python

**Mode:** taint



## tainted-code-stdlib

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval::stdlib
- code::sink::eval::stdlib2
- code::sink::eval::stdlib3
- expression-lang::sink::expression::stdlib
- expression-lang::sink::expression::stdlib2
- expression-lang::sink::expression::stdlib3
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://www.stackhawk.com/blog/command-injection-python/

**Technology:**

- http
- http.server
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-os-command-stdlib

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::commands
- os::sink::os-command-or-thread::os
- os::sink::os-command-or-thread::popen2
- os::sink::os-command-or-thread::stdlib
- os::sink::os-command-or-thread::stdlib2
- os::sink::os-command-or-thread::stdlib3
- os::sink::os-command-or-thread::subprocess
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.python.org/3/library/os.html
- https://docs.python.org/3/library/subprocess.html#subprocess.Popen
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/
- https://stackless.readthedocs.io/en/v2.7.16-slp/library/commands.html

**Technology:**

- commands
- http
- http.server
- os
- popen2
- stdlib
- stdlib2
- stdlib3
- subprocess
- web

**Languages:** python

**Mode:** taint



## tainted-pandas-hdf

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_hdf()` function uses `pickle` when the `fixed` format is used during serializing. This function should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_hdf.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- hdf
- http
- http.server
- pandas
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-marshal

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `marshal` module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- http
- http.server
- marhsal
- web

**Languages:** python

**Mode:** taint



## tainted-dill

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `dill` module allows arbitrary user defined classes and functions to be serialized. We do not recommend using it for unpickling data from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::dill
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://dill.readthedocs.io/en/latest/index.html
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pypi.org/project/dill/

**Technology:**

- deserialization
- dill
- http
- http.server
- web

**Languages:** python

**Mode:** taint



## tainted-pyyaml

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. PyYAML's `yaml` module is as powerful as `pickle` and so may call auny Python function. It is recommended to secure your application by using `yaml.SafeLoader` or `yaml.CSafeLoader`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pyyaml
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- http
- http.server
- pyyaml
- web
- yaml

**Languages:** python

**Mode:** taint



## tainted-jsonpickle

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `jsonpickle` module can execute arbitrary Python code. Do not load `jsonpickles` from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::jsonpickle
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://github.com/jsonpickle/jsonpickle#jsonpickle
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- http
- http.server
- jsonpickle
- web

**Languages:** python

**Mode:** taint



## tainted-pickle

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The C implementations of the `pickle` module, called `cPickle` or `_pickle`, are also considered insecure.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- http
- http.server
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-ruamel

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. Starting from `ruamel.yaml` version 0.15.0 the default loader (`typ='rt'`) is a direct derivative of the safe loader. Before this version, use the optional argument `Loader` with value `SafeLoader` or `CSafeLoader`, or use the `safe_load` function.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::ruamel
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://yaml.readthedocs.io/en/latest/api/

**Technology:**

- deserialization
- http
- http.server
- ruamel
- ruamel.yaml
- web
- yaml

**Languages:** python

**Mode:** taint



## tainted-numpy-pickle

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `numpy.load()` function allows `pickle` for object deserialization. This behaviour is turned off by default in version 1.16.3. Do not turn this on with `allow_pickle=True` when loading data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::numpy
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://numpy.org/doc/stable/reference/generated/numpy.load.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- http
- http.server
- numpy
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-torch-pickle

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. A number of functions and packages in the `torch` module rely on the `pickle` module and should not be used to unpackage data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::torch
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/
- https://davidhamann.de/2020/04/05/exploiting-python-pickle/;
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pytorch.org/docs/stable/_modules/torch/distributed/distributed_c10d.html#broadcast_object_list:~:text=.BytesIO()-,_pickler,-(f)
- https://pytorch.org/docs/stable/generated/torch.load.html

**Technology:**

- deserialization
- http
- http.server
- torch
- web

**Languages:** python

**Mode:** taint



## tainted-pandas-pickle

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_pickle()` function uses `pickle` for object deserialization and should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::lang
- web::source::form-data::lang
- web::source::header::lang
- web::source::http-body::lang
- web::source::http-params::lang
- web::source::url-path-params::lang

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- http
- http.server
- pandas
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-pycurl

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::pycurl
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- fastapi
- pycurl
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-boto3

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::boto3
- net::sink::http-request::botocore
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- boto3
- botocore
- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-httpx

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::httpx
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- fastapi
- httpx
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-aiohttp

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::aiohttp
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- aiohttp
- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-urllib3

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::urllib3
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- fastapi
- urllib3
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-httplib2

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::httplib2
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- fastapi
- httplib2
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-paramiko

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::paramiko
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- fastapi
- paramiko
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-http-request-requests

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::requests
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- fastapi
- requests
- web

**Languages:** python

**Mode:** taint



## tainted-shelve-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::shelve
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- fastapi
- file
- pickle
- shelve
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-openpyxl-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::openpyxl
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- fastapi
- file
- openpyxl
- web

**Languages:** python

**Mode:** taint



## tainted-pickleshare-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::pickleshare
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- fastapi
- file
- pickle
- pickleshare
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-fs-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fs
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- fastapi
- fs
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fastapi
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-pillow-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::pillow
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- PIL
- fastapi
- pillow
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-aiofile-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::aiofile
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- aiofile
- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-toml-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::toml
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- fastapi
- toml
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-stdlib-fastapi

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. In FastAPI apps, consider using the Starlette `:path` annotation in the route declaration to automatically sanitize paths and filenames.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fileinput
- file::sink::file-access::io
- file::sink::file-access::linecache
- file::sink::file-access::os
- file::sink::file-access::shutil
- file::sink::file-access::stdlib
- file::sink::file-access::stdlib2
- file::sink::file-access::stdlib3
- file::sink::file-access::tempfile
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://fastapi.palletsprojects.com/en/2.3.x/patterns/fileuploads/
- https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://werkzeug.palletsprojects.com/en/3.0.x/utils/#werkzeug.utils.secure_filename

**Technology:**

- codecs
- fastapi
- fileaccess
- fileinput
- io
- linecache
- os
- shutil
- stdlib
- stdlib2
- stdlib3
- tempfile
- web

**Languages:** python

**Mode:** taint



## fastapi-cookie-secure-false

**Message:** Detected a cookie where the `Secure` flag is either missing or disabled. The `Secure` cookie flag instructs the browser to forbid sending the cookie over an insecure HTTP request. Set the `Secure` flag to `true` so the cookie will only be sent over HTTPS.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

**Functional-categories:**

- web::search::cookie-config::fastapi
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- fastapi
- starlette
- web

**Languages:** python

**Mode:** N/A



## tainted-redirect-fastapi

**Message:** The application builds a URL using user-controlled input which can lead to an open redirect vulnerability. An attacker can manipulate the URL and redirect users to an arbitrary domain. Open redirect vulnerabilities can lead to issues such as Cross-site scripting (XSS) or redirecting to a malicious domain for activities such as phishing to capture users' credentials. To prevent this vulnerability perform strict input validation of the domain against an allowlist of approved domains. Notify a user in your application that they are leaving the website. Display a domain where they are redirected to the user. A user can then either accept or deny the redirect to an untrusted site.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

**Functional-categories:**

- web::sink::redirect::fastapi
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2021 - Broken Access Control

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://fastapi.tiangolo.com/uk/reference/responses/?h=redirect#fastapi.responses.RedirectResponse
- https://owasp.org/Top10/A01_2021-Broken_Access_Control

**Technology:**

- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-direct-response-fastapi

**Message:** Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::sink::direct-response::fastapi
- web::sink::html-webpage::fastapi
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A03:2021 - Injection
- A07:2017 - Cross-Site Scripting (XSS)

**References:**

- https://fastapi.tiangolo.com/uk/advanced/custom-response/#htmlresponse
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- web

**Languages:** python

**Mode:** taint



## fastapi-cookie-httponly-false

**Message:** Detected a cookie where the `HttpOnly` flag is either missing or disabled. The `HttpOnly` cookie flag instructs the browser to forbid client-side JavaScript to read the cookie. If JavaScript interaction is required, you can ignore this finding. However, set the `HttpOnly` flag to `true` in all other cases.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

**Functional-categories:**

- web::search::cookie-config::fastapi
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- fastapi
- starlette
- web

**Languages:** python

**Mode:** N/A



## fastapi-cookie-httponly-missing

**Message:** Detected a cookie where the `HttpOnly` flag is either missing or disabled. The `HttpOnly` cookie flag instructs the browser to forbid client-side JavaScript to read the cookie. If JavaScript interaction is required, you can ignore this finding. However, set the `HttpOnly` flag to `true` in all other cases.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

**Functional-categories:**

- web::search::cookie-config::fastapi
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- fastapi
- starlette
- web

**Languages:** python

**Mode:** N/A



## fastapi-cookie-secure-missing

**Message:** Detected a cookie where the `Secure` flag is either missing or disabled. The `Secure` cookie flag instructs the browser to forbid sending the cookie over an insecure HTTP request. Set the `Secure` flag to `true` so the cookie will only be sent over HTTPS.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

**Functional-categories:**

- web::search::cookie-config::fastapi
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- fastapi
- starlette
- web

**Languages:** python

**Mode:** N/A



## fastapi-cookie-samesite-none

**Message:** Detected a cookie options with the `SameSite` flag set to "None". This is a potential security risk that arises from the way web browsers manage cookies. In a typical web application, cookies are used to store and transmit session-related data between a client and a server. To enhance security, cookies can be marked with the "SameSite" attribute, which restricts their usage based on the origin of the page that set them. This attribute can have three values: "Strict," "Lax," or "None". Make sure the `SameSite` attribute of the important cookies (e.g., session cookie) is set to a reasonable value. When `SameSite` is set to "Strict", no 3rd party cookie will be sent with outgoing requests, this is the most secure and private setting but harder to deploy with good usability. Setting it to "Lax" is the minimum requirement.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1275: Sensitive Cookie with Improper SameSite Attribute

**Functional-categories:**

- web::search::cookie-config::fastapi
- web::search::cookie-config::starlette

**Owasp:**

- A01:2021 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://web.dev/articles/samesite-cookies-explained

**Technology:**

- cookie
- cookies
- fastapi
- starlette
- web

**Languages:** python

**Mode:** N/A



## tainted-code-stdlib-fastapi

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval::stdlib
- code::sink::eval::stdlib2
- code::sink::eval::stdlib3
- expression-lang::sink::expression::stdlib
- expression-lang::sink::expression::stdlib2
- expression-lang::sink::expression::stdlib3
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://www.stackhawk.com/blog/command-injection-python/

**Technology:**

- fastapi
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-regex-stdlib-fastapi

**Message:** The regular expression identified appears vulnerable to Regular Expression Denial of Service (ReDoS) through catastrophic backtracking. If the input is attacker controllable, this vulnerability can lead to systems being non-responsive or may crash due to ReDoS. Where possible, re-write the regex so as not to leverage backtracking or use a library that offers default protection against ReDoS.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1333: Inefficient Regular Expression Complexity

**Functional-categories:**

- regex::sink::regex::libxml2
- regex::sink::regex::re
- regex::sink::regex::regex
- regex::sink::regex::stdlib
- regex::sink::regex::stdlib2
- regex::sink::regex::stdlib3
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- https://www.regular-expressions.info/catastrophic.html

**Technology:**

- fastapi
- libxml2
- re
- regex
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-fastapi-xml-lxml

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi
- xml::sink::xml-parser::lxml
- xml::sink::xpath::lxml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
- https://github.com/lxml/lxml/blob/master/src/lxml/etree.pyx
- https://lxml.de/parsing.html
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

**Technology:**

- fastapi
- lxml,
- web
- xml
- xpath

**Languages:** python

**Mode:** taint



## tainted-fastapi-xml-libxml2

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi
- xml::sink::xml-parser::libxml2
- xml::sink::xpath::libxml2

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://github.com/vingd/libxml2-python/blob/libxml2-python-2.9.1/libxml2.py
- https://gitlab.gnome.org/GNOME/libxml2/-/wikis/Python-bindings
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- fastapi
- libxml2
- web

**Languages:** python

**Mode:** taint



## prompt-injection-fastapi

**Message:** A prompt is created and user-controlled data reaches that prompt. This can lead to prompt injection. Make sure the user inputs are properly segmented from the system's in your prompts.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)

**Functional-categories:**

- ai::sink::prompt::huggingface
- ai::sink::prompt::langchain
- ai::sink::prompt::openai
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- ai
- fastapi
- huggingface
- langchain
- openai
- web

**Languages:** python

**Mode:** taint



## ponyorm-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Use generator expressions syntax provided by Pony ORM to build SQL queries instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::ponyorm
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.ponyorm.org/queries.html
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- ponyorm
- sql
- web

**Languages:** python

**Mode:** taint



## generic-sql-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. The driver API has the ability to bind parameters to the query in a safe way. Make sure not to dynamically create SQL queries from user-influenced inputs. If you cannot avoid this, either escape the data properly or create an allowlist to check the value.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::aiomysql
- db::sink::sql-or-nosql-query::aiopg
- db::sink::sql-or-nosql-query::mysql-connector
- db::sink::sql-or-nosql-query::mysqldb
- db::sink::sql-or-nosql-query::pep249
- db::sink::sql-or-nosql-query::psycopg2
- db::sink::sql-or-nosql-query::pymssql
- db::sink::sql-or-nosql-query::pymysql
- db::sink::sql-or-nosql-query::pyodbc
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- aiomysql
- aiopg
- db-api
- fastapi
- mssql
- mysql
- mysql-connector
- mysqldb
- pep249
- postgres
- psycopg2
- pymssql
- pymysql
- pyodbc
- sql
- web

**Languages:** python

**Mode:** taint



## pymongo-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::pymongo
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- mongodb
- pymongo
- sql
- web

**Languages:** python

**Mode:** taint



## peewee-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Peewee provides a query builder which should allow to create the SQL query in a safe way. If you cannot use it, make sure to check the value exists in an allowlist, such that no user-controllable value can influence the eventual SQL query.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::peewee
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- peewee
- sql
- web

**Languages:** python

**Mode:** taint



## sqlobject-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use SQLBuilder instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlobject
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://sqlobject.org/SQLBuilder.html
- https://sqlobject.org/SQLObject.html

**Technology:**

- fastapi
- sql
- sqlobject
- web

**Languages:** python

**Mode:** taint



## sqlalchemy-connection-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- sql
- sqlalchemy
- web

**Languages:** python

**Mode:** taint



## sqlalchemy-fastapi-relationship

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. Don't pass untrusted data to this relationship argument, it's getting passed to `eval`.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A03:2021 - Injection

**References:**

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- sql
- sqlalchemy
- web

**Languages:** python

**Mode:** taint



## sqlalchemy-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Use the SQLAlchemy ORM provided functions to build SQL queries instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- fastapi
- sql
- sqlalchemy
- web

**Languages:** python

**Mode:** taint



## sqlobject-connection-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use SQLBuilder instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlobject
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://sqlobject.org/SQLBuilder.html
- https://sqlobject.org/SQLObject.html

**Technology:**

- fastapi
- sql
- sqlobject
- web

**Languages:** python

**Mode:** taint



## aiosqlite-fastapi

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure not to dynamically create SQL queries from user-influenced inputs. If you cannot avoid this, either escape the data properly or create an allowlist to check the value.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::aiosqlite
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://aiosqlite.omnilib.dev/en/stable/api.html
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- aiosqlite
- fastapi
- sql
- sqlite
- web

**Languages:** python

**Mode:** taint



## tainted-log-injection-stdlib-fastapi

**Message:** Detected a logger that logs user input without properly neutralizing the output. The log message could contain characters like ` ` and ` ` and cause an attacker to forge log entries or include malicious content into the logs. Use proper input validation and/or output encoding to prevent log entries from being forged.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-117: Improper Output Neutralization for Logs

**Functional-categories:**

- log::sink::log::stdlib
- log::sink::log::stdlib2
- log::sink::log::stdlib3
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A09:2021 - Security Logging and Monitoring Failures

**References:**

- https://cwe.mitre.org/data/definitions/117.html
- https://fastapi.palletsprojects.com/en/2.3.x/logging/
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures

**Technology:**

- fastapi
- log
- logging
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-os-command-stdlib-fastapi

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::commands
- os::sink::os-command-or-thread::os
- os::sink::os-command-or-thread::popen2
- os::sink::os-command-or-thread::stdlib
- os::sink::os-command-or-thread::stdlib2
- os::sink::os-command-or-thread::stdlib3
- os::sink::os-command-or-thread::subprocess
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.python.org/3/library/os.html
- https://docs.python.org/3/library/subprocess.html#subprocess.Popen
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/
- https://stackless.readthedocs.io/en/v2.7.16-slp/library/commands.html

**Technology:**

- commands
- fastapi
- os
- popen2
- stdlib
- stdlib2
- stdlib3
- subprocess
- web

**Languages:** python

**Mode:** taint



## tainted-dotenv-variable-fastapi

**Message:** The application is using variables or data stores that are defined or modified by untrusted input. To prevent this vulnerability perform strict input validation of the data against an allowlist of approved options.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-454: External Initialization of Trusted Variables or Data Stores

**Functional-categories:**

- os::sink::environment::dotenv
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- dotenv
- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-os-command-paramiko-fastapi

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::paramiko
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.paramiko.org/en/latest/api/client.html#paramiko.client.SSHClient.exec_command
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/

**Technology:**

- fastapi
- paramiko
- web

**Languages:** python

**Mode:** taint



## tainted-dill-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `dill` module allows arbitrary user defined classes and functions to be serialized. We do not recommend using it for unpickling data from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::dill
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://dill.readthedocs.io/en/latest/index.html
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pypi.org/project/dill/

**Technology:**

- deserialization
- dill
- fastapi
- web

**Languages:** python

**Mode:** taint



## tainted-ruamel-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. Starting from `ruamel.yaml` version 0.15.0 the default loader (`typ='rt'`) is a direct derivative of the safe loader. Before this version, use the optional argument `Loader` with value `SafeLoader` or `CSafeLoader`, or use the `safe_load` function.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::ruamel
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://yaml.readthedocs.io/en/latest/api/

**Technology:**

- deserialization
- fastapi
- ruamel
- ruamel.yaml
- web
- yaml

**Languages:** python

**Mode:** taint



## tainted-torch-pickle-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. A number of functions and packages in the `torch` module rely on the `pickle` module and should not be used to unpackage data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::torch
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/
- https://davidhamann.de/2020/04/05/exploiting-python-pickle/;
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pytorch.org/docs/stable/_modules/torch/distributed/distributed_c10d.html#broadcast_object_list:~:text=.BytesIO()-,_pickler,-(f)
- https://pytorch.org/docs/stable/generated/torch.load.html

**Technology:**

- deserialization
- fastapi
- torch
- web

**Languages:** python

**Mode:** taint



## tainted-pandas-hdf-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_hdf()` function uses `pickle` when the `fixed` format is used during serializing. This function should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_hdf.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- fastapi
- hdf
- pandas
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-marshal-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `marshal` module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- fastapi
- marhsal
- web

**Languages:** python

**Mode:** taint



## tainted-pandas-pickle-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_pickle()` function uses `pickle` for object deserialization and should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- fastapi
- pandas
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-pickle-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The C implementations of the `pickle` module, called `cPickle` or `_pickle`, are also considered insecure.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- fastapi
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-numpy-pickle-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `numpy.load()` function allows `pickle` for object deserialization. This behaviour is turned off by default in version 1.16.3. Do not turn this on with `allow_pickle=True` when loading data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::numpy
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://numpy.org/doc/stable/reference/generated/numpy.load.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- fastapi
- numpy
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-pyyaml-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. PyYAML's `yaml` module is as powerful as `pickle` and so may call auny Python function. It is recommended to secure your application by using `yaml.SafeLoader` or `yaml.CSafeLoader`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pyyaml
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- fastapi
- pyyaml
- web
- yaml

**Languages:** python

**Mode:** taint



## tainted-jsonpickle-fastapi

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `jsonpickle` module can execute arbitrary Python code. Do not load `jsonpickles` from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::jsonpickle
- web::source::cookie::fastapi
- web::source::form-data::fastapi
- web::source::header::fastapi
- web::source::http-body::fastapi
- web::source::http-params::fastapi
- web::source::url-path-params::fastapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://github.com/jsonpickle/jsonpickle#jsonpickle
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- fastapi
- jsonpickle
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-boto3

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::boto3
- net::sink::http-request::botocore
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- boto3
- botocore
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-httpx

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::httpx
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- django_rest_frameworkapi
- httpx
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-aiohttp

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::aiohttp
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- aiohttp
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-requests

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::requests
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- django_rest_frameworkapi
- requests
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-httplib2

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::httplib2
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- django_rest_frameworkapi
- httplib2
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-paramiko

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::paramiko
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- django_rest_frameworkapi
- paramiko
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-urllib3

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::urllib3
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- django_rest_frameworkapi
- urllib3
- web

**Languages:** python

**Mode:** taint



## tainted-django-http-request-pycurl

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::pycurl
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- django_rest_frameworkapi
- pycurl
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-pillow-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::pillow
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- PIL
- django_rest_frameworkapi
- pillow
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-fs-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fs
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- django_rest_frameworkapi
- fs
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-toml-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::toml
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- django_rest_frameworkapi
- toml
- web

**Languages:** python

**Mode:** taint



## tainted-filename-response-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::django
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- django
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## tainted-shelve-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::shelve
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- django_rest_frameworkapi
- file
- pickle
- shelve
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-stdlib-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::fileinput
- file::sink::file-access::io
- file::sink::file-access::linecache
- file::sink::file-access::os
- file::sink::file-access::shutil
- file::sink::file-access::stdlib
- file::sink::file-access::stdlib2
- file::sink::file-access::stdlib3
- file::sink::file-access::tempfile
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- codecs
- django_rest_frameworkapi
- fileaccess
- fileinput
- io
- linecache
- os
- shutil
- stdlib
- stdlib2
- stdlib3
- tempfile
- web

**Languages:** python

**Mode:** taint



## tainted-pickleshare-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::pickleshare
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- django_rest_frameworkapi
- file
- pickle
- pickleshare
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-openpyxl-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::openpyxl
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://docs.pyfilesystem.org/en/latest/guide.html#opening-filesystems
- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- django_rest_frameworkapi
- file
- openpyxl
- web

**Languages:** python

**Mode:** taint



## tainted-path-traversal-aiofile-django

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::aiofile
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/

**Technology:**

- aiofile
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## django-cookie-samesite-missing

**Message:** Detected a cookie options with the `SameSite` flag set to "None". This is a potential security risk that arises from the way web browsers manage cookies. In a typical web application, cookies are used to store and transmit session-related data between a client and a server. To enhance security, cookies can be marked with the "SameSite" attribute, which restricts their usage based on the origin of the page that set them. This attribute can have three values: "Strict," "Lax," or "None". Make sure the `SameSite` attribute of the important cookies (e.g., session cookie) is set to a reasonable value. When `SameSite` is set to "Strict", no 3rd party cookie will be sent with outgoing requests, this is the most secure and private setting but harder to deploy with good usability. Setting it to "Lax" is the minimum requirement.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1275: Sensitive Cookie with Improper SameSite Attribute

**Functional-categories:**

- web::search::cookie-config::django
- web::search::cookie-config::starlette

**Owasp:**

- A01:2021 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://web.dev/articles/samesite-cookies-explained

**Technology:**

- cookie
- cookies
- django
- web

**Languages:** python

**Mode:** N/A



## django-cookie-httponly-false

**Message:** Detected a cookie where the `HttpOnly` flag is either missing or disabled. The `HttpOnly` cookie flag instructs the browser to forbid client-side JavaScript to read the cookie. If JavaScript interaction is required, you can ignore this finding. However, set the `HttpOnly` flag to `true` in all other cases.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

**Functional-categories:**

- web::search::cookie-config::django
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- django
- web

**Languages:** python

**Mode:** N/A



## django-cookie-httponly-missing

**Message:** Detected a cookie where the `HttpOnly` flag is either missing or disabled. The `HttpOnly` cookie flag instructs the browser to forbid client-side JavaScript to read the cookie. If JavaScript interaction is required, you can ignore this finding. However, set the `HttpOnly` flag to `true` in all other cases.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag

**Functional-categories:**

- web::search::cookie-config::django
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- django
- web

**Languages:** python

**Mode:** N/A



## tainted-direct-response-django

**Message:** Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::sink::direct-response::django
- web::sink::html-webpage::django
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A03:2021 - Injection
- A07:2017 - Cross-Site Scripting (XSS)

**References:**

- https://docs.djangoproject.com/en/5.0/ref/request-response/#httpresponse-objects
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## django-cookie-secure-missing

**Message:** Detected a cookie where the `Secure` flag is either missing or disabled. The `Secure` cookie flag instructs the browser to forbid sending the cookie over an insecure HTTP request. Set the `Secure` flag to `true` so the cookie will only be sent over HTTPS.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

**Functional-categories:**

- web::search::cookie-config::django
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- django
- web

**Languages:** python

**Mode:** N/A



## django-cookie-samesite-none

**Message:** Detected a cookie options with the `SameSite` flag set to "None". This is a potential security risk that arises from the way web browsers manage cookies. In a typical web application, cookies are used to store and transmit session-related data between a client and a server. To enhance security, cookies can be marked with the "SameSite" attribute, which restricts their usage based on the origin of the page that set them. This attribute can have three values: "Strict," "Lax," or "None". Make sure the `SameSite` attribute of the important cookies (e.g., session cookie) is set to a reasonable value. When `SameSite` is set to "Strict", no 3rd party cookie will be sent with outgoing requests, this is the most secure and private setting but harder to deploy with good usability. Setting it to "Lax" is the minimum requirement.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1275: Sensitive Cookie with Improper SameSite Attribute

**Functional-categories:**

- web::search::cookie-config::django
- web::search::cookie-config::starlette

**Owasp:**

- A01:2021 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://web.dev/articles/samesite-cookies-explained

**Technology:**

- cookie
- cookies
- django
- web

**Languages:** python

**Mode:** N/A



## tainted-redirect-django

**Message:** The application builds a URL using user-controlled input which can lead to an open redirect vulnerability. An attacker can manipulate the URL and redirect users to an arbitrary domain. Open redirect vulnerabilities can lead to issues such as Cross-site scripting (XSS) or redirecting to a malicious domain for activities such as phishing to capture users' credentials. To prevent this vulnerability perform strict input validation of the domain against an allowlist of approved domains. Notify a user in your application that they are leaving the website. Display a domain where they are redirected to the user. A user can then either accept or deny the redirect to an untrusted site.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

**Functional-categories:**

- web::sink::redirect::django
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2021 - Broken Access Control

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://docs.djangoproject.com/en/5.0/ref/request-response/#django.http.HttpResponseRedirect
- https://docs.djangoproject.com/en/5.0/ref/urlresolvers/#reverse
- https://docs.djangoproject.com/en/5.0/topics/http/shortcuts/#redirect
- https://owasp.org/Top10/A01_2021-Broken_Access_Control

**Technology:**

- django
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## django-cookie-secure-false

**Message:** Detected a cookie where the `Secure` flag is either missing or disabled. The `Secure` cookie flag instructs the browser to forbid sending the cookie over an insecure HTTP request. Set the `Secure` flag to `true` so the cookie will only be sent over HTTPS.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** LOW

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

**Functional-categories:**

- web::search::cookie-config::django
- web::search::cookie-config::starlette

**Owasp:**

- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- cookie
- cookies
- django
- web

**Languages:** python

**Mode:** N/A



## tainted-code-stdlib-django

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval::stdlib
- code::sink::eval::stdlib2
- code::sink::eval::stdlib3
- expression-lang::sink::expression::stdlib
- expression-lang::sink::expression::stdlib2
- expression-lang::sink::expression::stdlib3
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://www.stackhawk.com/blog/command-injection-python/

**Technology:**

- django_rest_frameworkapi
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-regex-stdlib-django

**Message:** The regular expression identified appears vulnerable to Regular Expression Denial of Service (ReDoS) through catastrophic backtracking. If the input is attacker controllable, this vulnerability can lead to systems being non-responsive or may crash due to ReDoS. Where possible, re-write the regex so as not to leverage backtracking or use a library that offers default protection against ReDoS.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-1333: Inefficient Regular Expression Complexity

**Functional-categories:**

- regex::sink::regex::libxml2
- regex::sink::regex::re
- regex::sink::regex::regex
- regex::sink::regex::stdlib
- regex::sink::regex::stdlib2
- regex::sink::regex::stdlib3
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- https://www.regular-expressions.info/catastrophic.html

**Technology:**

- django_rest_frameworkapi
- libxml2
- re
- regex
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-django-xml-libxml2

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi
- xml::sink::xml-parser::libxml2
- xml::sink::xpath::libxml2

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://github.com/vingd/libxml2-python/blob/libxml2-python-2.9.1/libxml2.py
- https://gitlab.gnome.org/GNOME/libxml2/-/wikis/Python-bindings
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- django_rest_frameworkapi
- libxml2
- web

**Languages:** python

**Mode:** taint



## tainted-django-xml-lxml

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi
- xml::sink::xml-parser::lxml
- xml::sink::xpath::lxml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
- https://github.com/lxml/lxml/blob/master/src/lxml/etree.pyx
- https://lxml.de/parsing.html
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

**Technology:**

- django_rest_frameworkapi
- lxml,
- web
- xml
- xpath

**Languages:** python

**Mode:** taint



## prompt-injection-django

**Message:** A prompt is created and user-controlled data reaches that prompt. This can lead to prompt injection. Make sure the user inputs are properly segmented from the system's in your prompts.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-75: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)

**Functional-categories:**

- ai::sink::prompt::huggingface
- ai::sink::prompt::langchain
- ai::sink::prompt::openai
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- ai
- django_rest_frameworkapi
- huggingface
- langchain
- openai
- web

**Languages:** python

**Mode:** taint



## sqlalchemy-connection-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- sql
- sqlalchemy
- web

**Languages:** python

**Mode:** taint



## ponyorm-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Use generator expressions syntax provided by Pony ORM to build SQL queries instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::ponyorm
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.ponyorm.org/queries.html
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- ponyorm
- sql
- web

**Languages:** python

**Mode:** taint



## aiosqlite-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure not to dynamically create SQL queries from user-influenced inputs. If you cannot avoid this, either escape the data properly or create an allowlist to check the value.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::aiosqlite
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://aiosqlite.omnilib.dev/en/stable/api.html
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- aiosqlite
- django_rest_frameworkapi
- sql
- sqlite
- web

**Languages:** python

**Mode:** taint



## generic-sql-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. The driver API has the ability to bind parameters to the query in a safe way. Make sure not to dynamically create SQL queries from user-influenced inputs. If you cannot avoid this, either escape the data properly or create an allowlist to check the value.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::aiomysql
- db::sink::sql-or-nosql-query::aiopg
- db::sink::sql-or-nosql-query::mysql-connector
- db::sink::sql-or-nosql-query::mysqldb
- db::sink::sql-or-nosql-query::pep249
- db::sink::sql-or-nosql-query::psycopg2
- db::sink::sql-or-nosql-query::pymssql
- db::sink::sql-or-nosql-query::pymysql
- db::sink::sql-or-nosql-query::pyodbc
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Release:** alpha

**Technology:**

- aiomysql
- aiopg
- db-api
- django_rest_frameworkapi
- mssql
- mysql
- mysql-connector
- mysqldb
- pep249
- postgres
- psycopg2
- pymssql
- pymysql
- pyodbc
- sql
- web

**Languages:** python

**Mode:** taint



## peewee-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Peewee provides a query builder which should allow to create the SQL query in a safe way. If you cannot use it, make sure to check the value exists in an allowlist, such that no user-controllable value can influence the eventual SQL query.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::peewee
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- peewee
- sql
- web

**Languages:** python

**Mode:** taint



## sqlobject-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use SQLBuilder instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlobject
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://sqlobject.org/SQLBuilder.html
- https://sqlobject.org/SQLObject.html

**Technology:**

- django_rest_frameworkapi
- sql
- sqlobject
- web

**Languages:** python

**Mode:** taint



## sqlobject-connection-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use SQLBuilder instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlobject
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://sqlobject.org/SQLBuilder.html
- https://sqlobject.org/SQLObject.html

**Technology:**

- django_rest_frameworkapi
- sql
- sqlobject
- web

**Languages:** python

**Mode:** taint



## djangoorm-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Don’t manually concatenate values to a query, use query parameterization instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::django
- db::sink::sql-or-nosql-query::djangoorm
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.djangoproject.com/en/5.0/topics/db/sql/
- https://docs.djangoproject.com/en/5.0/topics/security/#sql-injection-protection
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django
- django_rest_frameworkapi
- djangoorm
- sql
- web

**Languages:** python

**Mode:** taint



## sqlalchemy-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Use the SQLAlchemy ORM provided functions to build SQL queries instead to avoid SQL injection.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- sql
- sqlalchemy
- web

**Languages:** python

**Mode:** taint



## sqlalchemy-django-relationship

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. Don't pass untrusted data to this relationship argument, it's getting passed to `eval`.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::sqlalchemy
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A03:2021 - Injection

**References:**

- https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- sql
- sqlalchemy
- web

**Languages:** python

**Mode:** taint



## pymongo-django

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::pymongo
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- mongodb
- pymongo
- sql
- web

**Languages:** python

**Mode:** taint



## tainted-log-injection-stdlib-django

**Message:** Detected a logger that logs user input without properly neutralizing the output. The log message could contain characters like ` ` and ` ` and cause an attacker to forge log entries or include malicious content into the logs. Use proper input validation and/or output encoding to prevent log entries from being forged.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-117: Improper Output Neutralization for Logs

**Functional-categories:**

- log::sink::log::stdlib
- log::sink::log::stdlib2
- log::sink::log::stdlib3
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A09:2021 - Security Logging and Monitoring Failures

**References:**

- https://cwe.mitre.org/data/definitions/117.html
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures

**Technology:**

- django_rest_frameworkapi
- log
- logging
- stdlib
- stdlib2
- stdlib3
- web

**Languages:** python

**Mode:** taint



## tainted-os-command-paramiko-django

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::paramiko
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://docs.paramiko.org/en/latest/api/client.html#paramiko.client.SSHClient.exec_command
- https://owasp.org/Top10/A03_2021-Injection
- https://semgrep.dev/docs/cheat-sheets/python-command-injection/

**Technology:**

- django_rest_frameworkapi
- paramiko
- web

**Languages:** python

**Mode:** taint



## tainted-dotenv-variable-django

**Message:** The application is using variables or data stores that are defined or modified by untrusted input. To prevent this vulnerability perform strict input validation of the data against an allowlist of approved options.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-454: External Initialization of Trusted Variables or Data Stores

**Functional-categories:**

- os::sink::environment::dotenv
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- django_rest_frameworkapi
- dotenv
- web

**Languages:** python

**Mode:** taint



## tainted-jsonpickle-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `jsonpickle` module can execute arbitrary Python code. Do not load `jsonpickles` from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::jsonpickle
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://github.com/jsonpickle/jsonpickle#jsonpickle
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- django_rest_frameworkapi
- jsonpickle
- web

**Languages:** python

**Mode:** taint



## tainted-ruamel-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. Starting from `ruamel.yaml` version 0.15.0 the default loader (`typ='rt'`) is a direct derivative of the safe loader. Before this version, use the optional argument `Loader` with value `SafeLoader` or `CSafeLoader`, or use the `safe_load` function.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::ruamel
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://yaml.readthedocs.io/en/latest/api/

**Technology:**

- deserialization
- django_rest_frameworkapi
- ruamel
- ruamel.yaml
- web
- yaml

**Languages:** python

**Mode:** taint



## tainted-pyyaml-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. PyYAML's `yaml` module is as powerful as `pickle` and so may call auny Python function. It is recommended to secure your application by using `yaml.SafeLoader` or `yaml.CSafeLoader`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pyyaml
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://cwe.mitre.org/data/definitions/502.html
- https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://nvd.nist.gov/vuln/detail/CVE-2017-18342
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- django_rest_frameworkapi
- pyyaml
- web
- yaml

**Languages:** python

**Mode:** taint



## tainted-marshal-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `marshal` module is not intended to be secure against erroneous or maliciously constructed data. Never unmarshal data received from an untrusted or unauthenticated source. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections, such as json, PyYAML, or ruamel.yaml.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- django_rest_frameworkapi
- marhsal
- web

**Languages:** python

**Mode:** taint



## tainted-pandas-hdf-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_hdf()` function uses `pickle` when the `fixed` format is used during serializing. This function should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_hdf.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- django_rest_frameworkapi
- hdf
- pandas
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-numpy-pickle-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `numpy.load()` function allows `pickle` for object deserialization. This behaviour is turned off by default in version 1.16.3. Do not turn this on with `allow_pickle=True` when loading data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::numpy
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/marshal.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://numpy.org/doc/stable/reference/generated/numpy.load.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- django_rest_frameworkapi
- numpy
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-pandas-pickle-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `pandas.read_pickle()` function uses `pickle` for object deserialization and should not be used with untrusted data.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::pandas
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_python.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://pandas.pydata.org/docs/reference/api/pandas.read_pickle.html
- https://portswigger.net/web-security/deserialization
- https://redfoxsec.com/blog/insecure-deserialization-in-python/
- https://www.exploit-db.com/exploits/49585

**Technology:**

- deserialization
- django_rest_frameworkapi
- pandas
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-pickle-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The C implementations of the `pickle` module, called `cPickle` or `_pickle`, are also considered insecure.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::lang
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization

**Technology:**

- deserialization
- django_rest_frameworkapi
- pickle
- web

**Languages:** python

**Mode:** taint



## tainted-dill-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. The `dill` module allows arbitrary user defined classes and functions to be serialized. We do not recommend using it for unpickling data from untrusted sources. For deserializing data from untrusted sources we recommend using YAML or JSON libraries with built-in protections.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::dill
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://davidhamann.de/2020/04/05/exploiting-python-pickle/
- https://dill.readthedocs.io/en/latest/index.html
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pypi.org/project/dill/

**Technology:**

- deserialization
- dill
- django_rest_frameworkapi
- web

**Languages:** python

**Mode:** taint



## tainted-torch-pickle-django

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. A number of functions and packages in the `torch` module rely on the `pickle` module and should not be used to unpackage data from untrusted sources.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::torch
- web::source::cookie::django_rest_frameworkapi
- web::source::form-data::django_rest_frameworkapi
- web::source::header::django_rest_frameworkapi
- web::source::http-body::django_rest_frameworkapi
- web::source::http-params::django_rest_frameworkapi
- web::source::url-path-params::django_rest_frameworkapi

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/
- https://davidhamann.de/2020/04/05/exploiting-python-pickle/;
- https://docs.python.org/3/library/pickle.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://portswigger.net/web-security/deserialization
- https://pytorch.org/docs/stable/_modules/torch/distributed/distributed_c10d.html#broadcast_object_list:~:text=.BytesIO()-,_pickler,-(f)
- https://pytorch.org/docs/stable/generated/torch.load.html

**Technology:**

- deserialization
- django_rest_frameworkapi
- torch
- web

**Languages:** python

**Mode:** taint



## tainted-code-injection-from-http-request-deepsemgrep

**Message:** User data flows into a script engine or another means of dynamic code evaluation. This is unsafe and could lead to code injection or arbitrary code execution as a result. Avoid inputting user data into code execution or use proper sandboxing if user code evaluation is necessary.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

**Functional-categories:**

- expression-lang::sink::expression::commons-jexl
- expression-lang::sink::expression::javax.el
- expression-lang::sink::expression::javax.script
- expression-lang::sink::expression::velocity
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## tainted-ssrf-deepsemgrep-format

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## tainted-xml-decoder-deepsemgrep

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet
- xml::sink::xml-parser::java.beans

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## tainted-session-from-http-request-deepsemgrep

**Message:** Mixing trusted and untrusted data within the same structure can lead to trust boundary violations, where unvalidated data is mistakenly trusted, potentially bypassing security mechanisms. Thoroughly sanitize user input before passing it into such function calls.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-501: Trust Boundary Violation

**Functional-categories:**

- web::sink::session-properties::Servlet
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A04:2021 - Insecure Design

**References:**

- https://owasp.org/Top10/A04_2021-Insecure_Design

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## servletresponse-writer-xss-deepsemgrep

**Message:** Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::sink::direct-response::Spring
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A03:2021 - Injection
- A07:2017 - Cross-Site Scripting (XSS)

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## tainted-ssrf-deepsemgrep-add

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## httpservlet-path-traversal-deepsemgrep

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## objectinputstream-deserialization-servlets

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `ObjectInputStream`. If you must, you can try overriding the `ObjectInputStream#resolveClass()` method or using a safe replacement for the generic `readObject()` method.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::apache.commons
- deserialization::sink::load-object::java.io
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## kryo-deserialization-deepsemgrep

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `Kryo` unless you explicitly define permissions for types that are allowed to be deserialized by `Kryo`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::kryo
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://github.com/EsotericSoftware/kryo
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- java
- kryo
- servlets
- xml

**Languages:** java

**Mode:** taint



## castor-deserialization-deepsemgrep

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the Castor XML Framework unless you explicitly define permissions for types that are allowed to be deserialized by `Castor`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::castor
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://castor-data-binding.github.io/castor/reference-guide/reference/xml/xml-framework.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## xstream-anytype-deserialization-deepsemgrep

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `XStream` unless you explicitly define permissions for types that are allowed to be deserialized by `XStream`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::xstream
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://x-stream.github.io/security.html

**Technology:**

- java
- servlets
- xml
- xstream

**Languages:** java

**Mode:** taint



## tainted-xpath-from-http-request-deepsemgrep

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet
- xml::sink::xpath::javax.xml

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## tainted-cmd-from-http-request-deepsemgrep

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. For more information, see: [Java command injection prevention](https://semgrep.dev/docs/cheat-sheets/java-command-injection/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## tainted-ldapi-from-http-request-deepsemgrep

**Message:** Untrusted input might be used to build an LDAP query, which can allow attackers to run arbitrary LDAP queries. If an LDAP query must contain untrusted input then it must be escaped. Ensure data passed to an LDAP query is not controllable or properly sanitize the user input with functions like createEqualityFilter.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

**Functional-categories:**

- ldap::sink::ldap-query::javax.naming
- web::source::cookie::Servlet
- web::source::header::Servlet
- web::source::http-body::Servlet
- web::source::http-params::Servlet
- web::source::url-path-params::Servlet

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- java
- servlets

**Languages:** java

**Mode:** taint



## httpclient-taint-msg

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- pubsub::source::message::Micronaut
- web::sink::http-request::HttpClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## java-http-taint-ws

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- net::source::network-connection::Micronaut
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## java-http-concat-taint-msg

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- pubsub::source::message::Micronaut
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## java-http-taint-sls

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- serverless::source::function-params::Micronaut
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## java-http-concat-taint-ws

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- net::source::network-connection::Micronaut
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## java-http-concat-taint-sls

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- serverless::source::function-params::Micronaut
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## httpclient-taint-concat-ws

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- net::source::network-connection::Micronaut
- web::sink::http-request::HttpClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## httpclient-taint-sls

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- serverless::source::function-params::Micronaut
- web::sink::http-request::HttpClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## java-http-taint-msg

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- pubsub::source::message::Micronaut
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## httpclient-taint-concat-msg

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- pubsub::source::message::Micronaut
- web::sink::http-request::HttpClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## httpclient-taint

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- web::sink::http-request::HttpClient
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## java-http-taint

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## java-http-concat-taint

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## httpclient-taint-concat

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- web::sink::http-request::HttpClient
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## httpclient-taint-ws

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- net::source::network-connection::Micronaut
- web::sink::http-request::HttpClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## httpclient-taint-concat-sls

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::HttpClient
- serverless::source::function-params::Micronaut
- web::sink::http-request::HttpClient

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## tainted-xpath

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut
- xml::sink::xpath::javax.xml

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## tainted-xpath-ws

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- net::source::network-connection::Micronaut
- xml::sink::xpath::javax.xml

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## tainted-xpath-msg

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- pubsub::source::message::Micronaut
- xml::sink::xpath::javax.xml

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## tainted-xpath-sls

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- serverless::source::function-params::Micronaut
- xml::sink::xpath::javax.xml

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## direct-response-write

**Message:** Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::sink::direct-response::Micronaut
- web::sink::html-webpage::Micronaut
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A03:2021 - Injection
- A07:2017 - Cross-Site Scripting (XSS)

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## file-access-taint

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- file::source::file-read::commons-io
- file::source::file-read::java.io
- file::source::file-read::java.xml
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## file-access-taint-ws

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- file::source::file-read::commons-io
- file::source::file-read::java.io
- file::source::file-read::java.xml
- net::source::network-connection::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## file-taint-ws

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- net::source::network-connection::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## file-taint-msg

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- pubsub::source::message::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## file-access-taint-msg

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- file::source::file-read::commons-io
- file::source::file-read::java.io
- file::source::file-read::java.xml
- pubsub::source::message::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## file-taint

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## file-access-taint-sls

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- file::source::file-read::commons-io
- file::source::file-read::java.io
- file::source::file-read::java.xml
- serverless::source::function-params::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## file-taint-sls

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- serverless::source::function-params::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## open-redirect

**Message:** The application builds a URL using user-controlled input which can lead to an open redirect vulnerability. An attacker can manipulate the URL and redirect users to an arbitrary domain. Open redirect vulnerabilities can lead to issues such as Cross-site scripting (XSS) or redirecting to a malicious domain for activities such as phishing to capture users' credentials. To prevent this vulnerability perform strict input validation of the domain against an allowlist of approved domains. Notify a user in your application that they are leaving the website. Display a domain where they are redirected to the user. A user can then either accept or deny the redirect to an untrusted site.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

**Functional-categories:**

- web::sink::redirect::HttpClient
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A01:2021 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## tainted-system-command

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. For more information, see: [Java command injection prevention](https://semgrep.dev/docs/cheat-sheets/java-command-injection/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## tainted-system-command-sls

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. For more information, see: [Java command injection prevention](https://semgrep.dev/docs/cheat-sheets/java-command-injection/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- serverless::source::function-params::Micronaut

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## tainted-system-command-ws

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. For more information, see: [Java command injection prevention](https://semgrep.dev/docs/cheat-sheets/java-command-injection/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::source::network-connection::Micronaut
- os::sink::os-command-or-thread

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## tainted-system-command-msg

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. For more information, see: [Java command injection prevention](https://semgrep.dev/docs/cheat-sheets/java-command-injection/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- pubsub::source::message::Micronaut

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## objectinputstream-deserialization-ws

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `ObjectInputStream`. If you must, you can try overriding the `ObjectInputStream#resolveClass()` method or using a safe replacement for the generic `readObject()` method.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::apache.commons
- deserialization::sink::load-object::java.io
- net::source::network-connection::Micronaut

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- Micronaut
- WebSocket
- java

**Languages:** java

**Mode:** taint



## objectinputstream-deserialization-msg

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `ObjectInputStream`. If you must, you can try overriding the `ObjectInputStream#resolveClass()` method or using a safe replacement for the generic `readObject()` method.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::apache.commons
- deserialization::sink::load-object::java.io
- pubsub::source::message::Micronaut

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- Kafka
- Micronaut
- RabbitMQ
- java

**Languages:** java

**Mode:** taint



## objectinputstream-deserialization-sls

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `ObjectInputStream`. If you must, you can try overriding the `ObjectInputStream#resolveClass()` method or using a safe replacement for the generic `readObject()` method.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::apache.commons
- deserialization::sink::load-object::java.io
- serverless::source::function-params::Micronaut

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- AWS
- Azure
- GCP
- Micronaut
- java

**Languages:** java

**Mode:** taint



## objectinputstream-deserialization

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `ObjectInputStream`. If you must, you can try overriding the `ObjectInputStream#resolveClass()` method or using a safe replacement for the generic `readObject()` method.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::apache.commons
- deserialization::sink::load-object::java.io
- web::source::cookie::Micronaut
- web::source::form-data::Micronaut
- web::source::header::Micronaut
- web::source::http-body::Micronaut
- web::source::http-params::Micronaut
- web::source::url-path-params::Micronaut

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- Micronaut
- java

**Languages:** java

**Mode:** taint



## spring-tainted-path-traversal

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files. In Java, you may also consider using a utility method such as `org.apache.commons.io.FilenameUtils.getName(...)` to only retrieve the file name from the path.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::commons-io
- file::sink::file-access::java.io
- file::sink::file-access::java.xml
- file::sink::file-access::spring
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://www.stackhawk.com/blog/spring-path-traversal-guide-examples-and-prevention/

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## log-request-headers

**Message:** The application stores potentially sensitive information in log files. This could lead to a vulnerability, if an attacker can gain access to logs and then use the sensitive information to perform further attacks. When dealing with HTTP requests, sensitive data could be, for instance, JWT tokens or other session identifiers. To prevent this vulnerability review the type of information being logged. Sensitive information can be identified and filtered or obfuscated before calling logging functions.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-532: Insertion of Sensitive Information into Log File

**Functional-categories:**

- log::sink::log::commons-logging
- web::source::cookie::Spring
- web::source::header::Spring

**Owasp:**

- A09:2021 - Security Logging and Monitoring Failures

**References:**

- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## tainted-html-string-responsebody

**Message:** Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::sink::direct-response::Spring
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A03:2021 - Injection
- A07:2017 - Cross-Site Scripting (XSS)

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## tainted-ssrf-spring

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::Guava
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::Guava
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## tainted-xpath

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xpath::javax.xml

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## objectinputstream-deserialization-spring

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `ObjectInputStream`. If you must, you can try overriding the `ObjectInputStream#resolveClass()` method or using a safe replacement for the generic `readObject()` method.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::apache.commons
- deserialization::sink::load-object::java.io
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## spring-tainted-code-execution

**Message:** User data flows into a script engine or another means of dynamic code evaluation. This is unsafe and could lead to code injection or arbitrary code execution as a result. Avoid inputting user data into code execution or use proper sandboxing if user code evaluation is necessary.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

**Functional-categories:**

- expression-lang::sink::expression::commons-jexl
- expression-lang::sink::expression::javax.el
- expression-lang::sink::expression::javax.script
- expression-lang::sink::expression::velocity
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spel-injection
- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## spring-tainted-ldap-injection

**Message:** Untrusted input might be used to build an LDAP query, which can allow attackers to run arbitrary LDAP queries. If an LDAP query must contain untrusted input then it must be escaped. Ensure data passed to an LDAP query is not controllable or properly sanitize the user input with functions like createEqualityFilter.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

**Functional-categories:**

- ldap::sink::ldap-query::javax.naming
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## hibernate-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. To build SQL queries safely in Java, it is possible to adopt prepared statements by using the `java.sql.PreparedStatement` class with bind variables.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::hibernate
- db::sink::sql-or-nosql-query::javax.persistence
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## jdo-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. To build SQL queries safely in Java, it is possible to adopt prepared statements by using the `java.sql.PreparedStatement` class with bind variables.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::javax.jdo
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## spring-tainted-xmldecoder

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::java.beans

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## kryo-deserialization-deepsemgrep

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `Kryo` unless you explicitly define permissions for types that are allowed to be deserialized by `Kryo`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::kryo
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://github.com/EsotericSoftware/kryo
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- Spring
- java
- kryo
- xml

**Languages:** java

**Mode:** taint



## tainted-ssrf-spring-format

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::Guava
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::Guava
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## spring-sqli-deepsemgrep

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. To build SQL queries safely in Java, it is possible to adopt prepared statements by using the `java.sql.PreparedStatement` class with bind variables.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::SpringData
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## castor-deserialization-deepsemgrep

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the Castor XML Framework unless you explicitly define permissions for types that are allowed to be deserialized by `Castor`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::castor
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://castor-data-binding.github.io/castor/reference-guide/reference/xml/xml-framework.html
- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## xstream-anytype-deserialization-deepsemgrep

**Message:** The application may convert user-controlled data into an object, which can lead to an insecure deserialization vulnerability. An attacker can create a malicious serialized object, pass it to the application, and take advantage of the deserialization process to perform Denial-of-service (DoS), Remote code execution (RCE), or bypass access control measures. To prevent this vulnerability, leverage data formats such as JSON or XML as safer alternatives. If you need to deserialize user input in a specific format, consider digitally signing the data before serialization to prevent tampering. For more information, see: [Deserialization prevention](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) We do not recommend deserializing untrusted data with the `XStream` unless you explicitly define permissions for types that are allowed to be deserialized by `XStream`.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-502: Deserialization of Untrusted Data

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- deserialization::sink::load-object::xstream
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A08:2017 - Insecure Deserialization
- A08:2021 - Software and Data Integrity Failures

**References:**

- https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures
- https://x-stream.github.io/security.html

**Technology:**

- Spring
- java
- xml
- xstream

**Languages:** java

**Mode:** taint



## jdbctemplate-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. To build SQL queries safely in Java, it is possible to adopt prepared statements by using the `java.sql.PreparedStatement` class with bind variables.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::SpringData
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## jpa-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. To build SQL queries safely in Java, it is possible to adopt prepared statements by using the `java.sql.PreparedStatement` class with bind variables.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::javax.persistence
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## tainted-ssrf-spring-add

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request::ApacheHttpClient
- net::sink::http-request::Guava
- net::sink::http-request::HttpClient
- net::sink::http-request::Jsoup
- net::sink::http-request::OkHttp
- net::sink::http-request::RestTemplate
- net::sink::http-request::URL
- net::sink::http-request::WebClient
- web::sink::http-request::ApacheHttpClient
- web::sink::http-request::Guava
- web::sink::http-request::HttpClient
- web::sink::http-request::Jsoup
- web::sink::http-request::OkHttp
- web::sink::http-request::RestTemplate
- web::sink::http-request::URL
- web::sink::http-request::WebClient
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## tainted-validator-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the Validator parser with `parser.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`. Alternatively, the following configuration also provides protection against XXE attacks. parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, ""). For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::javax.xml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-xmlreader-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the XMLReader parser with `parser.setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)`. Alternatively, the following configurations also provide protection against XXE attacks. `parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD,"")`, configuring the both of `parser.setFeature("http://xml.org/sax/features/external-general-entities", false)` and `parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::javax.xml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-documentbuilderfactory-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the DocumentBuilder parser with `factory.setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)`. Alternatively, the following configurations also provide protection against XXE attacks. `factory.setExpandEntityReferences(false)`, `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`, `factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")`, or enabling both `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)` and `factory.setFeature("http://xml.org/sax/features/external-general-entities", false);`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::javax.xml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-saxparser-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the SAXParserFactory with `factory.setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)`. Alternatively, the following configurations for the SAXParserFactory also provide protection against XXE attacks. `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`, enabling both of `factory.setFeature("http://xml.org/sax/features/external-general-entities", and `factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`. Furthermore, you can configure the SAXParser itself with `parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "")` to provide protection against XXE attacks. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::jdom2

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-schemafactory-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the parser with `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`. Alternatively, enabling both of the following configurations also provides protection against XXE attacks. `factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD,"")` and `factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::javax.xml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-saxreader-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the SAXReader parser with `parser.setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)`. Alternatively, configuring both of the below also provides protection against XXE attacks. `parser.setFeature("http://xml.org/sax/features/external-general-entities",false)` `praser.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::dom4j

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-saxtransformerfactory-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the parser with `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::javax.xml

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-saxbuilder-xxe-spring

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. It is our recommendation to secure this parser against XXE attacks by configuring the SAXBuilder parser with `parser.setFeature(http://apache.org/xml/features/disallow-doctype-decl, true)`. Alternatively, the following configurations also provide protection against XXE attacks. `parser.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "")`, enabling both of `parser.setFeature("http://xml.org/sax/features/external-general-entities", false)` and `parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`, and enabling both of `parser.setExpandEntities(false)` and parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false)` It is also possible to use one of the constructor parameters that will result in a more secure parser by default: `new SAXBuilder(XMLReaders.DTDVALIDATING)` or `new SAXBuilder(XMLReaders.XSDVALIDATING)`. For more information, see: [Java XXE prevention](https://semgrep.dev/docs/cheat-sheets/java-xxe/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring
- xml::sink::xml-parser::jdom2

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://blog.sonarsource.com/secure-xml-processor/
- https://blog.sonarsource.com/understanding-xxe-vulnerabilities/
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/611.html
- https://cwe.mitre.org/data/definitions/776.html
- https://docs.oracle.com/en/java/javase/13/security/java-api-xml-processing-jaxp-security-guide.html#GUID-D97A1F1D-8DDF-4D19-A7E5-99099F27346E
- https://github.com/semgrep/java-xxe-research
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://rules.sonarsource.com/java/type/Vulnerability/RSPEC-2755

**Technology:**

- Spring
- java
- xml

**Languages:** java

**Mode:** taint



## tainted-system-command

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands. For more information, see: [Java command injection prevention](https://semgrep.dev/docs/cheat-sheets/java-command-injection/)

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- web::source::cookie::Spring
- web::source::header::Spring
- web::source::http-body::Spring
- web::source::http-params::Spring
- web::source::url-path-params::Spring

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- Spring
- java

**Languages:** java

**Mode:** taint



## kmongo-nosqli

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query::kmongo
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kmongo
- kotlin
- mongo
- nosql
- spring

**Languages:** kotlin

**Mode:** taint



## spring-data-mongo-nosqli

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::source::sql-or-nosql-query::SpringData
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- mongo
- nosql
- spring
- spring-data

**Languages:** kotlin

**Mode:** taint



## hibernate-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Kotlin, it is possible to adopt prepared statements using the `connection.PreparedStatement` class with parameterized queries. For more information, see: [Prepared statements in Kotlin](https://developer.android.com/reference/kotlin/java/sql/PreparedStatement).

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::hibernate
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- hibernate
- kotlin
- orm
- spring

**Languages:** kotlin

**Mode:** taint



## mongo-driver-nosqli

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query::mongodb
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- mongo
- nosql
- spring

**Languages:** kotlin

**Mode:** taint



## tainted-system-command

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- spring

**Languages:** kotlin

**Mode:** taint



## exposed-exec-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Kotlin, it is possible to adopt prepared statements using the `connection.PreparedStatement` class with parameterized queries. For more information, see: [Prepared statements in Kotlin](https://developer.android.com/reference/kotlin/java/sql/PreparedStatement).

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::exposed
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- exposed
- kotlin
- orm
- spring

**Languages:** kotlin

**Mode:** taint



## tainted-ssrf-spring-format

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- net::sink::http-request::SpringBoot
- net::sink::http-request::commons-httpclient
- net::sink::http-request::jsoup
- net::sink::http-request::okhttp
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- kotlin
- spring

**Languages:** kotlin

**Mode:** taint



## prepare-statement-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Kotlin, it is possible to adopt prepared statements using the `connection.PreparedStatement` class with parameterized queries. For more information, see: [Prepared statements in Kotlin](https://developer.android.com/reference/kotlin/java/sql/PreparedStatement).

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::Ktor
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- ktorm
- spring

**Languages:** kotlin

**Mode:** taint



## scripting-host-eval

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- spring

**Languages:** kotlin

**Mode:** taint



## jdbctemplate-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Kotlin, it is possible to adopt prepared statements using the `connection.PreparedStatement` class with parameterized queries. For more information, see: [Prepared statements in Kotlin](https://developer.android.com/reference/kotlin/java/sql/PreparedStatement).

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::SpringData
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- jdbc
- kotlin
- spring

**Languages:** kotlin

**Mode:** taint



## tainted-ssrf-spring-add

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- net::sink::http-request::SpringBoot
- net::sink::http-request::commons-httpclient
- net::sink::http-request::jsoup
- net::sink::http-request::okhttp
- web::source::cookie::SpringBoot
- web::source::header::SpringBoot
- web::source::http-body::SpringBoot
- web::source::http-params::SpringBoot
- web::source::url-path-params::SpringBoot

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- kotlin
- spring

**Languages:** kotlin

**Mode:** taint



## ktor-exposed-unsafe-exec-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Kotlin, it is possible to adopt prepared statements using the `connection.PreparedStatement` class with parameterized queries. For more information, see: [Prepared statements in Kotlin](https://developer.android.com/reference/kotlin/java/sql/PreparedStatement).

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::exposed
- web::source::cookie::Ktor
- web::source::header::Ktor
- web::source::http-params::Ktor
- web::source::url-path-params::Ktor

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- exposed
- kotlin
- ktor

**Languages:** kotlin

**Mode:** taint



## ktor-prepare-statement-sqli

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions. When building SQL queries in Kotlin, it is possible to adopt prepared statements using the `connection.PreparedStatement` class with parameterized queries. For more information, see: [Prepared statements in Kotlin](https://developer.android.com/reference/kotlin/java/sql/PreparedStatement).

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::Ktor
- web::source::cookie::Ktor
- web::source::header::Ktor
- web::source::http-params::Ktor
- web::source::url-path-params::Ktor

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- ktor
- ktorm

**Languages:** kotlin

**Mode:** taint



## ktor-kmongo-nosqli

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query::kmongo
- web::source::cookie::Ktor
- web::source::header::Ktor
- web::source::http-params::Ktor
- web::source::url-path-params::Ktor

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kmongo
- kotlin
- ktor
- mongo
- nosql

**Languages:** kotlin

**Mode:** taint



## ktor-mongo-java-driver

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query::mongodb
- web::source::cookie::Ktor
- web::source::header::Ktor
- web::source::http-params::Ktor
- web::source::url-path-params::Ktor

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- ktor
- mongo
- nosql

**Languages:** kotlin

**Mode:** taint



## ktor-request-xss

**Message:** Untrusted input could be used to tamper with a web page rendering, which can lead to a Cross-site scripting (XSS) vulnerability. XSS vulnerabilities occur when untrusted input executes malicious JavaScript code, leading to issues such as account compromise and sensitive information leakage. To prevent this vulnerability, validate the user input, perform contextual output encoding or sanitize the input.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- web::sink::direct-response::Ktor
- web::source::cookie::Ktor
- web::source::header::Ktor
- web::source::http-params::Ktor
- web::source::url-path-params::Ktor

**Owasp:**

- A03:2021 - Injection
- A07:2017 - Cross-Site Scripting (XSS)

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- kotlin
- ktor

**Languages:** kotlin

**Mode:** taint



## libxml2-expand-xinclude

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::source::console
- os::source::environment
- web::source::http-body
- xml::sink::xml-parser

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp
- xml

**Languages:** cpp, c

**Mode:** taint



## libxml2-expand-local-entities

**Message:** The libxml2 parser is configured to process entities. Without other options such as processing DTDs or accessing remote entities from the network, it should not pose a risk except for memory exhaustion.

**Severity:** INFO

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Interfile:** True

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::source::console
- os::source::environment
- web::source::http-body
- xml::sink::xml-parser

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp
- xml

**Languages:** cpp, c

**Mode:** taint



## libxml2-expand-remote-dtd

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. If DTD is required for local files then pass the `XML_PARSE_NONET` option which will disable network access.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::source::console
- os::source::environment
- web::source::http-body
- xml::sink::xml-parser

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp
- xml

**Languages:** cpp, c

**Mode:** taint



## format-string-injection

**Message:** Externally controlled data influences a format string. This can allow an attacker to leak information from memory or trigger memory corruption. Format strings should be constant strings to prevent these issues. If you need to print a user-controlled string then you can use `%s`.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- FIO30-C
- L1

**Cwe:**

- CWE-134: Use of Externally-Controlled Format String

**Functional-categories:**

- os::source::console
- os::source::environment

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings

**Supersedes:**

- c.lang.security.insecure-use-printf-fn.insecure-use-printf-fn

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## command-injection-path

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread
- os::source::console
- os::source::environment

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## readlink-null-terminator

**Message:** `readlink` does not NULL terminate the output buffer. This expression expects a NULL terminated string and will trigger an out-of-bounds read.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR32-C

**Cwe:**

- CWE-125: Out-of-bounds Read

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/STR32-C.+Do+not+pass+a+non-null-terminated+character+sequence+to+a+library+function+that+expects+a+string

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## narrow-to-wide-string-mismatch

**Message:** A byte-string (narrow string) is used in an API that expects a wide-string. This can trigger an out-of-bounds read.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR38-C

**Cwe:**

- CWE-125: Out-of-bounds Read

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/STR38-C.+Do+not+confuse+narrow+and+wide+character+strings+and+functions

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## string-buffer-overflow

**Message:** `$STR_FUNCTION` does not validate the length of the source string which can trigger a buffer overflow

**Severity:** ERROR

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cert:**

- ARR38-C
- C
- C++
- L1

**Cwe:**

- CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/ARR38-C.+Guarantee+that+library+functions+do+not+form+invalid+pointers

**Supersedes:**

- c.lang.security.insecure-use-strcat-fn.insecure-use-strcat-fn
- c.lang.security.insecure-use-string-copy-fn.insecure-use-string-copy-fn

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## snprintf-return-value-length

**Message:** The return value of `snprintf` is the number of characters that would be written, excluding the NUL terminator. The return value must be validated before using it as a buffer index or buffer length.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- ARR30-C
- C
- C++
- L2

**Cwe:**

- CWE-787: Out-of-bounds Write

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://cwe.mitre.org/data/definitions/787.html
- https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C.+Do+not+form+or+use+out-of-bounds+pointers+or+array+subscripts

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## string-view-data-null-terminator

**Message:** The string returned from `std::string_view.data()` is not guaranteed to be NULL terminated. This expression expects a NULL terminated string and will trigger an out-of-bounds read.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR32-C

**Cwe:**

- CWE-125: Out-of-bounds Read

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/STR32-C.+Do+not+pass+a+non-null-terminated+character+sequence+to+a+library+function+that+expects+a+string

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## snprintf-return-value-snprintf

**Message:** The return value of `snprintf` is the number of characters that would be written, excluding the NUL terminator. The return value must be validated before using it as a buffer index or buffer length in this following `snprintf` call.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- ARR30-C
- C
- C++
- L2

**Cwe:**

- CWE-787: Out-of-bounds Write

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**References:**

- https://cwe.mitre.org/data/definitions/787.html
- https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C.+Do+not+form+or+use+out-of-bounds+pointers+or+array+subscripts

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## wide-to-narrow-string-mismatch

**Message:** A wide-string is used in an API that should consume byte-string (narrow string). This can trigger an out-of-bounds read.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR38-C

**Cwe:**

- CWE-125: Out-of-bounds Read

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/STR38-C.+Do+not+confuse+narrow+and+wide+character+strings+and+functions

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## std-string-npos

**Message:** The return value of `$VAR.$NPOS_CALL(...)` has been modified so it can never equal `std::string::npos`. This could lead to an `std::out_of_range` exception being thrown or trigger an out-of-bounds read if the position is used as an array index.

**Severity:** ERROR

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- CTR55-CPP
- L1

**Cwe:**

- CWE-125: Out-of-bounds Read

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**References:**

- https://wiki.sei.cmu.edu/confluence/display/cplusplus/CTR55-CPP.+Do+not+use+an+additive+operator+on+an+iterator+if+the+result+would+overflow

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## unvalidated-array-index

**Message:** Externally controlled data is used to index a fixed-size array, `$BUFFER`. This could lead to an out-of-bounds read or write, triggering memory corruption.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- ARR30-C
- C
- C++
- L2

**Cwe:**

- CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C.+Do+not+form+or+use+out-of-bounds+pointers+or+array+subscripts

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## negative-return-value-array-index

**Message:** The preceding call to `$SOURCE` can return a negative value when an error is encountered. This can lead to an out-of-bounds array access and possible memory corruption.

**Severity:** WARNING

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-787: Out-of-bounds Write

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- memory::sink::buffer-overflow

**References:**

- https://cwe.mitre.org/data/definitions/787.html

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## double-free

**Message:** `$SINK_VAR` has previously been freed which will trigger a double-free vulnerability. This may lead to memory corruption.

**Severity:** ERROR

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- MEM30-C
- MEM50-CPP

**Cwe:**

- CWE-415: Double Free

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/MEM30-C.+Do+not+access+freed+memory
- https://wiki.sei.cmu.edu/confluence/display/cplusplus/MEM50-CPP.+Do+not+access+freed+memory

**Supersedes:**

- c.lang.security.double-free.double-free

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## double-delete

**Message:** `$SINK_VAR` has previously been deleted which will trigger a double-free vulnerability. This may lead to memory corruption.

**Severity:** ERROR

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- MEM50-CPP

**Cwe:**

- CWE-415: Double Free

**References:**

- https://wiki.sei.cmu.edu/confluence/display/cplusplus/MEM50-CPP.+Do+not+access+freed+memory

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## local-variable-new-delete

**Message:** This expression points to memory that has been freed. This can lead to a segmentation fault or memory corruption.

**Severity:** ERROR

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- EXP54-CPP
- L1
- L2
- MEM30-C

**Cwe:**

- CWE-416: Use After Free

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/MEM30-C.+Do+not+access+freed+memory
- https://wiki.sei.cmu.edu/confluence/display/cplusplus/EXP54-CPP.+Do+not+access+an+object+outside+of+its+lifetime

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## local-variable-malloc-free

**Message:** This expression points to memory that has been freed. This can lead to a segmentation fault or memory corruption.

**Severity:** ERROR

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- EXP54-CPP
- L1
- L2
- MEM30-C

**Cwe:**

- CWE-416: Use After Free

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/MEM30-C.+Do+not+access+freed+memory
- https://wiki.sei.cmu.edu/confluence/display/cplusplus/EXP54-CPP.+Do+not+access+an+object+outside+of+its+lifetime

**Supersedes:**

- c.lang.security.function-use-after-free.function-use-after-free
- c.lang.security.use-after-free.use-after-free

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## ldap-injection-filter

**Message:** Untrusted input might be used to build an LDAP query, which can allow attackers to run arbitrary LDAP queries. If an LDAP query must contain untrusted input then it must be escaped.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

**Functional-categories:**

- ldap::sink::ldap-query
- os::source::console
- os::source::environment
- web::source::http-body

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp
- ldap

**Languages:** cpp, c

**Mode:** taint



## ldap-injection-dn

**Message:** Untrusted input might be used to build an LDAP query, which can allow attackers to run arbitrary LDAP queries. If an LDAP query must contain untrusted input then it must be escaped.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

**Functional-categories:**

- ldap::sink::ldap-query
- os::source::console
- os::source::environment
- web::source::http-body

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp
- ldap

**Languages:** cpp, c

**Mode:** taint



## dynamic-library-path

**Message:** Externally controlled data influences the filename of a dynamically loaded library. This could trigger arbitrary code execution.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-114: Process Control

**Functional-categories:**

- os::sink::os-command-or-thread
- os::source::console
- os::source::environment
- web::source::http-body

**References:**

- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## path-manipulation

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- FIO02-C
- L2

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access
- os::source::console
- os::source::environment
- web::source::http-body

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
- https://wiki.sei.cmu.edu/confluence/display/c/FIO02-C.+Canonicalize+path+names+originating+from+tainted+sources

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## url-manipulation-generic

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::source::console
- os::source::environment
- web::sink::header
- web::sink::http-request
- web::source::http-body

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## http-url

**Message:** The application may be making an insecure HTTP request which may allow attackers to intercept plaintext information. Instead, the URL should use HTTPS to ensure that the request is encrypted.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** MEDIUM

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-319: Cleartext Transmission of Sensitive Information

**Functional-categories:**

- net::sink::http-request

**Owasp:**

- A02:2021 - Cryptographic Failures
- A03:2017 - Sensitive Data Exposure

**References:**

- https://owasp.org/Top10/A02_2021-Cryptographic_Failures

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## predictable-seed-rng-time

**Message:** The seed value of a Pseudo Random Number Generator (PRNG) is directly derived from the time, which is highly predictable. Do not use values from this PRNG to derive a secrets, such as passwords or cryptographic keys.

**Severity:** INFO

### Metadata

**Likelihood:** LOW

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- audit

**Cert:**

- C
- C++
- L1
- MSC51-CPP

**Cwe:**

- CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)

**Owasp:**

- A02:2021 - Cryptographic Failures

**References:**

- https://owasp.org/Top10/A02_2021-Cryptographic_Failures
- https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC51-CPP.+Ensure+your+random+number+generator+is+properly+seeded

**Technology:**

- cpp

**Languages:** cpp, c

**Mode:** taint



## sql-injection

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cert:**

- C
- C++
- L1
- STR02-C

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query
- os::source::console
- os::source::environment

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection
- https://wiki.sei.cmu.edu/confluence/display/c/STR02-C.+Sanitize+data+passed+to+complex+subsystems

**Technology:**

- cpp
- sql

**Languages:** cpp, c

**Mode:** taint



## httpclient-taint-format

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- .NET
- api
- csharp
- dotnet
- http
- httpclient
- mvc

**Languages:** csharp

**Mode:** taint



## httpclient-taint-low

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- .NET
- api
- csharp
- dotnet
- http
- httpclient
- mvc

**Languages:** csharp

**Mode:** taint



## httpclient-taint-format-low

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- .NET
- api
- csharp
- dotnet
- http
- httpclient
- mvc

**Languages:** csharp

**Mode:** taint



## httpclient-taint-format-grpc

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- .NET
- csharp
- dotnet
- grpc
- http
- httpclient

**Languages:** csharp

**Mode:** taint



## httpclient-taint-grpc

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- .NET
- csharp
- dotnet
- grpc
- http
- httpclient

**Languages:** csharp

**Mode:** taint



## httpclient-taint

**Message:** Untrusted input might be used to build an HTTP request, which can lead to a Server-side request forgery (SSRF) vulnerability. SSRF allows an attacker to send crafted requests from the server side to other internal or external systems. SSRF can lead to unauthorized access to sensitive data and, in some cases, allow the attacker to control applications or systems that trust the vulnerable service. To prevent this vulnerability, avoid allowing user input to craft the base request. Instead, treat it as part of the path or query parameter and encode it appropriately. When user input is necessary to prepare the HTTP request, perform strict input validation. Additionally, whenever possible, use allowlists to only interact with expected, trusted domains.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-918: Server-Side Request Forgery (SSRF)

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::sink::http-request
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A10:2021 - Server-Side Request Forgery (SSRF)

**References:**

- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29

**Technology:**

- .NET
- api
- csharp
- dotnet
- http
- httpclient
- mvc

**Languages:** csharp

**Mode:** taint



## xml-dtd-allowed

**Message:** The application is using an XML parser that has not been safely configured. This might lead to XML External Entity (XXE) vulnerabilities when parsing user-controlled input. An attacker can include document type definitions (DTDs) or XIncludes which can interact with internal or external hosts. XXE can lead to other vulnerabilities, such as Local File Inclusion (LFI), Remote Code Execution (RCE), and Server-side request forgery (SSRF), depending on the application configuration. An attacker can also use DTDs to expand recursively, leading to a Denial-of-Service (DoS) attack, also known as a `Billion Laughs Attack`. The best defense against XXE is to have an XML parser that supports disabling DTDs. Limiting the use of external entities from the start can prevent the parser from being used to process untrusted XML files. Reducing dependencies on external resources is also a good practice for performance reasons. It is difficult to guarantee that even a trusted XML file on your server or during transmission has not been tampered with by a malicious third-party.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** MEDIUM

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-611: Improper Restriction of XML External Entity Reference

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- xml::sink::xml-parser::.net

**Owasp:**

- A04:2017 - XML External Entities (XXE)
- A05:2021 - Security Misconfiguration

**References:**

- https://owasp.org/Top10/A05_2021-Security_Misconfiguration

**Technology:**

- .NET
- csharp
- dotnet
- xml

**Languages:** csharp

**Mode:** taint



## systemdata-taint-grpc

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::ADO
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- ado
- ado.net
- csharp
- dotnet
- grpc
- sql

**Languages:** csharp

**Mode:** taint



## entityframework-taint-low

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::EntityFramework
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- ef
- entity
- entity framework
- mvc
- sql

**Languages:** csharp

**Mode:** taint



## entityframework-taint-grpc

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::EntityFramework
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- csharp
- dotnet
- ef
- entity
- entity framework
- grpc
- sql

**Languages:** csharp

**Mode:** taint



## systemdata-taint-low

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::ADO
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- ado
- ado.net
- api
- csharp
- dotnet
- mvc
- sql

**Languages:** csharp

**Mode:** taint



## entityframework-taint

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::EntityFramework
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- ef
- entity
- entity framework
- mvc
- sql

**Languages:** csharp

**Mode:** taint



## systemdata-taint

**Message:** Untrusted input might be used to build a database query, which can lead to a SQL injection vulnerability. An attacker can execute malicious SQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. To prevent this vulnerability, use prepared statements that do not concatenate user-controllable strings and use parameterized queries where SQL commands and user data are strictly separated. Also, consider using an object-relational (ORM) framework to operate with safer abstractions.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- db::sink::sql-or-nosql-query::ADO
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- ado
- ado.net
- api
- csharp
- dotnet
- mvc
- sql

**Languages:** csharp

**Mode:** taint



## mongodb-taint-low

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- ef
- entity
- entity framework
- mvc
- sql

**Languages:** csharp

**Mode:** taint



## mongodb-taint

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- ef
- entity
- entity framework
- mvc
- sql

**Languages:** csharp

**Mode:** taint



## mongodb-taint-grpc

**Message:** Untrusted input might be used to build a database query, which can lead to a NoSQL injection vulnerability. An attacker can execute malicious NoSQL statements and gain unauthorized access to sensitive data, modify, delete data, or execute arbitrary system commands. Make sure all user input is validated and sanitized, and avoid using tainted user input to construct NoSQL statements if possible. Ideally, avoid raw queries and instead use parameterized queries.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-943: Improper Neutralization of Special Elements in Data Query Logic

**Functional-categories:**

- db::sink::sql-or-nosql-query
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A01:2017 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- csharp
- dotnet
- ef
- entity
- entity framework
- grpc
- sql

**Languages:** csharp

**Mode:** taint



## xpath-taint-low

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET
- xml::sink::xpath

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- mvc
- xml
- xpath

**Languages:** csharp

**Mode:** taint



## xpath-taint

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET
- xml::sink::xpath

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- mvc
- xml
- xpath

**Languages:** csharp

**Mode:** taint



## xpath-taint-grpc

**Message:** XPath queries are constructed dynamically on user-controlled input. This could lead to XPath injection if variables passed into the evaluate or compile commands are not properly sanitized. Xpath injection could lead to unauthorized access to sensitive information in XML documents. Thoroughly sanitize user input or use parameterized XPath queries if you can.

**Severity:** WARNING

### Metadata

**Likelihood:** MEDIUM

**Impact:** MEDIUM

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')

**Functional-categories:**

- net::source::remote-procedure-call::gRPC
- xml::sink::xpath

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- csharp
- dotnet
- grpc
- xml
- xpath

**Languages:** csharp

**Mode:** taint



## req-file-taint-grpc

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::file
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- .NET
- csharp
- dotnet
- file
- grpc

**Languages:** csharp

**Mode:** taint



## req-file-taint

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::file
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- .NET
- api
- csharp
- dotnet
- file
- mvc

**Languages:** csharp

**Mode:** taint



## file-taint

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::file
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- .NET
- api
- csharp
- dotnet
- file
- mvc

**Languages:** csharp

**Mode:** taint



## file-taint-grpc

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::file
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- .NET
- csharp
- dotnet
- file
- grpc

**Languages:** csharp

**Mode:** taint



## file-taint-low

**Message:** The application builds a file path from potentially untrusted data, which can lead to a path traversal vulnerability. An attacker can manipulate the path which the application uses to access files. If the application does not validate user input and sanitize file paths, sensitive files such as configuration or user data can be accessed, potentially creating or overwriting files. To prevent this vulnerability, validate and sanitize any input that is used to create references to file paths. Also, enforce strict file access controls. For example, choose privileges allowing public-facing applications to access only the required files.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- file::sink::file-access::file
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2021 - Broken Access Control
- A05:2017 - Broken Access Control

**References:**

- https://owasp.org/Top10/A01_2021-Broken_Access_Control
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal

**Technology:**

- .NET
- api
- csharp
- dotnet
- file
- mvc

**Languages:** csharp

**Mode:** taint



## process-taint-grpc

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- net::source::remote-procedure-call::gRPC
- os::sink::os-command-or-thread::.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- csharp
- dotnet
- grpc
- process

**Languages:** csharp

**Mode:** taint



## process-taint

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::.NET
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- mvc
- process

**Languages:** csharp

**Mode:** taint



## process-taint-low

**Message:** Untrusted input might be injected into a command executed by the application, which can lead to a command injection vulnerability. An attacker can execute arbitrary commands, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing OS commands with user input. If this is unavoidable, validate and sanitize the input, and use safe methods for executing the commands.

**Severity:** ERROR

### Metadata

**Likelihood:** MEDIUM

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Cwe2020-top25:** True

**Cwe2021-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- os::sink::os-command-or-thread::.NET
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A01:2017 - Injection
- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- csharp
- dotnet
- mvc
- process

**Languages:** csharp

**Mode:** taint



## compile-taint-grpc

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval
- net::source::remote-procedure-call::gRPC

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- compiler
- csharp
- dotnet
- grpc
- roslyn

**Languages:** csharp

**Mode:** taint



## compile-taint-low

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** LOW

**Category:** security

**Subcategory:**

- audit

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- compiler
- csharp
- dotnet
- mvc
- roslyn

**Languages:** csharp

**Mode:** taint



## compile-taint

**Message:** The application might dynamically evaluate untrusted input, which can lead to a code injection vulnerability. An attacker can execute arbitrary code, potentially gaining complete control of the system. To prevent this vulnerability, avoid executing code containing user input. If this is unavoidable, validate and sanitize the input, and use safe alternatives for evaluating user input.

**Severity:** ERROR

### Metadata

**Likelihood:** HIGH

**Impact:** HIGH

**Confidence:** HIGH

**Category:** security

**Subcategory:**

- vuln

**Cwe:**

- CWE-94: Improper Control of Generation of Code ('Code Injection')

**Cwe2020-top25:** True

**Cwe2022-top25:** True

**Functional-categories:**

- code::sink::eval
- web::source::header::ASP.NET
- web::source::http-body::ASP.NET
- web::source::http-params::ASP.NET
- web::source::url-path-params::ASP.NET

**Owasp:**

- A03:2021 - Injection

**References:**

- https://owasp.org/Top10/A03_2021-Injection

**Technology:**

- .NET
- api
- compiler
- csharp
- dotnet
- mvc
- roslyn

**Languages:** csharp

**Mode:** taint

