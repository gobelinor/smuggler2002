
<img width="833" height="401" alt="Capture d’écran 2025-08-07 à 14 14 24" src="https://github.com/user-attachments/assets/54dd4e4a-3bdb-4968-aa08-e3f0740650c5" />

### PORTSWIGGER LABS TEST

✅ HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

✅ HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

✅ Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
—> detects CL.TE but no exploit implemented

✅ Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
—> detects TE.CL but no exploit implemented 

✅ Exploiting HTTP request smuggling to reveal front-end request rewriting
—> detects CL.TE but no exploit implemented

✅ Exploiting HTTP request smuggling to capture other users' requests
—> detects CL.TE but no exploit implemented

✅ Exploiting HTTP request smuggling to deliver reflected XSS
—> detects CL.TE but no exploit implemented

⚠️ Response queue poisoning via H2.TE request smuggling
-> NOT IMPLEMENTED

⚠️ H2.CL request smuggling
-> NOT IMPLEMENTED

⚠️ HTTP/2 request smuggling via CRLF injection
-> NOT IMPLEMENTED

⚠️ HTTP/2 request splitting via CRLF injection
-> NOT IMPLEMENTED

✅ CL.0 request smuggling
-> detects CL.0 if good enpoint is given in args

✅ HTTP request smuggling, basic CL.TE vulnerability

✅ HTTP request smuggling, basic TE.CL vulnerability

✅ HTTP request smuggling, obfuscating the TE header
—> detects TE.TE but no exploit implemented

### TODO

Add a flag to decide if we want the attack in the attack requests to be send in the same connection or separate ones.

Add a flag to spam test requests during 30s

Add a flag to test with all methods

Add HTTP2 support

Add TE0

Add an interesting endpoint scraper for CL0

Add the ability to add a header like `proxyconnection: gouguagaga`

Add new versions of advanced vulnerabilities presented by portswigger in august 2025

 
