### PORTSWIGGER LABS TEST

✅ HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

✅ HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

✅ Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
—> detects CL.TE but no exploit implemented

✅ Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
—> detects TE.CL but no exploit implemented —> EZ exploit osef

✅ Exploiting HTTP request smuggling to reveal front-end request rewriting
—> detects CL.TE but no exploit implemented

✅ Exploiting HTTP request smuggling to capture other users' requests
—> detects CL.TE but no exploit implemented

✅ Exploiting HTTP request smuggling to deliver reflected XSS
—> detects CL.TE but no exploit implemented

⚠️ Response queue poisoning via H2.TE request smuggling
—> host not dumb
-> NOT IMPLEMENTED

⚠️ H2.CL request smuggling
—> host not dumb
-> NOT IMPLEMENTED

⚠️ HTTP/2 request smuggling via CRLF injection
—> host not dumb
-> NOT IMPLEMENTED

⚠️ HTTP/2 request splitting via CRLF injection
—> host not dumb
-> NOT IMPLEMENTED

✅ CL.0 request smuggling
—> fonctionne avec le bon endpoint de renseigné

✅ HTTP request smuggling, basic CL.TE vulnerability

✅ HTTP request smuggling, basic TE.CL vulnerability

✅ HTTP request smuggling, obfuscating the TE header
—> detects TE.TE but no exploit implemented

### TODO
ajouter un TE0
ajouter un scrapper de endpoint interessant pour CL0
ajouter un la possibilité d’ajouter un header comme proxyconnection: gougougaga
