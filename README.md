# raksha

At Raksha.io we develope application such as SOAP and REST services for enterprise partners document exchanges:
Such as ePeppol transactions, Secure Envelope transactions Enterprise PKI X509 RSA TEST certificate generation
Enterprise PKI X509 ECDSA TEST certificate generation Enterprise JWKS repositories
Enterprise JWT, JWE token generation services Enterprise securiy authentication protocol conversions services:
X509 - SAML, SAML - X509, SAML - OAUTH, OAUTH - SAML, OAUTH - X509, X509 - OAUTH

Raksh.io REST Service as Protocols Exchange Hub:

Internet Security Protocols Exchange Hub: The Protocol Exchange Hub provides a dynamic REST service that delivers transformed protocol on demand as described here: Internet security has achieved great importance, as its vast and encompasses various aspects associated with internet security:
Various security mechanisms exist for specialized internet services like email, electronic commerce, and payment, wireless internet, etc.
To provide the security to this internet various protocols have been used like SSL (Secure Socket Layer), TLS ( Transport Layer Security), etc
Protocols are divided in the following catagories:
SSL Protocol
TLS Protocol
SHTTP
SET Protocol
PEM Protocol
PGP Protocol
IPSec and VPNs
SSL and TLS
Application Transparent Transport Layer Security
Kerberos
OSPF authentication
SNMPv3
All the above network and web security protocols need
mechanisms that would implement cyber threat protection
against the Enterprise web application attacks.
cryptographic protocol or encryption protocol is an
abstract or concrete protocol that performs a security-related
function and applies cryptographic methods, often as sequences
of cryptographic primitives
Cryptographic protocols are widely used for secure application-level
data transport. A cryptographic protocol usually incorporates at
least some of these aspects:
Key agreement or establishment
Entity authentication
Symmetric encryption and message authentication material construction
Secured application-level data transport
Non-repudiation methods
Secret sharing methods
Secure multi-party computation

raksha.io implements the cryptographic mechanisms required in form of : PKI, OAUTH, SAML2, ECDSA low level protocols. 
raksha.io runs a demo version of ProtocolExchange REST service Hub. This service can be accessed by any without any 
login at this url pattern: https://utes-dev.phadnis.no/getProtocolTrans?convrt=saml-oauth The url parameter convrt 
tells the service which type of protocol transformation is to be performed. Valid parameters are: 
saml-oauth, saml-x509, oauth-saml, oauth-x509, x509-saml and x509-oauth. 
Typical client interfaces are cURL and Postman. Example of Postman : 
configure a https - POST method with the url. Set Accept header to application/json. 
Paste client cert or token in the body of the request. Example of cURL : 
curl -s -o response.txt -w "%{http_code}" -F file=@saml2jwt_test.jwt 
--header 'Accept: application/json' -X POST -k https://localhost:20443/getProtocolTrans?convrt=oauth-saml

ECDSA For SSL / TLS Certificates & much more …

ECDSA stands for Elliptic Curve Digital Signature Algorithm. This algorithm deals with elliptical curve 
and the mathematics behind it to provide the cryptography. ECDSA works by selecting a number from an 
elliptical curve and then multiplying this by another number which results in a new point on the curve 
that makes it incredibly difficult to crack the new point or in crypto terms the new private key. 
This makes ECDSA a lot more complex than the RSA (Rivest Shamir Aldeman) algorithm that is used in 
most SSL certificates on the Internet. At Raksha.io we have IDPs issuing both the types of SSL /TLS 2 
certificates, depending on the client side PKI environments. ECDSA keys being short, gives distinct 
advantage in terms of scalability and performance. ECDSA is referred to Elliptic curve Cryptography- ECC.
