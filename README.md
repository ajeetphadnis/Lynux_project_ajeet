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


UTES Demo: ia raksha.io demo application that renders raksha.io's microservices those enable variout
crypto protocol endpoints. These protocols could be used or implemented as TLS, DSS, encrypt, decrypt.

The UTES Demo can be started with the following steps:

1. Register or Create a User
Of course we need a user if we are going to demostrate token exchange.
1. Raksha.io creates demo user in two ways:
2. Create a Demo User tab:
  a.In this you give full name of the demo user.
  b. Email and,
  c. Unique id for the user.
  This will create a user with unique id in
  database.
3. Generate Random User tab:
 This will create a random user with :
  a.Full name
  b. Email
  c.Unique id
In both the cases the required password is
the same as unique id of the demo user.
And don’t worry, none of this data that is
being stored in our database persists for more
than 24 hours.

UTES in Action:

Raksha.io is committed to secure network infrastructure and web apps and ops. Some UTES Actions are:
  * As it was absolutely necessary for us to use a databased user repo, we have implemented mongodb as database. The
    schema/models is auth_users and the collection is users. So a user has to register first and then user is able to login.
  * user can chose login if s/he is already member of the community. Or Register to become a member and a last option
    to logout.
  * After a user has registered successfully, user is navigated to start page. where user can login . When a user is logged in,
    user is navigated to this protocol converter service page:
  * The user id is then shown in readonly field on the page and is able to choose protocol operations as desired. The data
    display has a delay and the user has to repeat the operation to get the data in the page view. Investigating how to
    solve this.
  * Demo Development was initiated on 15 Jan 2022 the purpose was to develop a state of art one page app that was 
    responsive and would run on any device. On 28th Feb. 2022 the project was completed. The features deployed on this
new app are:
  * The app uses .env file for many key functions, ensure that the file is in the root.
  * Creating user with minimal inputs:
  * full name
  * email
  * unique id
  * Creating random user - this feature creates random user with one click
  * Protocol Exchange Service - includes:
    * SAML -> OAUTH
    * OAUTH -> SAML
    * SAML -> X509
    * X509 -> SAML
    * X509 -> OAUTH
    * OAUTH -> X509
    * SAML Assert Service
    * JWKeySet endpoint Service
    * JWToken endpoint Service
    * ECDSA Certificate Service
    * OCSP Service
    * Secure Envelop Service

 
