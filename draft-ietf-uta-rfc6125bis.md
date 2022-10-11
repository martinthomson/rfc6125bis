---
v: 3
ipr: trust200902
docname: draft-ietf-uta-rfc6125bis-latest
obsoletes: 6125
cat: std
stream: IETF
pi:
  compact: 'yes'
  subcompact: 'no'
  symrefs: 'yes'
  sortrefs: 'yes'
  toc: 'yes'
  tocdepth: '4'
  rfcedstyle: 'yes'
title: Service Identity in TLS
abbrev: Service Identity
area: Applications
kw: Internet-Draft
author:
- ins: P. Saint-Andre
  name: Peter Saint-Andre
  org: independent
  country: US
  email: stpeter@stpeter.im
- ins: R. Salz
  name: Rich Salz
  org: Akamai Technologies
  country: US
  email: rsalz@akamai.com
normative:
  DNS-CONCEPTS: RFC1034
  DNS-SRV: RFC2782
  DNS-WILDCARDS: RFC4592
  IDNA-DEFS: RFC5890
  IDNA-PROTO: RFC5891
  LDAP-DN: RFC4514
  PKIX: RFC5280
  SRVNAME: RFC4985
  URI: RFC3986
  RFC7525bis: I-D.ietf-uta-rfc7525bis
informative:
  ABNF: RFC5234
  ACME: RFC8555
  ALPN: RFC7301
  DANE: RFC6698
  DNS-CASE: RFC4343
  DNS-TERMS: RFC8499
  DNSSEC: RFC4033
  DTLS: RFC9147
  EMAIL-SRV: RFC6186
  HTTP: RFC9110
  NAPTR: RFC3403
  NTS: RFC8915
  QUIC: RFC9001
  SECTERMS: RFC4949
  SIP: RFC3261
  SIP-CERTS: RFC5922
  SIP-SIPS: RFC5630
  TLS: RFC8446
  TLS-SUBCERTS: I-D.ietf-tls-subcerts
  VERIFY: RFC6125
  XMPP: RFC6120
  ALPACA:
    target: https://alpaca-attack.com/ALPACA.pdf
    title: "ALPACA: Application Layer Protocol Confusion - Analyzing and Mitigating Cracks in TLS Authentication"
    author:
    - ins: M. Brinkmann
      name: Marcus Brinkmann
      org: Ruhr University Bochum
    - ins: C. Dresen
      name: Christian Dresen
      org: Münster University of Applied Sciences
    - ins: R. Merget
      name: Robert Merget
      org: Ruhr University Bochum
    - ins: D. Poddebniak
      name: Damian Poddebniak
      org: Münster University of Applied Sciences
    - ins: J. Müller
      name: Jens Müler
      org: Ruhr University Bochum
    - ins: J. Somorovsky
      name: Juraj Somorovsky
      org: Paderborn University
    - ins: J. Schwenk
      name: Jörg Schwek
      org: Ruhr University Bochum
    - ins: S. Schinzel
      name: Sebastian Schinzel
      org: Ruhr University Bochum
    date: 2021-9
  HTTPSbytes:
    target: https://media.blackhat.com/bh-ad-10/Hansen/Blackhat-AD-2010-Hansen-Sokol-HTTPS-Can-Byte-Me-slides.pdf
    title: HTTPS Can Byte Me
    author:
    - ins: J. Sokol
      name: Josh Sokol
      org: SecTheory Ltd.
    - ins: R. Hansen
      name: Robert Hansen
      org: SecTheory Ltd.
    date: 2010-11
    seriesinfo:
      BlackHat: Abu Dhabi
  Defeating-SSL:
    target: http://www.blackhat.com/presentations/bh-dc-09/Marlinspike/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf
    title: New Tricks for Defeating SSL in Practice
    author:
    - ins: M. Marlinspike
      name: Moxie Marlinspike
      org: ''
    date: 2009-02
    seriesinfo:
      BlackHat: DC
  Public-Suffix:
    target: https://publicsuffix.org
    title: "Public Suffix List"
    date: 2020
  US-ASCII:
    title: Coded Character Set - 7-bit American Standard Code for Information Interchange
    author:
    - org: American National Standards Institute
    date: 1986
    seriesinfo:
      ANSI: X3.4
  X.509:
    title: >
     Information Technology - Open Systems Interconnection -
     The Directory: Public-key and attribute certificate frameworks
    author:
    - org: International Telecommunications Union
    date: 2005
    seriesinfo:
      ITU-T: X.509
  X.690:
    title: >
      Information Technology - ASN.1 encoding rules:
      Specification of Basic Encoding Rules (BER), Canonical Encoding Rules
      (CER) and Distinguished Encoding Rules (DER)
    author:
    - org: International Telecommunications Union
    date: 2008
    seriesinfo:
      ITU-T: X.690
  WSC-UI:
    target: https://www.w3.org/TR/2010/REC-wsc-ui-20100812/
    title: 'Web Security Context: User Interface Guidelines'
    author:
    - ins: A. Saldhana
      name: Anil Saldhana
    - ins: T. Roessler
      name: Thomas Roessler
    date: '2010-08-12'

--- abstract

Many application technologies enable secure communication between two entities
by means of Transport Layer Security (TLS) with
Internet Public Key Infrastructure Using X.509 (PKIX) certificates.
This document specifies
procedures for representing and verifying the identity of application services
in such interactions.

This document obsoletes RFC 6125.

--- middle

# Introduction {#intro}

## Motivation {#motivation}

The visible face of the Internet largely consists of services that employ a
client-server architecture in which a client
communicates with an application service.  When a client communicates with an
application service using {{TLS}}, {{DTLS}}, or a protocol built on those
({{QUIC}} being a notable example),
it has some notion of the server's
identity (e.g., "the website at example.com") while attempting to establish
secure communication.  Likewise, during TLS negotiation, the server presents
its notion of the service's identity in the form of a public-key certificate
that was issued by a certificate authority (CA) in the context of the
Internet Public Key Infrastructure using X.509 {{PKIX}}.  Informally, we can
think of these identities as the client's "reference identity" and the
server's "presented identity"; more formal definitions are given later.  A
client needs to verify that the server's presented identity matches its
reference identity so it can deterministically and automatically authenticate the communication.

This document defines procedures for how clients do this verification.
It therefore also defines requirements on other parties, such as
the certificate authorities that issue certificates, the service administrators requesting
them, and the protocol designers defining how things are named.

This document obsoletes RFC 6125. Changes from RFC 6125 are described under {{changes}}.

## Applicability {#applicability}

This document does not supersede the rules for certificate issuance or
validation specified by {{PKIX}}.  That document also governs any
certificate-related topic on which this document is silent.  This includes
certificate syntax, extensions such as name constraints or
extended key usage, and handling of certification paths.

This document addresses only name forms in the leaf "end entity" server
certificate.  It does not address the name forms in the chain of certificates
used to validate a cetrificate, let alone creating or checking the validity
of such a chain.  In order to ensure proper authentication, applications need
to verify the entire certification path.

## Overview of Recommendations {#overview}

The previous version of this specification, {{VERIFY}}, surveyed the then-current
practice from many IETF standards and tried to generalize best practices
(see Appendix A of {{VERIFY}} for details).

This document takes the lessons learned since then and codifies them.
The following is a summary of the rules, which are described at greater
length in the remainder of this document:

* Only check DNS domain names via the subjectAlternativeName
  extension designed for that purpose: dNSName.

* Allow use of even more specific
  subjectAlternativeName extensions where appropriate such as
  uniformResourceIdentifier, iPAddress, and the otherName form SRVName.

* Wildcard support is now the default.
  Constrain wildcard certificates so that the wildcard can only
  be the complete left-most component of a domain name.

* Do not include or check strings that look like domain names
  in the subject's Common Name.

## Scope {#scope}

### In Scope {#in-scope}

This document applies only to service identities that are used in TLS or DTLS
and that are included in PKIX certificates.

With regard to TLS and DTLS, these security protocols are used to
protect data exchanged over a wide variety of application protocols,
which use both the TLS or DTLS handshake protocol and the TLS or
DTLS record layer, either directly or through a profile as in Network
Time Security {{NTS}}.  The TLS handshake protocol can also be used
with different record layers to define secure transport protocols;
at present the most prominent example is QUIC {{?RFC9000}}.  The
rules specified here are intended to apply to all protocols in this
extended TLS "family".

With regard to PKIX certificates, the primary usage is in the
context of the public key infrastructure described in {{PKIX}}.
In addition, technologies such as DNS-Based Authentication
of Named Entities (DANE) {{DANE}} sometimes use certificates based
on PKIX (more precisely, certificates structured via {{X.509}} or
specific encodings thereof such as {{X.690}}), at least in certain
modes.  Alternatively, a TLS peer could issue delegated credentials
that are based on a CA-issued certificate, as in {{TLS-SUBCERTS}}.
In both of these cases, a TLS client could learn of a service identity
through its inclusion in the relevant certificate.  The rules specified
here are intended to apply whenever service identities are included in
X.509 certificates or credentials that are derived from such certificates.


### Out of Scope {#out-of-scope}

The following topics are out of scope for this specification:

* Security protocols other than those
  described above.

* Keys or certificates employed outside the context of PKIX-based systems.

* Client or end-user identities.
  Certificates representing client identities other than as
  described above, such as rfc822Name, are beyond the scope
  of this document.

* Identification of servers using other than a domain name, IP address, or SRV service name.
  This document discusses Uniform Resource Identifiers {{URI}} only to the
  extent that they are expressed in certificates.  Other aspects of a service
  such as a specific resource (the URI "path" component) or parameters (the URI
  "query" component) are the responsibility of specific protocols or URI
  schemes.

* Certification authority policies.
  This includes items such as the following:

  * How to certify or validate FQDNs and application
    service types (see {{ACME}} for some definition of this).

  * Types or "classes" of certificates to issue and whether to apply different
    policies for them.

  * How to certify or validate other kinds of information that might be
    included in a certificate (e.g., organization name).

* Resolution of DNS domain names.
  Although the process whereby a client resolves the DNS domain name of an
  application service can involve several steps, for our purposes we care
  only about the fact that the client needs to verify the identity of the
  entity with which it communicates as a result of the resolution process.
  Thus the resolution process itself is out of scope for this specification.

* User interface issues.
  In general, such issues are properly the responsibility of client
  software developers and standards development organizations
  dedicated to particular application technologies (see, for example,
  {{WSC-UI}}).

## Terminology {#terminology}

Because many concepts related to "identity" are often too vague to be
actionable in application protocols, we define a set of more concrete terms
for use in this specification.

application service:
: A service on the Internet that enables clients to connect for the
  purpose of retrieving or uploading information, communicating with other
  entities, or connecting to a broader network of services.

application service provider:
: An entity that hosts or deploys an application service.

application service type:
: A formal identifier for the application protocol used to provide a
  particular kind of application service at a domain.  This often appears as
  a URI scheme {{URI}}, DNS SRV Service {{DNS-SRV}}, or an ALPN {{ALPN}}
  identifier.

delegated domain:
: A domain name or host name that is explicitly configured for communicating
  with the source domain, either by the human user controlling the client
  or by a trusted administrator.  For example, a server at mail.example.net
  could be a delegated domain for connecting to an IMAP server hosting an email address of
  user@example.net.

derived domain:
: A domain name or host name that a client has derived from the source domain
  in an automated fashion (e.g., by means of a {{DNS-SRV}} lookup).

identifier:
: A particular instance of an identifier type that is either presented by a
  server in a certificate or referenced by a client for matching purposes.

identifier type:
: A formally-defined category of identifier that can be included in a
  certificate and therefore that can also be used for matching purposes. For
  conciseness and convenience, we define the following identifier types of
  interest:

  * DNS-ID: a subjectAltName entry of type dNSName as defined in {{PKIX}}.

  * IP-ID: a subjectAltName entry of type iPAddress as defined in {{PKIX}}.

  * SRV-ID: a subjectAltName entry of type otherName whose name form is
    SRVName, as defined in {{SRVNAME}}.

  * URI-ID: a subjectAltName entry of type uniformResourceIdentifier
    as defined in {{PKIX}}. This entry MUST include both a "scheme" and
    a "host" component (or its equivalent) that matches the "reg-name"
    rule (where the quoted terms represent the associated {{ABNF}}
    productions from {{URI}}).  If the entry does not have both, it is not a
    valid URI-ID and MUST be ignored.

PKIX:
: The short name for the Internet Public Key Infrastructure using X.509
  defined in {{PKIX}}.  That document provides a profile of the X.509v3
  certificate specifications and X.509v2 certificate revocation list (CRL)
  specifications for use in the Internet.

presented identifier:
: An identifier presented by a server to a client within a PKIX certificate
  when the client attempts to establish secure communication with the server.
  The certificate can include one or more presented identifiers of different
  types, and if the server hosts more than one domain then the certificate
  might present distinct identifiers for each domain.

reference identifier:
: An identifier used by the client when examining presented identifiers.
  It is constructed from the source domain, and optionally an application
  service type.

Relative Distinguished Name (RDN):
: An ASN.1-based construction which itself is a building-block component of
  Distinguished Names. See {{LDAP-DN, Section 2}}.

source domain:
: The FQDN that a client expects an application
  service to present in the certificate. This is typically input by
  a human user, configured into a client, or provided by reference such as
  a URL. The combination of a source domain and, optionally, an application
  service type enables a client to construct one or more reference
  identifiers.

subjectAltName entry:
: An identifier placed in a subjectAltName extension.

subjectAltName extension:
: A standard PKIX extension enabling identifiers of various types to be
  bound to the certificate subject.

subjectName:
: The name of a PKIX certificate's subject, encoded in a certificate's
  subject field (see {{PKIX, Section 4.1.2.6}}).

TLS uses the words client and server, where the client is the entity
that initiates the connection.  In many cases, this is consistent with common practice,
such as a browser connecting to a Web origin.
For the sake of clarity, and to follow the usage in {{TLS}} and related
specifications, we will continue
to use the terms client and server in this document.
However, these are TLS-layer roles, and the application protocol
could support the TLS server making requests to the TLS client after the
TLS handshake; there is no requirement that the roles at the application
layer match the TLS layer.

Security-related terms used in this document, but not defined here or in
{{PKIX}} should be understood in the the sense defined in {{SECTERMS}}. Such
terms include "attack", "authentication", "identity", "trust", "validate",
and "verify".

{::boilerplate bcp14-tagged}

# Identifying Application Services {#names}

This document assumes that an application service is identified by a DNS domain
name (e.g., `example.com`), an IP address (IPv4 or IPv6), or by an identifier
that contains additional supplementary information.  Supplementary information
is limited to the application service type as expressed in SRV (e.g., "the IMAP
server at example.net") or a URI.

The DNS name conforms to one of the following forms:

1. A "traditional domain name", i.e., a FQDN (see {{DNS-CONCEPTS}}) all of
  whose labels are "LDH labels" as described in {{IDNA-DEFS}}.  Informally,
  such labels are constrained to {{US-ASCII}} letters, digits, and the
  hyphen, with the hyphen prohibited in the first character position.
  Additional qualifications apply (refer to the above-referenced
  specifications for details), but they are not relevant here.

2. An "internationalized domain name", i.e., a DNS domain name that includes at
  least one label containing appropriately encoded Unicode code points
  outside the traditional US-ASCII range. That is, it contains at least one
  U-label or A-label, but otherwise may contain any mixture of NR-LDH labels,
  A-labels, or U-labels, as described in {{IDNA-DEFS}} and the associated
  documents.

An IP address is either a 4-byte IPv4 address {{!IPv4=RFC0791}} or a 16-byte
IPv6 address {{!IPv6=RFC4291}}.  The identifer might need to be converted from a
textual representation to obtain this value.

From the perspective of the application client or user, some identifiers are
*direct* because they are provided directly by a human user.  This includes
runtime input, prior configuration, or explicit acceptance of a client
communication attempt.  Other names are *indirect* because they are
automatically resolved by the application based on user input, such as a
target name resolved from a source name using DNS SRV or {{NAPTR}} records.
The distinction matters most for certificate consumption, specifically
verification as discussed in this document.

From the perspective of the application service, some identifiers are
*unrestricted* because they can be used in any type of service, such as a
single certificate being used for both the HTTP and IMAP services at the host
"example.com".  Other identifiers are *restricted* because they can only be used for
one type of service, such as a special-purpose certificate that can only be
used for an IMAP service.  This distinction matters most for certificate
issuance.

We can categorize the three identifier types as follows:

* A DNS-ID is direct and unrestricted.

* An IP-ID is direct and unrestricted.

* An SRV-ID is typically indirect but can be direct, and is restricted.

* A URI-ID is direct and restricted.

It is important to keep these distinctions in mind, because best practices
for the deployment and use of the identifiers differ.
Note that cross-protocol attacks such as {{ALPACA}}
are possibile when two
different protocol services use the same certificate.
This can be addressed by using restricted identifiers, or deploying
services so that they do not share certificates.
Protocol specifications MUST specify which identifiers are
mandatory-to-implement and SHOULD provide operational guidance when necessary.

The Common Name RDN MUST NOT be used to identify a service because
it is not strongly typed (essentially free-form text) and therefore
suffers from ambiguities in interpretation.

For similar reasons, other RDNs within the subjectName MUST NOT be used to
identify a service.

An IP address that is the result of a DNS query is not direct. Use of IP-IDs
that are not direct is out of scope for this document.

# Designing Application Protocols {#design}

This section defines how protocol designers should reference this document,
which would typically be a normative reference in their specification.
Its specification
MAY choose to allow only one of the identifier types defined here.

If the technology does not use DNS SRV records to resolve the DNS domain
names of application services then its specification MUST state that SRV-ID
as defined in this document is not supported.  Note that many existing
application technologies use DNS SRV records to resolve the DNS domain names
of application services, but do not rely on representations of those records
in PKIX certificates by means of SRV-IDs as defined in {{SRVNAME}}.

If the technology does not use URIs to identify application services, then
its specification MUST state that URI-ID as defined in this document is not
supported.  Note that many existing application technologies use URIs to
identify application services, but do not rely on representation of those
URIs in PKIX certificates by means of URI-IDs.

A technology MAY disallow the use of the wildcard character in DNS names. If
it does so, then the specification MUST state that wildcard certificates as
defined in this document are not supported.

A protocol can allow the use of an IP address in place of a DNS name.  This
might use the same field without distinguishing the type of identifier, see for
example {{URI}}.  In this case, applications need to be aware that the textual
representation of an IPv4 address can appear to be a valid DNS name, though it is not.  The two
types can be distinguished by first testing if the identifier is a valid IPv4
address.  Note also that by policy, Top-Level Domains ({{DNS-TERMS}}) do not
start with a digit (TODO: citation needed).

# Representing Server Identity {#represent}

This section provides instructions for issuers of
certificates.

## Rules {#represent-rules}

When a certificate authority issues a certificate based on the FQDN
at which the application service provider
will provide the relevant application, the following rules apply to
the representation of application service identities.
Note that some of these rules are cumulative
and can interact in important ways that are illustrated later in this
document.

1. The certificate SHOULD include a "DNS-ID" as a baseline
   for interoperability.

2. If the service using the certificate deploys a technology for which
  the relevant specification stipulates that certificates ought to
  include identifiers of type SRV-ID (e.g., {{XMPP}}),
  then the certificate SHOULD include an SRV-ID.

3. If the service using the certificate deploys a technology for which
  the relevant specification stipulates that certificates ought to include
  identifiers of type URI-ID (e.g., {{SIP}} as specified by
  {{SIP-CERTS}}), then the certificate SHOULD include a URI-ID.  The scheme
  MUST be that of the protocol associated with the application service type
  and the "host" component (or its equivalent) MUST be the FQDN
  of the service.  The application protocol specification
  MUST specify which URI schemes are acceptable in URI-IDs contained in PKIX
  certificates used for the application protocol (e.g., `sip` but not `sips`
  or `tel` for SIP as described in {{SIP-SIPS}}).

4. The certificate MAY contain more than one DNS-ID, SRV-ID, URI-ID, or IP-ID
  as further explained under {{security-multi}}.

5. The certificate MAY include other application-specific identifiers
  for compatibility with a deployed base. Such identifiers are out of
  scope for this specification.

## Examples {#represent-examples}

Consider a simple website at `www.example.com`, which is not discoverable via
DNS SRV lookups.  Because HTTP does not specify the use of URIs in server
certificates, a certificate for this service might include only a DNS-ID of
`www.example.com`.

Consider the same website, which is reachable by a fixed IP address of
`2001:db8::5c`.  The certificate might include this value in an IP-ID to allow
clients to use the fixed IP address as a reference identity.

Consider an IMAP-accessible email server at the host `mail.example.net`
servicing email addresses of the form `user@example.net` and discoverable via
DNS SRV lookups on the application service name of `example.net`.  A
certificate for this service might include SRV-IDs of `_imap.example.net` and
`_imaps.example.net` (see {{EMAIL-SRV}}) along with DNS-IDs of `example.net`
and `mail.example.net`.

Consider a SIP-accessible voice-over-IP (VoIP) server at the host
`voice.example.edu` servicing SIP addresses of the form
`user@voice.example.edu` and identified by a URI of \<sip:voice.example.edu>.
A certificate for this service would include a URI-ID of
`sip:voice.example.edu` (see {{SIP-CERTS}}) along with a DNS-ID of
`voice.example.edu`.

Consider an XMPP-compatible instant messaging (IM) server at the host
`im.example.org` servicing IM addresses of the form `user@im.example.org` and
discoverable via DNS SRV lookups on the `im.example.org` domain.  A
certificate for this service might include SRV-IDs of
`_xmpp-client.im.example.org` and `_xmpp-server.im.example.org` (see
{{XMPP}}), a DNS-ID of `im.example.org`.

# Requesting Server Certificates {#request}

This section provides instructions for service providers regarding
the information to include in certificate signing requests (CSRs).
In general, service providers SHOULD request certificates that
include all of the identifier types that are required or recommended for
the application service type that will be secured using the certificate to
be issued.

A service provider SHOULD request certificates with as few identifiers as
necessary to identify a single service; see {{security-multi}}.

If the certificate will be used for only a single type of application
service, the service provider SHOULD request a certificate that includes
DNS-ID or IP-ID values that identify that service or,
if appropriate for the application service type, SRV-ID or
URI-ID values that limit the deployment scope of the certificate to only the
defined application service type.

If the certificate might be used for any type of application service, then
the service provider SHOULD request a certificate that includes
only DNS-IDs or IP-IDs. Again, because of multi-protocol attacks this practice is
discouraged; this can be mitigated by deploying only one service on
a host.

If a service provider offers multiple application service types and wishes to
limit the applicability of certificates using SRV-IDs or URI-IDs, they SHOULD
request multiple certificates, rather than a single certificate containing
multiple SRV-IDs or URI-IDs each identifying a different application service
type. This rule does not apply to application service type "bundles" that
identify distinct access methods to the same underlying application such as
an email application with access methods denoted by the application service
types of `imap`, `imaps`, `pop3`, `pop3s`, and `submission` as described in
{{EMAIL-SRV}}.

# Verifying Service Identity {#verify}

At a high level, the client verifies the application service's
identity by performing the following actions:

1. The client constructs a list of acceptable reference identifiers
  based on the source domain and, optionally, the type of service to
  which the client is connecting.

2. The server provides its identifiers in the form of a PKIX
   certificate.

3. The client checks each of its reference identifiers against the
  presented identifiers for the purpose of finding a match. When checking a
  reference identifier against a presented identifier, the client matches the
  source domain of the identifiers and, optionally, their application service
  type.

Naturally, in addition to checking identifiers, a client should perform
further checks, such as expiration and revocation, to ensure that the server
is authorized to provide the requested service.  Because such checking is not a
matter of verifying the application service identity presented in a
certificate, methods for doing so are out of scope for
this document.

## Constructing a List of Reference Identifiers {#verify-reference}

### Rules {#verify-reference-rules}

The client MUST construct a list of acceptable reference identifiers,
and MUST do so independently of the identifiers presented by the
service.

The inputs used by the client to construct its list of reference identifiers
might be a URI that a user has typed into an interface (e.g., an HTTPS URL
for a website), configured account information (e.g., the domain name of a
host for retrieving email, which might be different from the DNS domain name
portion of a username), a hyperlink in a web page that triggers a browser to
retrieve a media object or script, or some other combination of information
that can yield a source domain and an application service type.

The client might need to extract the source domain and application service
type from the input(s) it has received.  The extracted data MUST include only
information that can be securely parsed out of the inputs, such as parsing
the FQDN or IP address out of the "host" component or deriving the application service type
from the scheme of a URI.  Other possibilities include pulling the data from
a delegated domain that is explicitly established via client or system
configuration or resolving the data via {{DNSSEC}}.
These considerations apply only to extraction of the source domain from the
inputs.  Naturally, if the inputs themselves are invalid or corrupt (e.g., a
user has clicked a link provided by a malicious entity in a phishing attack),
then the client might end up communicating with an unexpected application
service.

For example, given an input URI of \<sip:alice@example.net>, a client
would derive the application service type `sip` from the scheme
and parse the domain name `example.net` from the host component.

Each reference identifier in the list MUST be based on the user inputs and
MUST NOT be based on a derived domain such as a domain name discovered
through DNS resolution of those inputs.  This rule is important because
only a match between the user inputs and a presented identifier enables the
client to be sure that the certificate can legitimately be used to secure the
client's communication with the server. This removes
DNS and DNS resolution from the attack surface.

Using the combination of FQDN(s) or IP address(es), plus optionally an application service type, the client
MUST construct its list of reference identifiers in accordance with the
following rules:

* If a server for the application service type is typically associated
  with a URI for security purposes (i.e., a formal protocol document
  specifies the use of URIs in server certificates), then the reference identifier
  SHOULD be a URI-ID.

* If a server for the application service type is typically discovered
  by means of DNS SRV records, then the reference identifier SHOULD be an SRV-ID.

* If the reference identifier is an IP address, the reference identifier is an
  IP-ID.

* In the absence of more specific identifiers, the reference identifier is a DNS-ID.
  A reference identifier of type DNS-ID can be directly constructed from a
  FQDN that is (a) contained in or securely derived from the inputs, or
  (b) explicitly associated with the source domain by means of user
  configuration.


Which identifier types a client includes in its list of reference
identifiers, and their priority, is a matter of local policy.  For example, a
client that is built to connect only to a particular kind of service might be
configured to accept as valid only certificates that include an SRV-ID for
that application service type.  By contrast, a more lenient client, even if
built to connect only to a particular kind of service, might include both
SRV-IDs, DNS-IDs, and IP-IDs in its list of reference identifiers.

### Examples {#verify-reference-examples}

The following examples are for illustrative purposes only and are not
intended to be comprehensive.

1. A web browser that is connecting via HTTPS to the website at `https://www.example.com/`
would have a single reference identifier: a DNS-ID of `www.example.com`.

2. A web browser connecting to `https://192.0.2.107/` would have a single IP-ID
reference identifier of `192.0.2.107`.

3. A mail user agent that is connecting via IMAPS to the email service at
`example.net` (resolved as `mail.example.net`) might have three reference
identifiers: an SRV-ID of `_imaps.example.net` (see {{EMAIL-SRV}}), and
DNS-IDs of `example.net` and `mail.example.net`.  An email user agent that
does not support {{EMAIL-SRV}} would probably be explicitly configured to
connect to `mail.example.net`, whereas an SRV-aware user agent would derive
`example.net` from an email address of the form `user@example.net` but might
also accept `mail.example.net` as the DNS domain name portion of reference
identifiers for the service.

4. A voice-over-IP (VoIP) user agent that is connecting via SIP to the voice
service at `voice.example.edu` might have only one reference identifier:
a URI-ID of `sip:voice.example.edu` (see {{SIP-CERTS}}).

5. An instant messaging (IM) client that is connecting via XMPP to the IM
service at `im.example.org` might have three reference identifiers: an
SRV-ID of `_xmpp-client.im.example.org` (see {{XMPP}}), a DNS-ID of
`im.example.org`, and an XMPP-specific `XmppAddr` of `im.example.org`
(see {{XMPP}}).

In all of these cases, presented identifiers that do not match the reference
identifier(s) would be rejected; for instance:

* With regard to the first example a DNS-ID of "web.example.com" would
  be rejected because the DNS domain name portion does not match
  "www.example.com".

* With regard to the third example, a URI-ID of "sip:www.example.edu"
  would be rejected because the DNS domain name portion does not match
  "voice.example.edu" and a DNS-ID of "voice.example.edu" would be
  rejected because it lacks the appropriate application service type
  portion (i.e., it does not specify a "sip:" URI).

## Preparing to Seek a Match {#verify-seek}

Once the client has constructed its list of reference identifiers and has
received the server's presented identifiers,
the client checks its reference identifiers against the presented identifiers
for the purpose of finding a match.
The search fails if the client exhausts
its list of reference identifiers without finding a match.  The search succeeds
if any presented identifier matches one of the reference identifiers, at
which point the client SHOULD stop the search.

Before applying the comparison rules provided in the following
sections, the client might need to split the reference identifier into
components.
Each reference identifier produces either a domain name or an IP address and
optionally an application service type as follows:

* A DNS-ID reference identifier MUST be used directly as the DNS domain
  name and there is no application service type.

* An IP-ID reference identifier MUST be exactly equal, octet for octet, to the value of a
  iPAddress entry in subjectAltName. There is no application service type.

* For an SRV-ID reference identifier, the DNS domain name portion is
  the Name and the application service type portion is the Service.  For
  example, an SRV-ID of `_imaps.example.net` has a DNS domain name portion
  of `example.net` and an application service type portion of
  `imaps`, which maps to the IMAP application protocol as explained in
  {{EMAIL-SRV}}.

* For a reference identifier of type URI-ID, the DNS domain name
  portion is the "reg-name" part of the "host" component and the application
  service type portion is the scheme, as defined above.  Matching only the
  "reg-name" rule from {{URI}} limits the additional domain name validation
  ({{verify-domain}}) to DNS domain names or non-IP hostnames.
  A URI that contains an IP address might be matched against an IP-ID in place
  of a URI-ID by some lenient clients.  This document does not describe how a
  URI that contains no "host" component can be matched.  Note that extraction of the
  "reg-name" might necessitate normalization of the URI (as explained in
  {{Section 6 of URI}}).  For example, a URI-ID of `sip:voice.example.edu` would be split
  into a DNS domain name portion of `voice.example.edu` and an application
  service type of `sip` (associated with an application protocol of SIP as
  explained in {{SIP-CERTS}}).

If the reference identifier produces a domain name, the client MUST match the
DNS name; see {{verify-domain}}.
If the reference identifier produces an IP address, the client MUST match the IP
address; see {{verify-ip}}.
If an application service type is present it MUST also match the
service type as well; see {{verify-app}}.

## Matching the DNS Domain Name Portion {#verify-domain}

This section describes how the client must determine if the presented DNS
name matches the reference DNS name.  The rules differ depending on whether
the domain to be checked is a traditional domain name or an
internationalized domain name, as defined in {{names}}.  For clients
that support names containing the wildcard character "\*", this section
also specifies a supplemental rule for such "wildcard certificates".
This section uses the description of labels and domain names in
{{DNS-CONCEPTS}}.

If the DNS domain name portion of a reference identifier is a traditional
domain name, then matching of the reference identifier against the presented
identifier MUST be performed by comparing the set of domain name labels using
a case-insensitive ASCII comparison, as clarified by {{DNS-CASE}}.  For
example, `WWW.Example.Com` would be lower-cased to `www.example.com` for
comparison purposes.  Each label MUST match in order for the names to be
considered to match, except as supplemented by the rule about checking of
wildcard labels given below.

If the DNS domain name portion of a reference identifier is an
internationalized domain name, then the client MUST convert any U-labels
{{IDNA-DEFS}} in the domain name to A-labels before checking the domain name.
In accordance with {{IDNA-PROTO}}, A-labels MUST be compared as
case-insensitive ASCII.  Each label MUST match in order for the domain names
to be considered to match, except as supplemented by the rule about checking
of wildcard labels given below.

If the technology specification supports wildcards, then the client MUST
match the reference identifier against a presented identifier whose DNS
domain name portion contains the wildcard character "\*" in a label provided
these requirements are met:

1. There is only one wildcard character.

2. The wildcard character appears only as the complete content of the left-most label.

If the requirements are not met, the presented identifier is invalid and MUST
be ignored.

A wildcard in a presented identifier can only match exactly one label in a
reference identifier. Note that this is not the same as DNS wildcard
matching, where the "\*" label always matches at least one whole label and
sometimes more. See {{DNS-CONCEPTS, Section 4.3.3}} and {{DNS-WILDCARDS}}.

For information regarding the security characteristics of wildcard
certificates, see {{security-wildcards}}.

## Matching an IP Address Portion {#verify-ip}

An IP-ID matches based on an octet-for-octet comparison of the bytes of the reference identity with the
bytes contained in the iPAddress subjectAltName.
The iPAddress field does not include the IP version, so IPv4 addresses are
distinguish from IPv6 addresses only by their length (4 as opposed to 16 bytes).

For an IP address that appears in a URI-ID, the "host" component of both the
reference identity and the presented identifier.  These are parsed as either
an "IP-literal" (following {{!IPv6}}) or an "IPv4address" (following {{!IPv4}}).
If the resulting bytes are equal, the IP address matches.

This document does not specify how an SRV-ID reference identity can include an
IP address.

## Matching the Application Service Type Portion {#verify-app}

The rules for matching the application service type depend on whether
the identifier is an SRV-ID or a URI-ID.

These identifiers provide an application service type portion to be checked,
but that portion is combined only with the DNS domain name portion of the
SRV-ID or URI-ID itself.  For example, if a client's list of reference
identifiers includes an SRV-ID of `_xmpp-client.im.example.org` and a DNS-ID
of `apps.example.net`, the client MUST check both the combination of an
application service type of `xmpp-client` and a DNS domain name of
`im.example.org` and, separately,
a DNS domain name of `apps.example.net`.  However, the
client MUST NOT check the combination of an application service type of
`xmpp-client` and a DNS domain name of `apps.example.net` because it does not
have an SRV-ID of `_xmpp-client.apps.example.net` in its list of reference
identifiers.

If the identifier is an SRV-ID, then the application service name MUST
be matched in a case-insensitive manner, in accordance with {{DNS-SRV}}.
Note that the `_` character is prepended to the service identifier in
DNS SRV records and in SRV-IDs (per {{SRVNAME}}), and thus does not
need to be included in any comparison.

If the identifier is a URI-ID, then the scheme name portion MUST be
matched in a case-insensitive manner, in accordance with {{URI}}.
Note that the `:` character is a separator between the scheme name
and the rest of the URI, and thus does not need to be included in any
comparison.

## Outcome {#outcome}

If the client has found a presented identifier that matches a reference
identifier, then the service identity check has succeeded.  In this case, the
client MUST use the matched reference identifier as the validated identity of
the application service.

If the client does not find a presented identifier matching any of the
reference identifiers, then the client MUST proceed as described as follows.

If the client is an automated application,
then it SHOULD terminate the communication attempt with a bad
certificate error and log the error appropriately.  The application MAY
provide a configuration setting to disable this behavior, but it MUST enable
it by default.

If the client is one that is directly controlled by a human
user, then it SHOULD inform the user of the identity mismatch and
automatically terminate the communication attempt with a bad certificate
error in order to prevent users from inadvertently bypassing security
protections in hostile situations.
Such clients MAY give advanced users the option of proceeding
with acceptance despite the identity mismatch.  Although this behavior can be
appropriate in certain specialized circumstances, it needs to be handled with
extreme caution, for example by first encouraging even an advanced user to
terminate the communication attempt and, if they choose to proceed anyway, by
forcing the user to view the entire certification path before proceeding.

The application MAY also present the user with the ability to accept the
presented certificate as valid for subsequent connections.  Such ad-hoc
"pinning" SHOULD NOT restrict future connections to just the pinned
certificate. Local policy that statically enforces a given certificate for a
given peer SHOULD made available only as prior configuration, rather than a
just-in-time override for a failed connection.

# Security Considerations {#security}

## Wildcard Certificates {#security-wildcards}

Wildcard certificates automatically vouch for any single-label host names
within their domain, but not multiple levels of domains.  This can be
convenient for administrators but also poses the risk of vouching for rogue
or buggy hosts. See for example {{Defeating-SSL}} (beginning at slide 91) and
{{HTTPSbytes}} (slides 38-40).

Protection against a wildcard that identifies a public suffix
{{Public-Suffix}}, such as `*.co.uk` or `*.com`, is beyond the scope of this
document.

## Internationalized Domain Names {#security-idn}

Allowing internationalized domain names can lead to visually similar
characters, also referred to as "confusables", being included within
certificates. For discussion, see for example {{IDNA-DEFS, Section 4.4}}
and {{UTS-39}}.

## IP Addresses

The TLS Server Name Indication (SNI) extension only conveys domain names.
Therefore, a client with an IP-ID reference identity cannot present any
information about its reference identity when connecting to a server.  Servers
that wish to present an IP-ID therefore need to present this identity when a
connection is made without SNI.

The textual representation of an IPv4 address might be misinterpreted as a valid
FQDN in some contexts. This can result in different security treatment that might cause
different components of a system to classify the value differently, which might lead
to vulnerabilities. For example, one system component enforces a security rule
that is conditional on the type of identifier.  This component misclassifies an
IP address as an FQDN.  A different component correctly classifies the
identifier, but might incorrectly assume that rules regarding IP addresses have
been enforced.  Consistent classification of identifiers avoids this problem.

## Multiple Presented Identifiers {#security-multi}

A given application service might be addressed by multiple DNS domain names
for a variety of reasons, and a given deployment might service multiple
domains or protocols. TLS Extensions such as TLS Server Name Indication
(SNI), discussed in {{TLS, Section 4.4.2.2}}, and Application Layer Protocol
Negotiation (ALPN), discussed in {{ALPN}}, provide a way for the application
to indicate the desired identifier and protocol to the server, which it
can then use to select the most appropriate certificate.

This specification allows multiple DNS-IDs, IP-IDs, SRV-IDs, or URI-IDs in a
certificate.  As a result, an application service can use the same
certificate for multiple hostnames, such as when a client does not support
the TLS SNI extension, or for multiple protocols, such as SMTP and HTTP, on a
single hostname.  Note that the set of names in a certificate is the set of
names that could be affected by a compromise of any other server named in
the set: the strength of any server in the set of names is determined by the
weakest of those servers that offer the names.

The way to mitigate this risk is to limit the number of names that
any server can speak for, and to ensure that all servers in the set
have a strong minimum configuration as described in {{RFC7525bis}}.

## Multiple Reference Identifiers

This specification describes how a client may construct multiple acceptable
reference identifiers, and may match any of those reference identifiers with
the set of presented identifiers. {{PKIX, Section 4.2.1.10}} describes a
mechanism to allow CA certificates to be constrained in the set of presented
identifiers that they may include within server certificates.  However, these
constraints only apply to the explicitly enumerated name forms. For example,
a CA that is only name constrained for DNS-IDs is not constrained for SRV-IDs
and URI-IDs, unless those name forms are also explicitly included within the
name constraints extension.

A client that constructs multiple reference identifiers of different types,
such as both DNS-ID and SRV-IDs, as described in {{verify-reference-rules}},
SHOULD take care to ensure that CAs issuing such certificates are
appropriately constrained. This MAY take the form of local policy through
agreement with the issuing CA, or MAY be enforced by the client requiring
that if one form of presented identifier is constrained, such as a dNSName
name constraint for DNS-IDs, then all other forms of acceptable reference
identities are also constrained, such as requiring a uniformResourceIndicator
name constraint for URI-IDs.

# IANA Considerations

This document has no actions for IANA.

--- back

# Changes from RFC 6125 {#changes}

This document revises and obsoletes {{VERIFY}} based
on the decade of experience and changes since it was published.
The major changes, in no particular order, include:

- The only legal place for a certificate wildcard is as the complete left-most
  component in a domain name.

- The server identity can only be expressed in the subjectAltNames
  extension; it is no longer valid to use the commonName RDN,
  known as `CN-ID` in {{VERIFY}}.

- Detailed discussion of pinning (configuring use of a certificate that
  doesn't match the criteria in this document) has been removed and replaced
  with two paragraphs in {{outcome}}.

- The sections detailing different target audiences and which sections
  to read (first) have been removed.

- References to the X.500 directory, the survey of prior art, and the
  sample text in Appendix A have been removed.

- All references have been updated to the current latest version.

- The TLS SNI extension is no longer new, it is commonplace.

- Additional text on multiple identifiers, and their security considerations,
  has been added.

- IP-ID reference identifiers are added.  This builds on the definition in {{Section
  4.3.5 of HTTP}}.

# Contributors

Jeff Hodges co-authored the previous version of these recommendations, {{VERIFY}}.
The authors gratefully acknowledge his essential contributions to this work.

# Acknowledgements {#acknowledgements}
{: numbered='false'}

We gratefully acknowledge everyone who contributed to the previous
version of these recommendations, {{VERIFY}}.
Thanks also to Carsten Bormann for converting the previous document
to Markdown so that we could more easily use Martin Thomson's `i-d-template`
software.

In addition to discussion on the mailing list, the following people
provided especially helpful feedback:
Viktor Dukhovni,
Jim Fenton,
Olle Johansson,
John Mattson,
Alexey Melnikov,
Yaron Sheffer,
Ryan Sleevi,
Brian Smith,
and
Martin Thomson.

A few descriptive sentences were borrowed from {{RFC7525bis}}.
