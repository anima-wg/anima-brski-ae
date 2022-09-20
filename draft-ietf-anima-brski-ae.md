---

title: 'BRSKI-AE: Alternative Enrollment Protocols in BRSKI'
abbrev: BRSKI-AE
docname: draft-ietf-anima-brski-ae-03
stand_alone: true
ipr: trust200902
area: Operations and Management
wg: ANIMA WG
kw: Internet-Draft
cat: std
consensus: true
date: 2022
pi:
  toc: 'yes'
  compact: 'yes'
  symrefs: 'yes'
  sortrefs: 'yes'
  iprnotified: 'no'
  strict: 'yes'
author:
- ins: D. von Oheimb
  name: David von Oheimb
  role: editor
  org: Siemens AG
  abbrev: Siemens
  street: Otto-Hahn-Ring 6
  city: Munich
  code: '81739'
  country: Germany
  email: david.von.oheimb@siemens.com
  uri: https://www.siemens.com/
- ins: S. Fries
  name: Steffen Fries
  org: Siemens AG
  abbrev: Siemens
  street: Otto-Hahn-Ring 6
  city: Munich
  code: '81739'
  country: Germany
  email: steffen.fries@siemens.com
  uri: https://www.siemens.com/
- ins: H. Brockhaus
  name: Hendrik Brockhaus
  org: Siemens AG
  abbrev: Siemens
  street: Otto-Hahn-Ring 6
  city: Munich
  code: '81739'
  country: Germany
  email: hendrik.brockhaus@siemens.com
  uri: https://www.siemens.com/
- ins: E. Lear
  name: Eliot Lear
  org: Cisco Systems
  street: Richtistrasse 7
  city: Wallisellen
  code: CH-8304
  country: Switzerland
  phone: "+41 44 878 9200"
  email: lear@cisco.com
venue:
  group: anima
  anima mail: {anima@ietf.org}
  github: anima-wg/anima-brski-ae
normative:
  RFC4210:
  RFC8366:
  RFC8995:
  I-D.ietf-lamps-cmp-updates:
  I-D.ietf-lamps-lightweight-cmp-profile:
  I-D.msahni-ace-cmpv2-coap-transport:
  I-D.ietf-anima-constrained-voucher:
  IEEE.802.1AR_2009:
informative:
  RFC2986:
  RFC4211:
  RFC5272:
  RFC5652:
  RFC5929:
  RFC7030:
  RFC8894:
  IEC-62351-9:
    title: 'IEC 62351 - Power systems management and associated information exchange
      - Data and communications security - Part 9: Cyber security key management for
      power system equipment'
    author:
    - org: International Electrotechnical Commission
    date: 2017-05
    seriesinfo:
      IEC: '62351-9 '
  NERC-CIP-005-5:
    title: Cyber Security - Electronic Security Perimeter
    author:
    - org: North American Reliability Council
    date: 2013-12
    seriesinfo:
      CIP: 005-5
  ISO-IEC-15118-2:
    title: 'ISO/IEC 15118-2 Road vehicles - Vehicle-to-Grid Communication Interface
      - Part 2: Network and application protocol requirements'
    author:
    - org: International Standardization Organization / International Electrotechnical
        Commission
    date: 2014-04
    seriesinfo:
      ISO/IEC: '15118-2 '
  UNISIG-Subset-137:
    author:
    - org: UNISIG
    title: 'Subset-137; ERTMS/ETCS On-line Key Management FFFIS; V1.0.0'
    date: December 2015
    format:
      PDF: https://www.era.europa.eu/sites/default/files/filesystem/ertms/ccs_tsi_annex_a_-_mandatory_specifications/set_of_specifications_3_etcs_b3_r2_gsm-r_b1/index083_-_subset-137_v100.pdf
    ann: http://www.kmc-subset137.eu/index.php/download/
  OCPP:
    title: Open Charge Point Protocol 2.0.1 (Draft)
    author:
    - org: Open Charge Alliance
    date: 2019-12


--- abstract

This document enhances
Bootstrapping Remote Secure Key Infrastructure (BRSKI, RFC 8995)
to allow employing alternative enrollment protocols, such as CMP.

Using self-contained signed objects, the origin of enrollment requests and responses
can be authenticated independently of message transfer.
This supports end-to-end security and asynchronous operation of certificate enrollment
and provides flexibility where to authenticate and authorize certification requests.

--- middle


# Introduction

## Motivation

BRSKI, as defined in {{RFC8995}}, specifies a solution for
secure automated zero-touch bootstrapping of new devices, which are given the name _pledges_.
This includes the discovery of the registrar in the target domain,
time synchronization, and the exchange of security information
necessary to establish mutual trust between pledges and the target domain.

A pledge gains trust in the target domain via the domain registrar as follows:
It obtains security information about the domain,
specifically a domain certificate to be trusted,
by requesting a voucher object defined in {{RFC8366}}.
Such a voucher is a self-contained signed object
originating from a Manufacturer Authorized Signing Authority (MASA).
Therefore, the voucher may be provided
in online mode (synchronously) or offline mode (asynchronously).
The pledge can authenticate the voucher
because it is shipped with trust anchor(s) by its manufacturer such that
it can validate signatures (including related certificates) by the MASA.

Trust by the target domain in a pledge is established by providing the pledge
with a domain-specific LDevID certificate.
The certification request of the pledge is signed using its IDevID secret and can be
validated by the target domain using the trust anchor of the pledge manufacturer,
which needs to pre-installed in the domain.

SZTP {{?RFC8572}} is an example of another mode where vouchers may be
delivered asynchronously by tools such as portable USB "thumb" drives.
However, SZTP does not do signed voucher requests,
so it does not allow the domain to verify the identity of the device
in the same way, nor does it deploy LDevIDs to the device in the same way.

For enrolling devices with LDevID certificates,
BRSKI typically utilizes Enrollment over Secure Transport (EST) {{RFC7030}}.
EST has its specific characteristics, detailed in {{using-est}}.
In particular, it requires online or on-site availability of the RA
for performing the data origin authentication and final authorization decision
on the certification request.
This type of enrollment can be called 'synchronous enrollment'.
For various reasons,
it may be preferable to use alternative enrollment protocols such as
the Certificate Management Protocol (CMP) {{RFC4210}}
profiled in {{I-D.ietf-lamps-lightweight-cmp-profile}}
or Certificate Management over CMS (CMC) {{RFC5272}}.
These protocols are more flexible, and
by representing the certification request messages as authenticated self-contained objects,
they are designed to be independent of the transfer mechanism.

Depending on the application scenario,
the required RA/CA components may not be part of the BRSKI registrar.
They even may not be available on-site but rather be
provided by remote backend systems. The registrar or its deployment site may not have
an online connection with them or the connectivity may be intermittent.
This may be due to security requirements for operating the backend systems
or due to site deployments where on-site or always-online operation
may be not feasible or too costly.
In such scenarios, the authentication and authorization of certification requests
will not or can not be performed on-site at enrollment time.
In this document, enrollment that is not performed in a (time-wise) consistent
way is called 'asynchronous enrollment'.
Asynchronous enrollment requires a store-and-forward transfer of certification
requests along with the information needed for authenticating the requester.
This allows offline processing the request.

Application scenarios may also involve network segmentation, which is utilized
in industrial systems to separate domains with different security needs.
Such scenarios lead to similar requirements if the TLS connection
carrying the requester authentication is terminated
and thus request messages need to be forwarded on further channels
before the registrar/RA can authorize the certification request.
In order to preserve the requester authentication, authentication information
needs to be retained and ideally bound directly to the certification request.

There are basically two approaches for forwarding certification requests
along with requester authentication information:

* A trusted component (e.g., a local RA) in the target domain is needed
  that forwards the certification request combined with the validated identity of
  the requester (e,g., its IDevID certificate)
  and an indication of successful verification of
  the proof-of-possession (of the corresponding private key) in a way
  preventing changes to the combined information.
  When connectivity is available, the trusted component
  forwards the certification request together with the requester information
  (authentication and proof-of-possession) for further processing.
  This approach offers only hop-by-hop security.
  The backend PKI must rely on the local pledge authentication result
  provided by the local RA
  when performing the authorization of the certification request.
  In BRSKI, the EST server is such a trusted component,
  being co-located with the registrar in the target domain.

* Involved components use authenticated self-contained objects for the enrollment,
  directly binding the certification request and the requester authentication
  in a cryptographic way.
  This approach supports end-to-end security,
  without the need to trust in intermediate domain components.
  Manipulation of the request and the requester identity information
  can be detected during the validation of the self-contained signed object.

Focus of this document is the support of alternative enrollment protocols that allow
using authenticated self-contained objects for device credential bootstrapping.
This enhancement of BRSKI is named BRSKI-AE, where AE stands for
**A**lternative **E**nrollment and for **A**synchronous **E**nrollment.
This specification carries over the main characteristics of BRSKI,
namely that the pledge obtains trust anchor information
for authenticating the domain registrar and other target domain components
as well as a domain-specific X.509 device certificate (the LDevID certificate)
along with the corresponding private key (the LDevID secret) and certificate chain.

The goals are to enhance BRSKI to

* support alternative enrollment protocols,

* support end-to-end security for enrollment, and

* make it applicable to scenarios involving asynchronous enrollment.

This is achieved by

* extending the well-known URI approach with an additional path element
  indicating the enrollment protocol being used, and

* defining a certificate waiting indication and handling, for the case that the
  certifying component is (temporarily) not available.

This specification can be applied to both synchronous and asynchronous enrollment.

In contrast to BRSKI, this specification supports offering multiple enrollment protocols
on the infrastructure side, which enables pledges and their developers
to pick the preferred one.

## Supported Environment {#sup-env}

BRSKI-AE is intended to be used in domains that may have limited support
of on-site PKI services and comprises application scenarios like the following.

* There are requirements or implementation restrictions
  that do not allow using EST for enrolling an LDevID certificate.

* Pledges and/or the target domain already have an established
  certificate management approach different from EST that shall be reused
  (e.g., in brownfield installations).

* There is no registration authority available on site in the target domain.
  Connectivity to an off-site RA is intermittent or entirely offline.
  A store-and-forward mechanism is used
  for communicating with the off-site services.

* Authoritative actions of a local RA are limited and may not be sufficient
  for authorizing certification requests by pledges.
  Final authorization is done by an RA residing in the operator domain.


## List of Application Examples {#list-examples}

Bootstrapping can be handled in various ways, depending on the application domains.
The informative {{app-examples}} provides illustrative examples from
various industrial control system environments and operational setups.
They motivate the support of alternative enrollment protocols,
based on the following examples of operational environments:

* Rolling stock

* Building automation

* Electrical substation automation

* Electric vehicle charging infrastructures

* Infrastructure isolation policy

* Sites with insufficient level of operational security


# Terminology

{::boilerplate bcp14-tagged}

This document relies on the terminology defined in {{RFC8995}}
and {{IEEE.802.1AR_2009}}.<!-- TBD DvO: Have not found version of 2014 -->
The following terms are defined in addition:

EE:
: End entity, in the BRSKI context called pledge.
  It is the entity that is bootstrapped to the target domain.
  It holds a public-private key pair, for which it requests a public-key certificate.
  An identifier for the EE is given as the subject name of the certificate.

RA:
: Registration authority, an optional system
  component to which a CA delegates certificate management functions
  such as authenticating requesters and performing authorization checks
  on certification requests.

CA:
: Certification authority, issues certificates
  and provides certificate status information.

target domain:
: The set of entities that share a common local trust anchor,
  independent of where the entities are deployed.

site:
: Describes the locality where an entity, e.g., pledge, registrar, RA, CA, is deployed.
  Different sites can belong to the same target domain.

on-site:
: Describes a component or service or
  functionality available in the target deployment site.

off-site:
: Describes a component or service or
  functionality available in an operator site different from
  the target deployment site. This may be a central site or a
  cloud service, to which only a temporary connection is available.

asynchronous communication:
: Describes a time-wise interrupted communication
  between a pledge (EE) and a registrar or PKI component.

synchronous communication:
: Describes a time-wise uninterrupted communication
  between a pledge (EE) and a registrar or PKI component.

authenticated self-contained object:
: Describes in this context an object
  that is cryptographically bound to the IDevID certificate of a pledge.
  The binding is assumed to be provided through a digital signature
  of the actual object using the IDevID secret.


# Requirements and Mapping to Solutions {#req-sol}

## Basic Requirements

There were two main drivers for the definition of BRSKI-AE:

* The solution architecture may already use or require
  a certificate management protocol other than EST.
  Therefore, this other protocol should be usable for requesting LDevID certificates.

* The domain registrar may not be the (final) point that authenticates and authorizes
  certification requests and the pledge may not have a direct connection to it.
  Therefore, certification requests should be self-contained signed objects.

Based on the intended target environment described in {{sup-env}} and
the application examples described in {{app-examples}}, the following
requirements are derived to support authenticated self-contained objects
as containers carrying certification requests.

At least the following properties are required:

* proof-of-possession: demonstrates access to the private
  key corresponding to the public key contained in a certification request.
  This is typically achieved by a self-signature using the corresponding private key.

* proof-of-identity: provides data origin authentication of
  the certification request. This typically is achieved by a signature
  using the IDevID secret of the pledge.

The rest of this section gives an incomplete list of solution examples,
based on existing technology described in IETF documents:

## Solution Options for Proof-of-possession

  Certification request objects: Certification requests are
  data structures protecting only the integrity of the contained data
  and providing proof-of-possession for a (locally generated) private key.
  Examples for certification request data structures are:

  * PKCS#10 {{RFC2986}}. This certification request structure is self-signed to
    protect its integrity and prove possession of the private key
    that corresponds to the public key included in the request.

  * CRMF {{RFC4211}}. This certificate request message format also supports
    integrity protection and proof-of-possession,
    typically by a self-signature generated over (part of) the structure
    with the private key corresponding to the included public key.
    CRMF also supports further proof-of-possession methods
    for types of keys that do not support any signature algorithm.

  The integrity protection of certification request fields includes the public
  key because it is part of the data signed by the corresponding private key.
  Yet note that for the above examples this is not sufficient to provide data
  origin authentication, i.e., proof-of-identity. This extra property can be
  achieved by an additional binding to the IDevID of the pledge.
  This binding to the source authentication supports the
  authorization decision of the certification request.
  The binding of data
  origin authentication to the certification request may be
  delegated to the protocol used for certificate management.

## Solution Options for Proof-of-identity

  The certification request should be bound to
  an existing authenticated credential (here, the IDevID certificate) to enable a proof
  of identity and, based on it, an authorization of the certification request.
  The binding may be achieved through security options in an
  underlying transport protocol such as TLS if the authorization of the
  certification request is (completely) done at the next communication hop.
  This binding can also be done in a transport-independent way by wrapping the
  certification request with a signature employing an existing IDevID.
  the BRSKI context, this will be the IDevID.
  This requirement is addressed by existing enrollment protocols
  in various ways, such as:

  * EST {{RFC7030}} utilizes PKCS#10 to
    encode the certification request. The Certificate Signing
    Request (CSR) optionally provides a binding to the underlying TLS session
    by including the tls-unique value in the self-signed PKCS#10 structure.
    The tls-unique value results from the TLS handshake.
    Since the TLS handshake includes client
    authentication and the pledge utilizes its IDevID for it,
    the proof-of-identity is provided by such a binding to the TLS session.
    This can be supported using the EST /simpleenroll endpoint.
    Note that the binding of the TLS handshake to the CSR is optional in EST.
    As an alternative to binding to the underlying
    TLS authentication in the transport layer, {{RFC7030}} sketches wrapping the CSR
    with a Full PKI Request message using an existing certificate.

  * SCEP {{RFC8894}} supports using a shared secret (passphrase) or
    an existing certificate to protect CSRs based on
    SCEP Secure Message Objects using CMS wrapping
    ({{RFC5652}}). Note that the wrapping using
    an existing IDevID in SCEP is referred to as renewal.
    Thus SCEP does not rely on the security of the underlying transfer.

  * CMP {{RFC4210}} supports using a shared secret (passphrase) or an existing
    certificate, which may be an IDevID credential, to authenticate
    certification requests via the PKIProtection structure in a PKIMessage.
    The certification request is typically encoded utilizing CRMF,
    while PKCS#10 is supported as an alternative.
    Thus CMP does not rely on the security of the underlying transfer protocol.

  * CMC {{RFC5272}} also supports utilizing a shared secret (passphrase) or
    an existing certificate to protect certification requests,
    which can be either in CRMF or PKCS#10 structure.
    The proof-of-identity can be provided as part of a FullCMCRequest,
    based on CMS {{RFC5652}} and signed with an existing IDevID secret.
    Thus CMC does not rely on the security of the underlying transfer protocol.

<!--
Note that, besides the existing enrollment protocols, there is
ongoing work in the ACE WG to define an encapsulation of EST messages in
OSCORE, which will result in a TLS-independent way of protecting EST.
This approach {{I-D.selander-ace-coap-est-oscore}}
may be considered as a further variant.
-->


# Adaptations to BRSKI {#uc1}

In order to support alternative enrollment protocols, asynchronous enrollment,
and more general system architectures,
BRSKI-AE lifts some restrictions of BRSKI {{RFC8995}}.
This way, authenticated self-contained objects such as those described in
{{req-sol}} above can be used for certificate enrollment.

The enhancements needed are kept to a minimum in order to ensure reuse of
already defined architecture elements and interactions.
In general, the communication follows the BRSKI model and utilizes the existing
BRSKI architecture elements.
In particular, the pledge initiates communication with the domain registrar
and interacts with the MASA as usual.


##  Architecture {#architecture}

The key element of BRSKI-AE is that the authorization of a certification request
MUST be performed based on an authenticated self-contained object.
The certification request is bound in a self-contained way
to a proof-of-origin based on the IDevID.
Consequently, the authentication and authorization of the certification request
MAY be done by the domain registrar and/or by other domain components. These components
may be offline or reside in some central backend of the domain operator (off-site)
as described in {{sup-env}}. The registrar and other on-site domain components
may have no or only temporary (intermittent) connectivity to them.
The certification request MAY also be piggybacked on another protocol.

This leads to generalizations in the
placement and enhancements of the logical elements as shown in {{uc1figure}}.

~~~~
                                         +------------------------+
   +--------------Drop-Ship------------->| Vendor Service         |
   |                                     +------------------------+
   |                                     | M anufacturer|         |
   |                                     | A uthorized  |Ownership|
   |                                     | S igning     |Tracker  |
   |                                     | A uthority   |         |
   |                                     +--------------+---------+
   |                                                      ^
   |                                                      |
   V                                                      |
+--------+     .........................................  |
|        |     .                                       .  | BRSKI-
|        |     .  +-------+          +--------------+  .  | MASA
| Pledge |     .  | Join  |          | Domain       |<----+
|        |     .  | Proxy |          | Registrar w/ |  .
|        |<------>|.......|<-------->| Enrollment   |  .
|        |     .  |       | BRSKI-AE | Proxy/LRA/RA |  .
| IDevID |     .  |       |          +--------------+  .
|        |     .  +-------+                   ^        .
|        |     .                              |        .
+--------+     ...............................|.........
                on-site "domain" components   |
                                              | e.g., RFC 4210,
                                              |       RFC 7030, ...
 .............................................|....................
 .                                            v                    .
 . +---------------------------+     +---------------------------+ .
 . | Public-Key Infrastructure |<----+ Registration Authority    | .
 . | PKI CA                    +---->| PKI RA                    | .
 . +---------------------------+     +---------------------------+ .
 ...................................................................
         off-site or central "domain" components
~~~~
{: #uc1figure title='Architecture Overview Using Off-site PKI Components' artwork-align="left"}

The architecture overview in {{uc1figure}}
has the same logical elements as BRSKI, but with more flexible placement
of the authentication and authorization checks on certification requests.
Depending on the application scenario, the registrar MAY still do all of these
checks (as is the case in BRSKI), or part of them, or none of them.

The following list describes the on-site components in the target domain
of the pledge shown in {{uc1figure}}.

* Join Proxy: same functionality as described in BRSKI {{RFC8995, Section 4}}

* Domain Registrar including RA, LRA, or Enrollment Proxy: in BRSKI-AE,
  the domain registrar has mostly the same functionality as in BRSKI, namely
  to facilitate the communication of the pledge with the MASA and the PKI.
  Yet there are two generalizations:

  1. The registrar MAY offer different enrollment protocols. For supporting this,
  the URI scheme for addressing the domain registrar is generalized
  (see {{addressing}}).

  2. The registrar MAY also delegate (part of) its certificate enrollment support
  to a separate system. That is, alternatively to having full RA functionality,
  the registrar may act as a local registration authority (LRA)
  or just as an enrollment proxy.
  In such cases, the domain registrar may forward the certification request to
  some off-site RA component that performs part of the enrollment authorization.
  This also covers the case that the registrar has only intermittent connection
  and forwards certification requests to the RA upon re-established connectivity.<br>
  Still all certificate enrollment traffic goes via the registrar, such that
  from the pledge perspective there is no difference in connectivity and
  the registrar is involved in all steps, including enrollment status telemetry.

The following list describes the components provided by the vendor or manufacturer
outside the target domain.

* MASA: general functionality as described in BRSKI {{RFC8995}}.
  The voucher exchange with the MASA via the domain registrar
  is performed as described in BRSKI.

  Note: The interaction with the MASA may be synchronous (voucher request with nonce)
  or asynchronous (voucher request without nonce).

* Ownership tracker: as defined in BRSKI.

The following list describes the target domain components that can optionally be
operated in the off-site backend of the target domain.

* PKI RA: Performs certificate management functions for the domain
  as a centralized public-key infrastructure for the domain operator.
  As far as not already done by the domain registrar, it performs the final
  validation and authorization of certification requests.

* PKI CA: Performs certificate generation by signing the certificate structure
  requested in already authenticated and authorized certification requests.

Based on the diagram in BRSKI {{RFC8995, Section 2.1}} and the architectural changes,
the original protocol flow is divided into three phases showing commonalities
and differences to the original approach as follows.

* Discovery phase: same as in BRSKI steps (1) and (2)

* Voucher exchange phase: same as in BRSKI steps (3) and (4).

* Enrollment phase: step (5) is changed to employing an alternative enrollment protocol
  that uses authenticated self-contained objects.


## Message Exchange

The behavior of a pledge described in BRSKI {{RFC8995, Section 2.1}}
is kept with one exception.
After finishing the Imprint step (4), the Enroll step (5) MUST be performed
with an enrollment protocol utilizing authenticated self-contained objects.
<!-- Note that EST with simple-enroll cannot be applied here
because it binds the pledge authentication to the transport channel (TLS) rather than
to the certification request object itself, so this form of authentication
is not visible / verifiable to authorization points outside the registrar.-->
{{exist_prot}} discusses selected suitable enrollment protocols and options applicable.

<figure title="BRSKI-AE Abstract Protocol Overview">
    <artwork>
[
 Cannot render SVG graphics - please view
 https://raw.githubusercontent.com/anima-wg/anima-brski-ae/main/o.png
]
    </artwork>
</figure>

**Pledge - registrar discovery and voucher exchange**

The discovery phase and voucher exchange are applied as specified in {{RFC8995}}.


**Registrar - MASA voucher exchange**

This voucher exchange is performed as specified in {{RFC8995}}.


**Pledge - registrar - RA/CA certificate enrollment**

As stated in {{req-sol}}, the enrollment MUST be
performed using an authenticated self-contained object providing
not only proof-of-possession but also proof-of-identity (source authentication).


~~~~
+--------+                        +------------+       +------------+
| Pledge |                        | Domain     |       | Operator   |
|        |                        | Registrar  |       | RA/CA      |
|        |                        |  (JRC)     |       | (PKI)      |
+--------+                        +------------+       +------------+
 /-->                                      |                       |
 |  [Optional request of CA certificates]  |                       |
 |---------- CA Certs Request (1)--------->|                       |
 |                 [if connection to operator domain is available] |
 |                                         |-- CA Certs Request -->|
 |                                         |<- CA Certs Response --|
 |<--------- CA Certs Response (2)---------|                       |
 |-->                                      |                       |
 |  [Optional request of attributes        |                       |
 |   to include in Certificate Request]    |                       |
 |---------- Attribute Request (3)-------->|                       |
 |                 [if connection to operator domain is available] |
 |                                         |- Attribute Request -->|
 |                                         |<- Attribute Response -|
 |<--------- Attribute Response (4)--------|                       |
 |-->                                      |                       |
 |  [Mandatory certificate request]        |                       |
 |---------- Certificate Request (5)------>|                       |
 |                 [if connection to operator domain is available] |
 |                                         |-Certificate Request ->|
 |                                         |<- Certificate Resp. --|
 |<--------- Certificate Response (6)------|                       |
 |-->                                      |                       |
 |  [Optional certificate confirmation]    |                       |
 |---------- Certificate Confirm (7)------>|                       |
 |                 [if connection to operator domain is available] |
 |                                         |-Certificate Confirm ->|
 |                                         |<---- PKI Confirm -----|
 |<--------- PKI/Registrar Confirm (8)-----|                       |
~~~~
{: #enrollfigure title='Certificate Enrollment' artwork-align="left"}

The following list provides an abstract description of the flow
depicted in {{enrollfigure}}.

* CA Certs Request (1): The pledge optionally requests the latest relevant
  CA certificates. This ensures that the pledge has the
  complete set of current CA certificates beyond the
  pinned-domain-cert (which is contained in the voucher
  and may be just the domain registrar certificate).

* CA Certs Response (2): It MUST contain the current root CA certificate,
  which typically is the LDevID trust anchor, and any additional certificates
  that the pledge may need to validate certificates.

* Attribute Request (3): Typically, the automated bootstrapping occurs
  without local administrative configuration of the pledge.
  Nevertheless, there are cases in which the pledge may also
  include additional attributes specific to the target domain
  into the certification request. To get these attributes in
  advance, the attribute request can be used.

* Attribute Response (4): It MUST contain the attributes to be included
  in the subsequent certification request.

* Certificate Request (5): This certification request MUST contain the
  authenticated self-contained object ensuring both proof-of-possession of the
  corresponding private key and proof-of-identity of the requester.

* Certificate Response (6): The certification response message MUST contain on success
  the requested certificate and MAY include further information,
  like certificates of intermediate CAs.

* Certificate Confirm (7): An optional confirmation sent
  after the requested certificate has been received and validated.
  It contains a positive or negative confirmation by the pledge whether
  the certificate was successfully enrolled and fits its needs.

* PKI/Registrar Confirm (8): An acknowledgment by the PKI or registrar
  that MUST be sent on reception of the Cert Confirm.

The generic messages described above may be implemented using various
enrollment protocols supporting authenticated self-contained objects,
as described in {{req-sol}}. Examples are available in {{exist_prot}}.


**Pledge - registrar - enrollment status telemetry**

The enrollment status telemetry is performed as specified in {{RFC8995}}.
In BRSKI this is described as part of the enrollment phase,
but due to the generalization on the enrollment protocol described in this document
it fits better as a separate step here.


## Enhancements to Addressing Scheme {#addressing}

BRSKI-AE provides generalizations to the addressing scheme defined in
BRSKI {{RFC8995}} to accommodate alternative enrollment protocols that
use authenticated self-contained objects for certification requests.
As this is supported by various existing enrollment protocols,
they can be directly employed (see also {{exist_prot}}).

The addressing scheme in BRSKI for certification requests and
the related CA certificates and CSR attributes retrieval functions
uses the definition from EST {{RFC7030}},
here on the example of simple enrollment: `"/.well-known/est/simpleenroll"`.
This approach is generalized to the following notation:
`"/.well-known/<enrollment-protocol>/<request>"`
in which `<enrollment-protocol>` refers to a certificate enrollment protocol.
Note that enrollment is considered here a message sequence
that contains at least a certification request and a certification response.
The following conventions are used in order to provide maximal compatibility to BRSKI:

* `<enrollment-protocol>`: MUST reference the protocol being used, which
  MAY be CMP, CMC, SCEP, EST {{RFC7030}} as in BRSKI, or a newly defined approach.

  Note: additional endpoints (well-known URIs) at the registrar
  may need to be defined by the enrollment protocol being used.

* `<request>`: if present, this path component MUST describe,
  depending on the enrollment protocol being used, the operation requested.
  Enrollment protocols are expected to define their request endpoints,
  as done by existing protocols (see also {{exist_prot}}).


## Domain Registrar Support of Alternative Enrollment Protocols {#discovery_eo}

Well-known URIs for various endpoints on the domain registrar are
already defined as part of the base BRSKI specification or indirectly by EST.
In addition, alternative enrollment endpoints MAY be supported at the registrar.
The pledge will recognize whether its
preferred enrollment option is supported by the domain registrar
by sending a request to its preferred enrollment endpoint
and evaluating the HTTP response status code.

The following list of endpoints provides an illustrative example for
a domain registrar supporting several options for EST as well as for
CMP to be used in BRSKI-AE. The listing contains the supported
endpoints to which the pledge may connect for bootstrapping. This
includes the voucher handling as well as the enrollment endpoints.
The CMP-related enrollment endpoints are defined as well-known URIs
in CMP Updates {{I-D.ietf-lamps-cmp-updates}}
and the Lightweight CMP profile {{I-D.ietf-lamps-lightweight-cmp-profile}}.


~~~~
  </brski/voucherrequest>,ct=voucher-cms+json
  </brski/voucher_status>,ct=json
  </brski/enrollstatus>,ct=json
  </est/cacerts>;ct=pkcs7-mime
  </est/fullcmc>;ct=pkcs7-mime
  </est/csrattrs>;ct=pkcs7-mime
  </cmp/initialization>;ct=pkixcmp
  </cmp/p10>;ct=pkixcmp
  </cmp/getcacerts>;ct=pkixcmp
  </cmp/getcertreqtemplate>;ct=pkixcmp

~~~~
{: artwork-align="left"}


# Instantiation to Existing Enrollment Protocols {#exist_prot}

This section maps the requirements to support proof-of-possession and
proof-of-identity to selected existing enrollment protocols
handles provides further aspects of instantiating them in BRSKI-AE.

<!--
Note that the work in the ACE WG described in
{{I-D.selander-ace-coap-est-oscore}} may be considered
here as well, as it also addresses the encapsulation of EST in a way to
make it independent of the underlying TLS connection using OSCORE,
which also entails that authenticated self-contained objects are used.
-->


## BRSKI-EST-fullCMC: Instantiation to EST (informative)

When using EST {{RFC7030}}, the following aspects and constraints
need to be considered and the given extra requirements need to be fulfilled,
which adapt BRSKI {{RFC8995, Section 5.9.3}}:

* proof-of-possession is provided typically by using the specified PKCS#10
  structure in the request.
  Together with Full PKI requests, also CRMF can be used.

* proof-of-identity needs to be achieved by signing the certification request
  object using the Full PKI Request option (including the /fullcmc endpoint).
  This provides sufficient information for the RA to authenticate the pledge
  as the origin of the request and to make an authorization decision on the
  received certification request.
  Note: EST references CMC {{RFC5272}} for the
  definition of the Full PKI Request. For proof-of-identity, the
  signature of the SignedData of the Full PKI Request is
  performed using the IDevID secret of the pledge.

  Note: In this case the binding to the underlying TLS connection is not necessary.

* When the RA is temporarily not available, as per {{RFC7030, Section 4.2.3}},
  an HTTP status code 202 should be returned by the registrar,
  and the pledge will repeat the initial Full PKI Request


## BRSKI-CMP: Instantiation to CMP (normative if CMP is chosen)

Note: Instead of referring to CMP
as specified in {{RFC4210}} and {{I-D.ietf-lamps-cmp-updates}},
this document refers to the Lightweight CMP Profile
{{I-D.ietf-lamps-lightweight-cmp-profile}} because
the subset of CMP defined there is sufficient for the functionality needed here.

When using CMP, the following specific implementation requirements apply
(cf. {{enrollfigure}}).

* CA Certs Request
  * Requesting CA certificates over CMP is OPTIONAL.<br>
  If supported, it SHALL be implemented as specified in
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 4.3.1}}.

* Attribute Request
  * Requesting certificate request attributes over CMP is OPTIONAL.<br>
  If supported, it SHALL be implemented as specified in
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 4.3.3}}.<br>
  Note that alternatively the registrar MAY modify the contents of requested certificate contents
  as specified in {{I-D.ietf-lamps-lightweight-cmp-profile, Section 5.2.3.2}}.

* Certificate Request
  * Proof-of-possession SHALL be provided as defined in
  the Lightweight CMP Profile
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 4.1.1}} (based on CRMF) or
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 4.1.4}} (based on PKCS#10).
  <br>
  The `caPubs` field of certificate response messages SHOULD NOT be used.

  * Proof-of-identity SHALL be provided by using signature-based
  protection of the certification request message
  as outlined in {{I-D.ietf-lamps-lightweight-cmp-profile, Section 3.2}}
  using the IDevID secret.

* Certificate Confirm
  * Explicit confirmation of new certificates to the RA
  MAY be used as specified in the Lightweight CMP Profile
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 4.1.1}}.<br>
  Note that independently of certificate confirmation within CMP,
  enrollment status telemetry with the registrar will be performed
  as described in BRSKI {{RFC8995, Section 5.9.4}}.

* If delayed delivery of responses (for instance, to support asynchronous enrollment)
  within CMP is needed, it SHALL be performed
  as specified in the Lightweight CMP Profile
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 4.4}} and
  {{I-D.ietf-lamps-lightweight-cmp-profile, Section 5.1.2}}.

BRSKI-AE with CMP can also be combined with
Constrained BRSKI {{I-D.ietf-anima-constrained-voucher}},
using CoAP for enrollment message transport as described by
CoAP Transport for CMPV2 {{I-D.msahni-ace-cmpv2-coap-transport}}.
In this scenario, of course the EST-specific parts
of {{I-D.ietf-anima-constrained-voucher}} do not apply.

# IANA Considerations

This document does not require IANA actions.


# Security Considerations

The security considerations as laid out in BRSKI {{RFC8995}} apply for
the discovery and voucher exchange as well as for the status exchange information.

The security considerations as laid out in the Lightweight CMP Profile
{{I-D.ietf-lamps-lightweight-cmp-profile}} apply as far as CMP is used.


# Acknowledgments

We would like to thank
Brian E. Carpenter, Michael Richardson, and Giorgio Romanenghi
for their input and discussion on use cases and call flows.



--- back


# Using EST for Certificate Enrollment {#using-est}

When using EST with BRSKI, pledges interact via TLS with the domain registrar,
which acts both as EST server and as registration authority (RA).
The TLS connection is mutually authenticated,
where the pledge uses its IDevID certificate issued by its manufacturer.

In order to provide a strong proof-of-origin of the certification request,
EST has the option to include in the certification request
the so-called tls-unique value {{RFC5929}} of the underlying TLS channel.
This binding of the proof-of-identity of the TLS client, which is supposed to
be the certificate requester, to the proof-of-possession for the private key is
conceptually non-trivial and requires specific support by TLS implementations.

The registrar terminates the security association with the pledge at TLS level
and thus the binding between the certification request and the authentication
of the pledge.
The EST server uses the authenticated pledge identity provided by the IDevID
for checking the authorization of the pledge for the given certification request
before issuing to the pledge a domain-specific certificate (LDevID certificate).
This approach typically requires online or on-site availability of the RA
for performing the final authorization decision for the certification request.

Using EST for BRSKI has the advantage that the mutually authenticated TLS
connection established between the pledge and the registrar can be reused
for protecting the message exchange needed for enrolling the LDevID certificate.
This strongly simplifies the implementation of the enrollment message exchange.

Yet the use of TLS has the limitation that this cannot provide auditability
nor end-to-end security for the certificate enrollment request
because the TLS session is transient and terminates at the registrar.
This is a problem in particular if the enrollment is done via multiple hops,
part of which may not even be network-based.

A further limitation of using EST as the certificate enrollment protocol is that
due to using PKCS#10 structures in enrollment requests,
the only possible proof-of-possession method is a self-signature, which
excludes requesting certificates for key types that do not support signing.


# Application Examples {#app-examples}

This informative annex provides some detail to
the application examples listed in {{list-examples}}.

## Rolling Stock

Rolling stock or railroad cars contain a variety of sensors,
actuators, and controllers, which communicate within the railroad car
but also exchange information between railroad cars building a train,
with track-side equipment, and/or possibly with backend systems.
These devices are typically unaware of backend system
connectivity. Managing certificates may be done during maintenance
cycles of the railroad car, but can already be prepared during
operation. Preparation will include generating certification requests,
which are collected and later forwarded for
processing, once the railroad car is connected to the operator backend.
The authorization of the certification request is then done based on
the operator's asset/inventory information in the backend.

UNISIG has included a CMP profile for enrollment of TLS certificates of
on-board and track-side components in the Subset-137 specifying the ETRAM/ETCS
on-line key management for train control systems {{UNISIG-Subset-137}}.

## Building Automation

In building automation scenarios, a detached
building or the basement of a building may be equipped with sensors, actuators,
and controllers that are connected with each other in a local network but
with only limited or no connectivity to a central building management system.
This problem may occur during installation time but also during operation.
In such a situation a service technician collects the necessary data
and transfers it between the local network and the central building management
system, e.g., using a laptop or a mobile phone.
This data may comprise parameters and settings
required in the operational phase of the sensors/actuators, like a
component certificate issued by the operator to authenticate against other
components and services.

The collected data may be provided by a domain registrar
already existing in the local network. In this case
connectivity to the backend PKI may be facilitated by the service
technician's laptop.
Alternatively, the data can also be collected from the
pledges directly and provided to a domain registrar deployed in a
different network as preparation for the operational phase.
In this case, connectivity to the domain registrar
may also be facilitated by the service technician's laptop.

## Substation Automation

In electrical substation automation scenarios, a control center typically hosts
PKI services to issue certificates for Intelligent Electronic Devices
(IEDs) operated in a substation. Communication between the substation
and control center is performed through a proxy/gateway/DMZ, which
terminates protocol flows. Note that {{NERC-CIP-005-5}} requires
inspection of protocols at the boundary of a security
perimeter (the substation in this case).
In addition, security management in substation automation assumes
central support of several enrollment protocols in order to support the
various capabilities of IEDs from different vendors. The IEC standard
IEC62351-9 {{IEC-62351-9}} specifies mandatory
support of two enrollment protocols: SCEP {{RFC8894}} and EST
{{RFC7030}} for the infrastructure side, while
the IED must only support one of the two.

## Electric Vehicle Charging Infrastructure

For electric vehicle charging infrastructure, protocols have been
defined for the interaction between the electric vehicle and the
charging point (e.g., ISO 15118-2 {{ISO-IEC-15118-2}})
as well as between the charging point and the charging point operator
(e.g. OCPP {{OCPP}}). Depending on the authentication
model, unilateral or mutual authentication is required. In both cases
the charging point uses an X.509 certificate to authenticate itself
in TLS connections between the electric vehicle and
the charging point. The management of this certificate depends,
among others, on the selected backend connectivity protocol.
In the case of OCPP, this protocol is meant to be the only communication
protocol between the charging point and the backend, carrying all
information to control the charging operations and maintain the
charging point itself. This means that the certificate management
needs to be handled in-band of OCPP. This requires the ability to
encapsulate the certificate management messages in a transport-independent way.
Authenticated self-containment will support this by
allowing the transport without a separate enrollment protocol,
binding the messages to the identity of the communicating endpoints.

## Infrastructure Isolation Policy

This refers to any case in which network infrastructure is normally
isolated from the Internet as a matter of policy, most likely for
security reasons. In such a case, limited access to external PKI
services will be allowed in carefully controlled short periods of
time, for example when a batch of new devices is deployed, and
forbidden or prevented at other times.


## Sites with Insufficient Level of Operational Security

The registration authority performing (at least part of) the authorization of a
certification request is a critical PKI component and therefore requires higher
operational security than components utilizing the issued
certificates for their security features. CAs may also demand higher
security in the registration procedures. Especially the CA/Browser
forum currently increases the security requirements in the certificate
issuance procedures for publicly trusted certificates.
In case the on-site components of the target domain cannot be operated securely
enough for the needs of a registration authority, this service should be
transferred to an off-site backend component that has a sufficient level of security.


# History of Changes TBD RFC Editor: please delete {#app_history}

List of reviewers (besides the authors):

* Toerless Eckert - TODO

* Michael Richardson

* TBD - TODO

From IETF draft ae-02 -> IETF draft ae-03:

Reviews - TODO

From IETF draft ae-01 -> IETF draft ae-02:

* Architecture: clarify registrar role including RA/LRA/enrollment proxy

* CMP: add reference to CoAP Transport for CMPV2 and Constrained BRSKI

* Included venue information


From IETF draft 05 -> IETF draft ae-01:

* Renamed the repo and files from anima-brski-async-enroll to anima-brski-ae

* Added graphics for abstract protocol overview as suggested by Toerless Eckert

* Balanced (sub-)sections and their headers

* Added details on CMP instance, now called BRSKI-CMP

From IETF draft 04 -> IETF draft 05:

* David von Oheimb became the editor.

* Streamline wording, consolidate terminology, improve grammar, etc.

* Shift the emphasis towards supporting alternative enrollment protocols.

* Update the title accordingly - preliminary change to be approved.

* Move comments on EST and detailed application examples to informative annex.

* Move the remaining text of section 3 as two new sub-sections of section 1.


From IETF draft 03 -> IETF draft 04:

* Moved UC2-related parts defining the pledge in responder mode to a
  separate document. This required changes and adaptations in several
  sections. Main changes concerned the removal of the subsection for UC2
  as well as the removal of the YANG model related text as it is not
  applicable in UC1.

* Updated references to the Lightweight CMP Profile.

* Added David von Oheimb as co-author.


From IETF draft 02 -> IETF draft 03:

* Housekeeping, deleted open issue regarding YANG voucher-request
  in UC2 as voucher-request was enhanced with additional leaf.

* Included open issues in YANG model in UC2 regarding assertion
  value agent-proximity and CSR encapsulation using SZTP sub module).


From IETF draft 01 -> IETF draft 02:

* Defined call flow and objects for interactions in UC2. Object format
  based on draft for JOSE signed voucher artifacts and aligned the
  remaining objects with this approach in UC2 .

* Terminology change: issue #2 pledge-agent -> registrar-agent to
  better underline agent relation.

* Terminology change: issue #3 PULL/PUSH -> pledge-initiator-mode
  and pledge-responder-mode to better address the pledge operation.

* Communication approach between pledge and registrar-agent
  changed by removing TLS-PSK (former section TLS establishment)
  and associated references to other drafts in favor of relying on
  higher layer exchange of signed data objects. These data objects
  are included also in the pledge-voucher-request and lead to an
  extension of the YANG module for the voucher-request (issue #12).

* Details on trust relationship between registrar-agent and
  registrar (issue #4, #5, #9) included in UC2.

* Recommendation regarding short-lived certificates for
  registrar-agent authentication towards registrar (issue #7) in
  the security considerations.

* Introduction of reference to agent signing certificate using SKID
  in agent signed data (issue #11).

* Enhanced objects in exchanges between pledge and registrar-agent
  to allow the registrar to verify agent-proximity to the pledge
  (issue #1) in UC2.

* Details on trust relationship between registrar-agent and
  pledge (issue #5) included in UC2.

* Split of use case 2 call flow into sub sections in UC2.


From IETF draft 00 -> IETF draft 01:

* Update of scope in {{sup-env}} to include in
  which the pledge acts as a server. This is one main motivation
  for use case 2.

* Rework of use case 2 to consider the
  transport between the pledge and the pledge-agent. Addressed is
  the TLS channel establishment between the pledge-agent and the
  pledge as well as the endpoint definition on the pledge.

* First description of exchanged object types (needs more work)

* Clarification in discovery options for enrollment endpoints at
  the domain registrar based on well-known endpoints in
  {{discovery_eo}} do not result in additional
  /.well-known URIs. Update of the illustrative example.
  Note that the change to /brski for the voucher-related endpoints
  has been taken over in the BRSKI main document.

* Updated references.

* Included Thomas Werner as additional author for the document.


From individual version 03 -> IETF draft 00:

* Inclusion of discovery options of enrollment endpoints at
  the domain registrar based on well-known endpoints in
  {{discovery_eo}} as replacement of section 5.1.3
  in the individual draft. This is intended to support both use
  cases in the document. An illustrative example is provided.

* Missing details provided for the description and call flow in
  pledge-agent use case UC2, e.g. to
  accommodate distribution of CA certificates.

* Updated CMP example in {{exist_prot}} to use
  Lightweight CMP instead of CMP, as the draft already provides
  the necessary /.well-known endpoints.

* Requirements discussion moved to separate section in
  {{req-sol}}. Shortened description of proof
  of identity binding and mapping to existing protocols.

* Removal of copied call flows for voucher exchange and registrar
  discovery flow from {{RFC8995}} in {{uc1}} to avoid doubling or text or
  inconsistencies.

* Reworked abstract and introduction to be more crisp regarding
  the targeted solution. Several structural changes in the document
  to have a better distinction between requirements, use case
  description, and solution description as separate sections.
  History moved to appendix.


From individual version 02 -> 03:

* Update of terminology from self-contained to authenticated
  self-contained object to be consistent in the wording and to
  underline the protection of the object with an existing
  credential. Note that the naming of this object may be discussed.
  An alternative name may be attestation object.

* Simplification of the architecture approach for the initial use
  case having an offsite PKI.

* Introduction of a new use case utilizing authenticated
  self-contain objects to onboard a pledge using a commissioning
  tool containing a pledge-agent. This requires additional changes
  in the BRSKI call flow sequence and led to changes in the
  introduction, the application example,and also in the
  related BRSKI-AE call flow.

* Update of provided examples of the addressing approach used in
  BRSKI to allow for support of multiple enrollment protocols in
  {{addressing}}.


From individual version 01 -> 02:

* Update of introduction text to clearly relate to the usage of
  IDevID and LDevID.

* Definition of the addressing approach used in BRSKI to allow for
  support of multiple enrollment protocols in {{addressing}}.  This
  section also contains a first
  discussion of an optional discovery mechanism to address
  situations in which the registrar supports more than one enrollment
  approach. Discovery should avoid that the pledge performs a trial
  and error of enrollment protocols.

* Update of description of architecture elements and
  changes to BRSKI in {{architecture}}.

* Enhanced consideration of existing enrollment protocols in the
  context of mapping the requirements to existing solutions in
  {{req-sol}} and in {{exist_prot}}.


From individual version 00 -> 01:

* Update of examples, specifically for building automation as
  well as two new application use cases in {{app-examples}}.

* Deletion of asynchronous interaction with MASA to not
  complicate the use case. Note that the voucher exchange can
  already be handled in an asynchronous manner and is therefore
  not considered further. This resulted in removal of the
  alternative path the MASA in Figure 1 and the associated
  description in {{architecture}}.

* Enhancement of description of architecture elements and
  changes to BRSKI in {{architecture}}.

* Consideration of existing enrollment protocols in the context
  of mapping the requirements to existing solutions in {{req-sol}}.

* New section starting {{exist_prot}} with the
  mapping to existing enrollment protocols by collecting
  boundary conditions.

<!--
LocalWords: bcp uc prot vexchange enrollfigure req eo selander coap br
LocalWords: oscore fullcmc simpleenroll tls env brski UC seriesinfo
LocalWords: Attrib lt docname ipr toc anima async wg symrefs ann ae
LocalWords: sortrefs iprnotified Instantiation caPubs raVerified repo
-->
