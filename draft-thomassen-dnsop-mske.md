%%%
Title = "DNSSEC Multi-Signer Key Exchange (MSKE)"
abbrev = "mske"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [ 4034 ]
area = "Internet"
workgroup = "DNSOP Working Group"
date = @TODAY@

[seriesInfo]
name = "Internet-Draft"
value = "@DOCNAME@"
stream = "IETF"
status = "standard"

[[author]]
initials = "P."
surname = "Thomassen"
fullname = "Peter Thomassen"
organization = "Secure Systems Engineering, deSEC"
[author.address]
 email = "peter.thomassen@securesystems.de"
[author.address.postal]
 city = "Berlin"
 country = "Germany"
%%%


.# Abstract

Answering DNSKEY/CDS/CDNSKEY queries in an [@!RFC8901] multi-signer DNSSEC
configuration requires all operators to serve not only their own public key
information, but also include each other's public keys.
This ensures that clients obtain a consistent view of the DNSSEC configuration
regardless of who is answering a given query.
In order to enable operators to import the keys needed for assembling these
responses, a method for discovering them is necessary.

This document specifies how DNS operators can announce which are the keys they
intend to use for signing a given zone (DNSKEY) and which keys are designated
for secure entry into the zone (CDS/CDNSKEY).
It further introduces the CNS record type to facilitate proactive discovery of
the aforementioned signals.
Taken together, these parts function as an authenticated multi-signer
key-exchange (MSKE) scheme.

This MSKE mechanism uses the signaling mechanism introduced in
[@!I-D.ietf-dnsop-dnssec-bootstrapping] to complete the automated workflows
described in [@!I-D.ietf-dnsop-dnssec-automation].


{mainmatter}

# Introduction

In comparison to single-signer DNSSEC deployments, multi-signer setups as
described in [@!RFC8901] come with additional coordination overhead.
This overhead entails

  - the key exchange process that is needed so that each provider can serve a
    joint record set reflecting all relevant providers' DNSSEC keys when
    responding to a DNSKEY or CDS/CDNSKEY query,
  - timing coordination when updating the DNSSEC confguration (similarly to
    what's needed when performing a key rollover, see [@!RFC7583] for details).

While the logistics and timing considerations of adding and removing a DNSSEC
signer to/from a given constellation are described in
[@!I-D.ietf-dnsop-dnssec-automation], an automatable method for the key exchange
step has not been specified so far.
It is thus proposed with this document.

Readers are expected to be familiar with DNSSEC, including [@!RFC4033],
[@!RFC4034], [@!RFC4035], [@!RFC6781], [@!RFC7344], [@!RFC7477], [@!RFC7583],
and [@!RFC8901].


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL
NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT
RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be
interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when,
they appear in all capitals, as shown here.


# Conceptual Overview

DNS resolvers may direct queries against any nameserver contained in a zone's NS
record set.
When asking (for instance) for an A record set, the response (including the
RRSIG signature) may thus be retrieved from one nameserver, while the DNSKEY
record set required for validation may be retrieved from another nameserver (and
hence provider).
This is by design: Resolvers do not have any notion of multi-provider concepts;
the multi-signer models described in [@!RFC8901] just look like multi-key setups
to them.

DNSSEC multi-signer setups thus require that a DNSKEY response contains all keys
a validating resolver may need to validate an RRSIG signature from that zone,
irrespective of whether that RRSIG is obtained from the same nameserver/provider
as the DNSKEY record set.
To allow validation to work properly, the DNSKEY RRset therefore must be the
union of all of the DNSKEY record sets that each provider would serve if they
were the only (signing) provider.

Similarly, CDS/CDNSKEY record sets published on any of the nameservers for the
purpose of automated DS record maintenance
([@!RFC7344;@!RFC8078;@!I-D.ietf-dnsop-dnssec-bootstrapping]) are required to be
the union across all signers in order to prevent accidents caused by a single
provider publishing an inconsistent RRset
([@!I-D.thomassen-dnsop-cds-consistency]).

{#keyannouncement}
## Key Announcement

In order for the participating providers to discover each others'
DNSKEY/CDS/CDNSKEY records for inclusion in their responses, providers need to
signal what their single-provider record sets would be.
Specifically, each provider needs to separately announce

  - their KSK (or CSK) public keys for inclusion in CDS/CDNSKEY record sets, and
  - their ZSK (or CSK) public keys for inclusion in the DNSKEY record set.

Ideally, the mechanism would be authenticated and in-band, and allow each
provider to import these records in a straightforward manner.
In particular, no heuristics should need to be applied to determine the usage
mode of any given key.
The publishing provider, having ultimate knowledge of how each key is used,
should instead make this distinction explicit in what they publish.

(This is in contrast to inference methods, such as querying the DNSKEY RRset
from each provider and guessing which keys are used for KSK and/or ZSK purposes.
Such methods do not adequately cover edge cases such as distinguishing a standby
key from a retired key that needs to be cleaned up, or a key that looks like a
KSK but also signs another RRset.)

The signaling mechanism described in [@!I-D.ietf-dnsop-dnssec-bootstrapping]
Section 2 provides a suitable framework for these key announcements.

## Triggering Initial Key Synchronization

Once providers have put their key announcements in place, they need to be made
aware of each other so that keys can be retrieved, validated, and included in
each provider's local copy of the DNSKEY/CDS/CDNSKEY record sets.

To see how this can work, consider the process of onboarding a new signing
provider.
Suppose that the zone is configured both at the existing and the new
provider(s), with equivalent contents as far as non-DNSSEC records are concerned
(that is, same A/MX/CNAME/TXT/... records).

As the new provider can only be added to the NS record set once the key exchange
has concluded, the new provider's nameservers are not yet part of it and cannot
be discovered by looking at the NS RRset.
The NS record set therefore is not a suitable starting point for provider
discovery.

### Mechanism

Discovery can be achieved by adding a new record set which holds the prospective
set of NS hostnames.
This is similar to how the CDS record set holds the prospective DS records.
Like the CDS RRset, it also resides on the child side of the zone cut, and it is
used for scanning (albeit peer-to-peer, not parent-child).
The type of the new record set is therefore called CNS.

To indicate that the set of providers is about to change, the zone administrator
adds a CNS record set to the zone at all involved providers (both old and new).
The record set is the same at all providers (just like any regular record set in
the zone, such as A/MX/...).

Providers can detect that a CNS record set has been created, and subsequently
start collecting keys (see (#keyannouncement)) from the other providers'
nameservers, as extracted from the CNS record set.

### Properties

The process is symmetrical in two ways: (1) it works the same way for old and
new signers alike (both existing and incoming provider(s) see the same CNS
record set); (2) it covers both additional and removal of providers.
It therefore also covers transitions from one single provider to another single
provider (with a temporary multi-signer period in between).

If necessary, the method can further be used to trigger a key re-sync without
changing providers (such as when revoking a key).
This is achieved by copying the NS records into the CNS record set, upon which
key collection would occur.

## Parent-side Updates

After importing, each provider can periodically check whether the key exchange
has converged.
This can be done by verifying that the zone's DNSKEY/CDS/CDNSKEY record sets as
served by the other providers are equivalent to the joint set seen locally
(containing both local and imported keys).
As the process is fully transparent, it can also be externally observed.

In case convergence does not occur for a while, any provider (or other observer)
MAY detect which keys are missing on whose nameservers (by comparing each apex
DNSKEY record set to everyone's announced keys, see (#keyannouncement)).
Detecting providers can easily relay this information to the zone owner.
This allows the zone owner to proactively tackle the problem (e.g. by contacting
customer support), instead of experiencing a silent or intransparent failure.

Once convergence is confirmed and the parent has updated the DS record
accordingly (e.g. after observing the new CDS/CDNSKEY records), the NS record
set can be replaced with the records from the CNS RRset.
Finally, the updated NS RRset can be conveyed to the parent for updating the
delegation (e.g. via CSYNC, or EPP if available to one of the providers).

From the parent's perspective, this process is identical to how DS and NS
records would be updated in a single-provider setup.
No dedicated functionality specific to multi-signer setups is required.

# The CNS Record Type

During a multi-provider configuration process, CNS records indicate which are
the NS records that are expected to be in place once the process finishes.
As such, record parameters, value constraints, and wire as well as presentation
format are the same as for NS records ([@!RFC1034] Section 3.3.11).

This is similar to how CDS records indicate the prospective DS records, and thus
share formats and constraints with the DS record type.

# Multi-Signer Key Exchange Protocol

This section specifies the details of how each provider publishes their keys and
how they can be discovered by peers.

The signaling-related terminology in this section is as defined in
[@!I-D.ietf-dnsop-dnssec-bootstrapping].

## Key Announcements

To indicate that a provider is willing to participate in a multi-signer key
exchange for a given zone, iterate over the zone's DNSKEY records for which the
provider holds the private key.
For each such key, execute all of the following steps:

 1. Mark the key for CDS/CDNSKEY signaling if the provider intends to use the
    key as a secure entry point into the zone (= would want it referenced in the
    delegation's DS record set);

 2. Mark the key for DNSKEY signaling if the provider intends to sign, with the
    corresponding private key, any RRsets besides the apex DNSKEY RRset.

Next, publish CDS and CDNSKEY records corresponding to (1) and DNSKEY records
corresponding to (2) under the zone's Signaling Domains using Signaling Type
"_multi".

Existing use of DNSKEY and CDS/CDNSKEY records is specified at the apex only
([@!RFC4034], Section 2.1.1 and [@!RFC7344], Section 4.1, respectively).
This protocol extends the use of these record types to non-apex owner names for
the purposes of DNSSEC MSKE.
To exclude the possibility of semantic collision, there MUST NOT be a zone cut
at a the Signaling Records' owner name.

### Example

Consider Provider 1 with nameservers ns1.example.net and ns2.example.net.
To prepare a multi-signer key exchange for the zone example.co.uk hosted on
these nameservers, the provider starts from the list of DNSKEY records for which
the provider holds the private key.

Iterating over all these DNSKEYs, the provider publishes CDS/CDNSKEY records for
each key that it would like promoted to the delegation's DS record set (KSK-like
use), at the following owner names:
```
   _multi.example.co.uk._signal.ns1.example.net
   _multi.example.co.uk._signal.ns2.example.net
```

Iterating over the same list, the provider also publishes a DNSKEY record for
each key that it wants to use for signing any RRsets besides the apex DNSKEY
RRset (ZSK-like use), at the same owner names.

The records are accompanied by RRSIG records created using the key(s) of the
respective Signaling Zone.

Provider 2 (with nameservers under example.org) follows the same steps to
announce their multi-signer keys, under the owner names:
```
   _multi.example.co.uk._signal.ns1.example.org
   _multi.example.co.uk._signal.ns2.example.org
```

[TODO Strictly, if Provider 1 knows that a key will ONLY be used as a KSK and
NOT for signing any other records, it doesn't need to be imported by other
providers and thus does not need to be announced here as a DNSKEY. -- This is
because the key is needed only for verifying the target zone's DNKSEY RRset when
retrieved from Provider 1, and in this case, it will be included in the apex
DNSKEY RRset itself. To validate a DNSKEY RRset retrieved from Provider 2, the
KSK of Provider 1 is not needed.]

## Key Discovery

When a provider finds that the zone owner has created a CNS record set, the
provider creates an "external nameserver list" by filtering the NS hostnames
contained in the CNS RRset, removing those which are under the provider's
control.
The remaining list represent the subset of prospective NS hostnames operated by
other providers.

To import the other providers' DNSSEC keys, the provider starts out from initial
DNKSEY/CDS/CDNSKEY record sets that only reference keys for which the provider
holds the private key.
These record sets are called "local RRsets" below.

Next, for each hostname in the "external nameserver list", the provider
constructs the owner names of the corresponding Signaling Records and queries
CDS, CDNSKEY, and DNSKEY records at these owner names.
Answers that can be DNSSEC-validated are added to the corresponding
"local RRset".

### Example

The zone owner is generally tasked with keeping the zone contents at all
provider in sync.
It is thus the first step for the zone owner to ensure that general zone content
(such as A/MX/TXT records) is equal everywhere.

Next, the zone owner adds the following record set to the zone configuration at
both Provider 1 and Provider 2:
```
example.co.uk. 3600 IN CNS ns1.example.net.
example.co.uk. 3600 IN CNS ns2.example.net.
example.co.uk. 3600 IN CNS ns1.example.org.
example.co.uk. 3600 IN CNS ns2.example.org.
```

When Provider 1 detects the CNS RRset, Provider 1 creates the "external
nameserver list" by removing their own nameservers.
The list then contains the hostnames ns1.example.org and ns2.example.org, which
belong to Provider 2.

Provider 1 then uses these hostnames, the target zone name and the Signaling
Type "_multi" to query the CDS/CDNSKEY/DNSKEY Signaling Records from the
following owner names:
```
   _multi.example.co.uk._signal.ns1.example.org
   _multi.example.co.uk._signal.ns2.example.org
```

Starting out from DNSKEY/CDS/CDNSKEY "local RRsets" that only have Provider 1's
keys, Provider 1 validates the received answers and adds them to the
corresponding local RRset.

Provider 2 performs the same steps to import Provider 1's keys, by querying and
validating the CDS/CDNSKEY/DNSKEY records from the following owner names:
```
   _multi.example.co.uk._signal.ns1.example.net
   _multi.example.co.uk._signal.ns2.example.net
```

## Parent-side Updates

Multi-signer setups are not in any way special from the parent's perspective:
Like for any client (such as resolvers), they merely look like a multi-key
setup.

Once convergence has been detected, existing protocols can therefore be used for
DS management automation (via CDS/CDNSKEY,
[@!RFC7344;@!RFC8078;@!I-D.ietf-dnsop-dnssec-bootstrapping])

Once providers detect that the DS record set has been updated accordingly, the
zone's NS record set can be updated to reflect the changes indicated by the CNS
RRset.
This is most easily done wy overwriting the NS records set with the contents of
the CNS RRset.

Finally, existing protocols can be used to propagate the NS (and possibly glue)
changes to the parent (e.g. via CSYNC, [@!RFC7477]).

If one of the participating providers is also a registrar, the EPP protocol may
be used as well [@!RFC5730].

# Security Considerations

TODO


{backmatter}


# Change History (to be removed before publication)

* draft-thomassen-dnsop-mske-00

> Initial public draft.
