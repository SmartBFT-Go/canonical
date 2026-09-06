# What `WIRE-SPEC.md` did not say clearly enough

`ci/verify_vectors.py` was written from `WIRE-SPEC.md` alone, without opening any `.go` file in
this repository. Every question below is one the document could not answer, recorded before it was
resolved. Each is a defect in the document, not in the implementer's patience: the next person to
write a client from it hits the same wall.

Each entry records the section, the readings that seemed possible, how it was resolved, and
whether the resolution was a spec edit or the implementer having misread a section that was
already clear.

---

## A1 — §1.4/§1.5: the annex's `fields` object is not specified at all

**Question.** §1.4 makes the annex normative for `der`, `sha256` and `hash`. §1.5 marks
`annotation` informative. Nothing in the document mentions `name`, `structure` or `fields`, yet
`fields` is the only machine-readable statement of what a vector's bytes are supposed to *mean* —
without it a checker can only assert that a hex string hashes to another hex string, which
verifies nothing about the field layout of §3.

Two readings were possible:

1. `fields` is informative like `annotation`, and a conformant implementation ignores it;
2. `fields` is normative and its representation conventions (byte strings as lowercase hex,
   INTEGERs as JSON numbers, `SEQUENCE OF` as a JSON array, an element type as a nested object
   keyed by field name) are part of the annex format.

Reading 1 makes the annex far weaker than §1.4 claims — "sufficient to reproduce those bytes in
any language" is satisfiable by a program that hashes hex — so reading 2 was assumed and the
conventions inferred from the data.

**Resolution.** Reading 2 is right, and the conventions had to be inferred rather than read.
**Spec edit:** §1.4 now specifies the annex entry format, names `fields` as normative, states the
four representation conventions, and §1.5 keeps `annotation` informative.

**Also unspecified and needed:** a vector may carry a key that is *not* a field of its structure —
the verifier's own inputs, `GenesisDigest` and `PubKey` on a `SignedBlobV1` vector, which §3.9.1
says are reconstructed and never transmitted. A checker that rejects unknown keys (as this one
does, deliberately) needs the document to say those keys exist and what they mean. §1.4 now says
so.

---

## A2 — §4.1: the "exhaustive" exception table is not exhaustive

**Question.** §4.1 introduces its table with "The exceptions are exhaustively:" and lists four
structures: `ProposalV0`, `SignatureSetV0`, `SignerSigV0`, `GenesisMemberV1`. §3.11.7 says
"**`CertificateV1` has no `Version` field.** It is an allowlisted exception to §4.1". Two sections
of the same document contradict each other, and §4.1's own text claims the list is closed.

Readings: either `CertificateV1` does carry a `Version` and §3.11.7 is wrong (but §3.11's table
for `CertificateV1` shows a single `DER` field, so it does not), or §4.1's table is stale.

**Resolution.** §4.1's table is stale — the annex's `client-request/v1/one-intermediate` vector
encodes `Intermediates[0]` as `30 10 04 0e ...`, one field, no `Version`. **Spec edit:** the
`CertificateV1` row was added to §4.1's table.

Cost of not fixing it: an implementer who trusts the word "exhaustively" writes a V-RULE check
that rejects every request carrying an intermediate certificate.

---

## A3 — §3.8.5: the purpose-to-payload mapping is stated as a rule the annex breaks

**Question.** §3.8.5 says `SignedV1.Payload` "is the purpose's own structure, DER-encoded" and
maps purpose 1 to §3.10, purpose 3 to §3.11 and purpose 4 to §3.12. Read as a constraint on the
envelope, five of the annex's own `signed/v1/*` vectors violate it: `signed/v1/commit` and
`signed/v1/long-form-length` carry purpose 1 with a payload of `"PAYLOAD"` and 0x5a filler
respectively, neither of which is a `CommitPayloadV1`; `signed/v1/client-request` and
`signed/v1/read-index` do the same for purposes 3 and 4.

§1.6 says the annex wins where the two disagree, so the document is in error — but it does not say
*how*. Two readings:

1. the mapping binds the envelope encoder, which must parse `Payload` and reject a mismatch —
   in which case the annex is non-conformant and §1.6 makes the document wrong;
2. the mapping binds the *producer* of an envelope and the verifier of that purpose, and the
   envelope layer treats `Payload` as opaque exactly as the §3.8 table's "Opaque at this layer"
   wording elsewhere suggests.

Reading 1 cannot be right — §3.8.5 itself says purpose 2 carries "whatever the caller handed to
`Sign`", which no encoder can validate — but the section never states the scope of the rule, and
without it a checker either rejects five annex vectors or silently skips the only mapping check
there is.

**Resolution.** Reading 2. **Spec edit:** §3.8.5 now states the scope of the mapping explicitly,
says the envelope layer MUST NOT parse `Payload`, and records that the `signed/v1/*` vectors carry
a deliberately opaque payload because they exercise the envelope encoding and purpose separation
(§3.8.3) rather than a system envelope. §3.9.4 is where the mapping becomes checkable, because
§3.9's table already requires a real payload; the checker enforces it there and reports it, not
silently, for `SignedV1`.

---

## A4 — §2.4: how many length octets are legal

**Question.** §2.4's table shows the short form, `0x81` and `0x82`, and stops at length 65535. It
does not say whether `0x83`/`0x84` are legal for a larger value, whether there is an upper bound
on a structure's size, or what to do with the reserved octet `0xff`. A decoder must decide, and
the two decisions are not equivalent: accepting arbitrary width invites a length that allocates,
and rejecting `0x83` rejects any future structure past 64 KiB — `commit-cert/v1/n13-q9` is already
1104 bytes, so the ceiling is not remote.

**Resolution.** Resolved by reading the reference decoder, which is Go's `encoding/asn1`
(`asn1.go` shows `unmarshal` calls `asn1.Unmarshal` and adds the R-RULE on top of it).
`parseTagAndLength` accepts the general long form with any number of length octets, and bounds the
result rather than the form — verbatim from `$(go env GOROOT)/src/encoding/asn1/asn1.go`:

```
594:            err = SyntaxError{"indefinite length found (not DER)"}
605:            if ret.length >= 1<<23 {
608:                err = StructuralError{"length too large"}
615:                err = StructuralError{"superfluous leading zeros in length"}
621:            err = StructuralError{"non-minimal length"}
```

So `0x83` and wider are legal, the effective ceiling is 2^23 bytes, and `0xff` is not
special-cased — it means 127 length octets and dies as truncated or too large either way.

**Spec edit:** §2.4 now states that the long form is the general DER one with no fixed width, that
the first length octet MUST NOT be zero and the value MUST NOT fit a shorter form, that indefinite
length MUST be rejected, and that an implementation MAY refuse a length beyond a documented
ceiling — naming the reference implementation's 2^23, because two implementations disagreeing on
that boundary is the divergence this note exists to prevent. `verify_vectors.py` caps at four
length octets and says so in a comment.

---

## A5 — §2.5: an INTEGER with no content octet is not addressed

**Question.** §2.5 gives the minimal-encoding rule and worked examples, and rejects `02 02 00 01`.
It does not say that `02 00` — an INTEGER of zero length — is invalid. §4.2.1's re-encode rule
catches it indirectly (0 encodes to `02 01 00`, so `02 00` is not the encoding of any value), but
a decoder needs the rule at the point where it reads content octets, not two sections later.

**Resolution.** Not a spec defect *in effect* — §4.2.1 is the general statement and it does cover
this. It is a defect *in usability*: every implementer has to derive it. **Spec edit:** §2.5 gains
one sentence requiring at least one content octet.

---

## A6 — §2.2 vs §3.11.3: "the producer MUST sort" has two exceptions, one of them undocumented

**Question.** §2.2's table says a `SEQUENCE OF` producer "MUST sort deterministically before
encoding", stated flatly with no exception. §3.7.4 records `SignatureSetV0.Sigs` as an exception.
§3.11.3 says `ClientRequestV1.Intermediates` is ordered by the chain and "§2.2's producer-sorts
rule does not apply" — a second exception that §2.2 does not acknowledge and that no index in the
document collects, unlike §4.1's exception table for the V-RULE.

An implementer reading §2 before §3 writes a checker that requires every `SEQUENCE OF` to be
sorted, and then rejects `client-request/v1/one-intermediate`.

**Resolution.** Both exceptions are real. **Spec edit:** §2.2's sort cell now points at the two
sections that carve out exceptions, so the rule is not read as unconditional.

---

## A7 — §5.1: `depth` is one byte and no section bounds it

**Question.** §5.1 encodes `depth` in a single unsigned byte. Nothing says what an implementation
does at depth 256, and a Merkle tree over 32-byte keys has a natural depth of 256 if it is a radix
tree over key bits. Either the trees are bounded below 256 levels, or the encoding silently wraps
and two nodes 256 levels apart hash identically — which is exactly the relocation §5.3 says
`depth` exists to prevent.

**Resolution.** Left open, deliberately, and recorded here rather than fixed. The authenticated
data structure is Phase 4's decision and its depth bound is a property of that structure, not of
this encoding; a bound written into §5 now would be a number this document cannot justify.
**Spec edit:** §5.1 states the constraint (`depth` MUST be 0..255, and a producer MUST reject a
node deeper than that) without naming the tree, which is the part §5 can be sure of.

**This entry is the one place the exercise found a question the document should not answer yet.**

---

## A8 — §3.13: `CommitCertificateV1.Sigs[].Msg` is required to be a `CommitPayloadV1` that the annex does not supply

**Question.** §3.13's second table constrains `Msg` as "The `CommitPayloadV1` of §3.10, DER. MUST
be non-empty", and §3.13.1 says "A client MUST also check that the `ProposalDigest` inside each
`Msg` equals the certificate's own `ProposalDigest`, or the container's digest is decorative."

Vector `commit-cert/v1/long-form-length` carries one entry whose `Msg` is 300 bytes of `0x6d`,
which is not DER at all. Its own annotation says the point of the vector is to pin the `04 82`
length form on a primitive. So the annex contains a certificate on which §3.13.1's MUST cannot be
performed. Found the same way A3 was: the checker was written to the document and rejected the
vector.

```
FAIL commit-cert/v1/long-form-length: tag 0x6d is outside the type profile (2.2, 2.3)
```

Two readings, the same pair as A3: either the encoding layer parses `Msg` and rejects the vector,
or the constraint binds the verifier and `Msg` is opaque to the encoder.

**Resolution.** The second. `Msg` belongs to `SignerSigV0`, which §3.7 declares a frozen v0
element whose `Msg` is "Opaque, and may be empty" — §3.13 cannot tighten a v0 element's *parsing*
without changing what `SignatureSetV0` accepts. **Spec edit:** §3.13's table and §3.13.1 now say
that the `CommitPayloadV1` requirement and the digest cross-check bind the producer and the
verifying client, that the encoding layer does not parse `Msg`, and that
`commit-cert/v1/long-form-length` carries an opaque `Msg` on purpose.

`verify_vectors.py` performs the §3.13.1 cross-check on every entry whose `Msg` decodes, counts
the entries it checked, and **fails if that count is zero** — a check that silently applies to
nothing is a check that has stopped existing. The current annex gives 12 of 13 entries checked.

---

## Entries that were the implementer's misreading, not a spec defect

None. Every question above survived a re-read of the section that raised it.

---

## How the resolutions were reached

A1, A2, A3, A6 and A8 were resolved by reading the annex itself — `testdata/vectors.json` is
normative under §1.4, and in each case the bytes answered the question the prose did not. A5 was
resolved from §4.2.1, inside the document. A4 is the only entry that needed the Go, and what it
needed was `encoding/asn1`'s length parser rather than anything in this package. A7 was not
resolved by anything; it is recorded as an open constraint with the part of it §5 can state.

A3 and A8 are the same defect in two places: a section states a structural rule about a field
that the layer it describes treats as opaque, and the annex — which §1.6 makes the tiebreaker —
does not follow it. Both were found by a checker that took the prose literally, which is what an
implementer working from the document does.

No `.go` file in this repository was opened while `ci/verify_vectors.py` was being written. The
first Go read was `asn1.go` and `encoding/asn1`, for A4, after the checker was green on all 29
vectors.
