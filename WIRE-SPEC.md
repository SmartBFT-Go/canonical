# Canonical wire specification, v1

Every byte this system hashes or signs is produced by the rules below. This document plus
[`testdata/vectors.json`](testdata/vectors.json) is sufficient to reproduce those bytes in any
language.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope and status

1.1 Status: **frozen v1, additive only**. Once a structure's encoding ships, its bytes never
change.

1.2 A new field means a new structure or a new `Version`. It never means an edited encoding.

1.3 Changing an existing encoding is a **breaking release**. Every digest, signature and state
root produced under the old bytes stops verifying, so the change requires a coordinated
upgrade of every replica in the cluster.

1.4 `testdata/vectors.json` is the **normative test-vector annex** of this document. An
implementation is conformant iff it reproduces every vector in that file: for each entry in
`vectors`, the DER hex in `der` and its SHA-256 in `sha256`; for each entry in `merkle`, the
32-byte digest in `hash`.

1.5 The `annotation` arrays in the annex are informative, not normative. They exist so a vector
can be reviewed in a diff without decoding hex by hand.

1.6 Where this document and the annex disagree, the annex wins and this document is in error.

1.7 Two encodings are specified, each for its own job: ASN.1 DER (§3) for structured, evolving
values, and fixed-width domain-separated concatenation (§5) for Merkle node hashing. §5.6 gives
the measurement that justifies the split.

## 2. The type profile

2.1 The safety of the DER encoding comes from the restricted set of value types, not from any
particular encoder. A conformant implementation MUST restrict itself to the same set.

2.2 Allowed:

| Type | ASN.1 | Encoding |
|---|---|---|
| `Version` integer | INTEGER | `02 <len> <minimal signed big-endian>` — MUST be the first field of every top-level structure, see §4 |
| byte string | OCTET STRING | `04 <len> <bytes>` |
| 64-bit signed integer | INTEGER | `02 <len> <minimal signed big-endian>` |
| boolean | BOOLEAN | `01 01 00` false, `01 01 ff` true |
| nested structure | SEQUENCE | `30 <len> <fields in declaration order>` |
| homogeneous list | SEQUENCE OF | `30 <len> <elements>` — the producer MUST sort deterministically before encoding |

2.3 Banned, with the reason for each ban:

| Banned | Reason |
|---|---|
| text string | The ASN.1 tag flips between PrintableString (`13`) and UTF8String (`0c`) depending on the *content*. A non-Go implementer would have to reimplement Go's exact PrintableString predicate to reproduce our bytes. Use a byte string. |
| date/time value | Truncates to whole seconds, changes tag between UTCTime and GeneralizedTime at the 1950 and 2050 boundaries, and encodes the timezone offset — so the same instant expressed in two locations produces different bytes. Use `int64` Unix nanoseconds. |
| platform-width integer | Width varies by architecture, so two replicas can disagree. |
| unsigned 64-bit integer | Not representable; see §3.5. |
| fixed-size array | Encode as OCTET STRING with a length check at construction. |
| floating point | Not deterministic across implementations, and banned in the deterministic core generally. |
| map / dictionary | Iteration order is unspecified. |
| `OPTIONAL` / `DEFAULT` / omit-if-empty | Makes absent and zero-valued indistinguishable, which is the opposite of what a frozen encoding wants. |
| `SET OF` | Sorted on encode but **unsorted input is accepted on decode**, so two distinct byte strings decode to the same value: malleable. Use SEQUENCE OF and sort at construction. |

2.4 Length encoding MUST be DER-minimal and definite:

```
length 0..127      short form, one byte:      2b            = 43
length 128..255    long form, 0x81 + 1 byte:  81 8a         = 138
length 256..65535  long form, 0x82 + 2 bytes: 82 01 00      = 256
```

`81 80` is the only valid encoding of length 128. `82 00 80` MUST be rejected. Indefinite length
(`80` … `00 00`) MUST be rejected.

2.5 INTEGER content MUST be minimal two's-complement big-endian, and INTEGER is **signed**:

```
0    -> 02 01 00
7    -> 02 01 07
127  -> 02 01 7f
128  -> 02 02 00 80     leading 00: without it 0x80 would decode as -128
2^63-1 -> 02 08 7fffffffffffffff
```

`02 02 00 01` (non-minimal 1) MUST be rejected.

2.6 An empty byte string encodes to `04 00`. A conformant implementation MUST NOT attempt to
distinguish an absent byte string from an empty one — the encoding cannot express the
difference. A caller needing that distinction MUST carry a separate boolean or use a distinct
structure.

## 3. Structures

### 3.1 `Header`

Wire order is the order below. It is frozen.

| # | Field | ASN.1 | Constraints |
|---|---|---|---|
| 1 | `Version` | INTEGER | MUST equal 1 for v1. §4.1 applies. |
| 2 | `PrevStateRoot` | OCTET STRING | MUST be exactly 32 bytes, on encode **and** on decode. |
| 3 | `PrevSeq` | INTEGER | 64-bit signed. Sequence number of the previous decision. |
| 4 | `ConsensusTime` | INTEGER | 64-bit signed, Unix **nanoseconds**. See §6. |

Annotated breakdown of vector `header/v1/seq-128`:

```
30 2c                                SEQUENCE, 44 bytes
   02 01 01                          INTEGER 1                 Version
   04 20 0000…0000                   OCTET STRING, 32 bytes    PrevStateRoot
   02 02 00 80                       INTEGER 128               PrevSeq
   02 01 00                          INTEGER 0                 ConsensusTime
```

3.1.1 A decoder MUST reject a `Header` whose `PrevStateRoot` is not 32 bytes. An encoder would
never produce one, and a consumer that copies a short root into a fixed 32-byte buffer would
silently zero-pad it and then compare it against real state roots.

3.1.2 `ConsensusTime` as `int64` nanoseconds overflows in the year 2262.

### 3.2 `ProposalV0`

| # | Field | ASN.1 | Constraints |
|---|---|---|---|
| 1 | `Payload` | OCTET STRING | Opaque to this layer. |
| 2 | `Header` | OCTET STRING | Carries the DER of §3.1 in this system, but is opaque here. |
| 3 | `Metadata` | OCTET STRING | Opaque to this layer. |
| 4 | `VerificationSequence` | INTEGER | 64-bit signed. |

Annotated breakdown of vector `proposal/v0/smartbft-reference`:

```
30 12                                SEQUENCE, 18 bytes
   04 03 50 41 59                    OCTET STRING "PAY"        Payload
   04 03 48 44 52                    OCTET STRING "HDR"        Header
   04 03 4d 45 54                    OCTET STRING "MET"        Metadata
   02 01 07                          INTEGER 7                 VerificationSequence
```

3.2.1 **`ProposalV0` has no `Version` field.** It is the single allowlisted exception to §4.1. The
structure mirrors an encoding that already shipped in SmartBFT; adding a `Version` field would
change every digest the consensus library has ever produced. The `V0` in the name is the version
tag, carried out of band.

3.2.2 Field order is **declaration order**, as shown above. Any source that lists these fields in
another order — including the composite literal in the upstream `Proposal.Digest()` — is
describing something cosmetic. It does not affect the bytes.

3.2.3 The digest of a proposal is `SHA-256` over the DER of §3.2, rendered lowercase-hex when a
string is required. Vector `proposal/v0/smartbft-reference` records both, and the digest there is
the value the unmodified upstream implementation produces for that input.

### 3.3 Structures added later

Any structure added after v1 MUST carry `Version` as its first field, MUST be added to the annex
with its own vector before first use, and MUST NOT change any encoding in §3.1 or §3.2.

### 3.4 Digests

Unless a structure's own section says otherwise, the digest of a structure is `SHA-256` over its
complete DER encoding — the full `30 <len> …` SEQUENCE, not the contents alone.

### 3.5 Unsigned 64-bit values

Values that are logically unsigned (sequence numbers, node identifiers, nanosecond timestamps)
are carried as signed 64-bit INTEGER with a documented range invariant: the producer MUST reject
values above 2^63-1 at construction. They are all far below that bound in practice. This keeps a
plain INTEGER on the wire and avoids the arbitrary-precision encoding a true unsigned 64-bit
value would need.

## 4. The two rules

### 4.1 V-RULE

**Every top-level structure begins with `Version`, and every decoder MUST reject a version it
does not know.** `ProposalV0` (§3.2.1) is the single exception.

Attack prevented: a DER decoder that maps a SEQUENCE onto a fixed field list **silently discards
trailing elements it was not expecting**. A v2 structure `{Root, Seq, Extra}` handed to a v1
decoder for `{Root, Seq}` decodes successfully with no error and no leftover bytes, and the v1
node never sees `Extra`. If `Extra` is security-relevant — a purpose tag, a new signature scope —
the v1 node validates something it did not fully read. Rejecting unknown versions is the only
mechanism that makes "frozen v1, additive only" mechanically true against that decoder behaviour.

An implementation MUST check the version before acting on any other field.

### 4.2 R-RULE

**Every decode MUST fail unless zero bytes remain after the structure.**

Attack prevented: appending bytes after a well-formed DER structure does not make it
undecodable — a permissive decoder returns the decoded value and hands the leftovers back to the
caller as a separate result. A caller that ignores the leftovers accepts `DER || 0xff 0xff` as
equivalent to `DER`, while the two have **different digests**. That is digest malleability: an
attacker mints an unlimited family of byte strings that all decode to the same authorised value
but hash differently, defeating any deduplication, equivocation check or signature scope keyed on
the digest.

An implementation MUST treat leftover bytes as a decode error, not as a warning.

### 4.3 Both rules are pinned by the annex

`TestVectorRules` takes each `Header` vector's real bytes, increments the `Version` content byte,
and requires a version error; then appends `0xff` and requires a trailing-bytes error. A
conformant implementation SHOULD run the same two derivations over the annex.

## 5. Merkle node hashing

Merkle node hashing does **not** use DER. It is fixed-width domain-separated concatenation, hashed
with SHA-256.

### 5.1 Common encoding

| Component | Width | Encoding |
|---|---|---|
| prefix | 1 byte | see §5.2 |
| `treeID` | 8 bytes | unsigned big-endian |
| `depth` | 1 byte | unsigned |
| length prefix | 8 bytes | unsigned big-endian |
| child digest | 32 bytes | raw, **no** length prefix — the width is fixed |

### 5.2 The three node forms

```
leaf      SHA-256( 0x00 ‖ treeID ‖ depth ‖ len(key) ‖ key ‖ len(val) ‖ val )
internal  SHA-256( 0x01 ‖ treeID ‖ depth ‖ left ‖ right )
empty     SHA-256( 0x02 ‖ treeID ‖ depth )
```

Worked example, vector `merkle/leaf/basic` — `treeID` 1, `depth` 0, key `"key"`, value `"val"`:

```
00                  prefix, leaf
0000000000000001    treeID
00                  depth
0000000000000003    len(key)
6b6579              "key"
0000000000000003    len(val)
76616c              "val"
-> 6fd00b5b8e0150f8b35d08a1c712de26bf6dc47a1c50054d109642db80fcc9b9
```

### 5.3 What each bound field prevents

- **Distinct leaf and internal prefixes** prevent second-preimage attacks: without them a
  32-byte key and 32-byte value at a leaf are indistinguishable from a pair of child digests, so
  an internal node can be presented as a leaf and a proof of a fabricated value verifies.
- **`treeID`** prevents cross-tree relocation. This system has two authenticated structures, and
  without `treeID` a proof valid in one is valid in the other. Vectors `merkle/leaf/basic` and
  `merkle/leaf/tree2` differ only in `treeID` and hash differently.
- **`depth`** prevents relocation within a tree — a subtree cannot be lifted to another level.
  Vectors `merkle/leaf/basic` and `merkle/leaf/depth1` demonstrate this.
- **Length prefixes on `key` and `val`** prevent collision by re-splitting: without them
  `("ab","c")` and `("a","bc")` hash identically and two distinct states share a root.
- **The `0x02` empty prefix** keeps an empty subtree from being constructible as a leaf. Without
  a third prefix, a proof of non-membership and a proof of membership-of-the-empty-value collide.

### 5.4 Cost of the binding

`treeID` and `depth` add 9 bytes to every node preimage. Adding them after v1 ships would be a
breaking release under §1.3, so they are in v1 unconditionally.

### 5.5 Ordering

`left` and `right` are positional and MUST NOT be sorted or normalised. Swapping them yields a
different node.

### 5.6 Why this path is not DER

Measured on Apple M2 Max, Go 1.26.5:

| Operation | ns/op |
|---|---|
| DER-encode `{32-byte string, int64, int64}` (a proposal header) | 614 |
| Equivalent fixed-width concatenation | 7.5 |
| **Merkle internal node, domain-separated concatenation** | **68** |
| **Merkle internal node, DER-encoded** | **1601** |

DER-encoding Merkle nodes is 23× slower on a path that runs millions of times per compaction, and
DER by itself would not supply the domain separation §5.3 requires. Both encodings are therefore
specified, each for the job it fits.

## 6. `ConsensusTime` policy

The **encoding** of `ConsensusTime` is frozen here (§3.1: `int64` Unix nanoseconds). The
**acceptance policy** below is normative but is implemented and tested in Phase 3, at the
`VerifyProposal` call site. Nothing in Phase 1 depends on it.

6.1 The leader stamps its own wall clock into `ConsensusTime` when it constructs a proposal.

6.2 Validation MUST read no local clock. A replica accepts `t` if and only if, writing `p` for
the `ConsensusTime` of the last decision it has committed:

```
t > p
t - p <= MAX_STEP
```

`MAX_STEP` is a fixed protocol constant, identical on every replica.

6.3 §6.2 is stated negatively as well, because it is the whole point of the rule: a replica MUST
NOT compare `ConsensusTime` against its own clock. Two honest replicas with normally drifting
clocks would reach different verdicts on the same proposal, acceptance would not be a function of
committed state, and identical apply would break. An earlier version of this section required
exactly that comparison and was wrong.

6.4 The monotonicity check of §6.2 is against the last **committed** value, not a locally tracked
one. A new leader after a view change inherits `p` from the log like everyone else, so it cannot
move time backwards and there is nothing to deadlock on.

6.5 Open parameter, to be decided in Phase 3: the value of `MAX_STEP`. Too large and §6.6 widens.
Too small and an idle cluster stalls — after a gap longer than `MAX_STEP` an honest leader's true
clock already exceeds `p + MAX_STEP`, so it must propose a stamp it knows to be stale or be
rejected.

6.6 Accepted limitation, stated rather than left implicit: a Byzantine leader can place
`ConsensusTime` anywhere in `(p, p + MAX_STEP]`, and the skew compounds across decisions. Every
honest replica still agrees on the value, so state remains deterministic and TTL expiry still
fires identically everywhere. Determinism is preserved; timeliness is not. `ConsensusTime` is a
deterministic clock, not a trustworthy one, and MUST NOT be used as evidence of when an event
actually occurred.

## 7. Compatibility

7.1 A v1 encoding is never edited. Not to fix a field name, not to reorder for readability, not
to make a field optional.

7.2 To introduce v2 of a structure:

1. Bump `Version` to 2.
2. Append the new fields after the existing ones, in declaration order.
3. Add a **new** vector to `testdata/vectors.json` for the v2 encoding. Leave every v1 vector
   untouched.
4. Ship the decoder that accepts version 2 to every replica **before** any replica emits version
   2 bytes.

7.3 A v1 node handed v2 bytes rejects them under §4.1. It does not half-read them. That rejection
is the intended behaviour and is what makes step 4 an ordering requirement rather than a
suggestion.

7.4 Removing or renaming a field, changing a field's type, changing field order, and changing a
Merkle prefix are all breaking changes under §1.3. There is no in-place migration for them: the
cluster stops, upgrades, and restarts from a state root that both versions agree on.

7.5 A conformance failure against the annex is a breaking wire change, not a broken test. The
test suite says so on failure, and the correct response is to revert the encoding change or take
§7.2, never to update the vector.
