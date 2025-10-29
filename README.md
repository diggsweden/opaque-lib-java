<!--
SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government

SPDX-License-Identifier: EUPL-1.2
-->

# OPAQUE client java

[![License: EUPL 1.2](https://img.shields.io/badge/License-European%20Union%20Public%20Licence%201.2-library?style=for-the-badge&&color=lightblue)](LICENSE)
[![REUSE](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.reuse.software%2Fstatus%2Fgithub.com%2Fdiggsweden%2Fopaque-lib-java&query=status&style=for-the-badge&label=REUSE)](https://api.reuse.software/info/github.com/diggsweden/opaque-lib-java)

[![Tag](https://img.shields.io/github/v/tag/diggsweden/opaque-lib-java?style=for-the-badge&color=green)](https://github.com/diggsweden/opaque-lib-java/tags)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/diggsweden/opaque-lib-java/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/diggsweden/opaque-lib-java)

# 1. Usage

## 1.1 Dependency
Include this library in your project by including the following dependency:

```
<dependecny>
  <groupId>se.digg.crypto</groupId>
  <artifactId>opaque</artifactId>
  <version>1.0.0</version>
</dependecny>
```

## 1.2 Components

This implementation provides implementation of both an OPAQUE client and an OPAQUE server

These main components depend on the following common subcomponents

| Component              | Function                                                                  |
|------------------------|---------------------------------------------------------------------------|
| StretchAlgorithm       | Stretch algorithm. This implementation implements Argon stretch algorithm |
| HashFunctioins         | Provides the Hash, Mac and Stretch functions for other components         |
| OprfFunctions          | Implements the OPRF (Oblivious Pseudo Random Function)                    |
| KeyDerivationFunctions | Provides key derivation functions. This implementation implements HKDF    |


### 1.2.1 Stretch algorithm

This implements the `se.digg.crypto.opaque.crypto.StretchAlgorithm` interface.

Instantiation of the Stretch algorithm is demonstrated in the following example:

> StretchAlgorithm stretch = new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT)

Argon can be instantiated either by a profile, or by custom Argon parameters.

A null stretch implementation of Argon (stretch (x) = x) can be instantiated as follows:

> StretchAlgorithm stretch = new ArgonStretch(ArgonStretch.ARGON_PROFILE_IDENTITY)



### 1.2.2 HashFunctions

A `se.digg.crypto.opaque.crypto.HashFunctions` object is created as follows:

> HashFunctions hashFunctions = new HashFunctions(SHA256Digest.newInstance(), stretch)

Parameters specify the base hash function and the stretch algorithm.

### 1.2.3 OprfFunctions

This implements the `se.digg.crypto.opaque.crypto.OprfFunctions` interface.

Instantiation of an OprfFunctions object is demonstrated in the following example:

> OprfFunctions oprf = new DefaultOprfFunction(hashFunctions, context);

`context` is an optional arbitrary string for the context within which this OPRF is used.


### 1.2.4 KeyDerivationFunctions

This implements the `se.digg.crypto.opaque.crypto.KeyDerivationFunctions` interface.

Instantiation of a KeyDerivationFunctions object is demonstrated in the following example:

> KeyDerivationFunctions hkdf = new HKDFKeyDerivation(hashFunctions);


## 1.3 OPAQUE Client

This implements the `se.digg.crypto.opaque.client.OpaqueClient` interface.

Instantiation of an OpaqueClient object is demonstrated in the following example:

> OpaqueClient client = new DefaultOpaqueClient(oprf, hkdf, hashFunctions);

This interface provides functions to generate all client data needed to engage in the Opaque protocol exchange as well as
all data that needs to be stored in as session data or static records.


### 1.4

This implements the `se.digg.crypto.opaque.client.OpaqueServer` interface.

Instantiation of an OpaqueClient object is demonstrated in the following example:

> OpaqueServer server = new DefaultOpaqueServer(oprf, hkdf, hashFunctions);

This interface provides functions to generate all server data needed to engage in the Opaque protocol exchange as well as
all data that needs to be stored in as session data or static records.

# 2. HSM support

This implementation supports extending the ORF function with an additional Diffie-Hellman operation by the server private key.
This allows an HSM-based private key to be part of protection of all password records to protect them against off-line attacks
on stolen data.

When this option is used, the OPRF protocol is extended in a way that provides more security,
but deviates from the standardized implementation of the OPRF protocol.

## 2.2 Protocol changes

The following protocol changes are made to the OPRF function:

Blind evaluate calculation is updated to:

> blindEvalueate = Ppw *b* rs [* ks ]

Where `Ppw` is the password point derived from G.HashToGroup(password), `b`
is the blind `rs` is the derived OPRF private key (as defined in OPAQUE)
and `ks` is an optional static server private key that may be maintained in an HSM.

## 2.3 Usage

An HSM enabled OPAQUE client and server are instantiated in the following example:

```
StretchAlgorithm stretch = new ArgonStretch(ArgonStretch.ARGON_PROFILE_DEFAULT)
HashFunctions hashFunctions = new HashFunctions(new SHA512Digest(), stretch);
HSMEnabledOprfFunction oprf = new HSMEnabledOprfFunction(
    ECNamedCurveTable.getParameterSpec("curve25519"), hashFunctions, "HSM-Supported OPRF");
KeyDerivationFunctions hkdf = new HKDFKeyDerivation(hashFunctions);
OpaqueClient client = new DefaultOpaqueClient(oprf, hkdf, hashFunctions);
client.setIncludeY(false);
HSMEnabledOpaqueServer server = new HSMEnabledOpaqueServer(
    oprf, hkdf, hashFunctions, serverKeyPariObjects.getPrivate());
```

## 2.4 Scalar Multiplications Using PKCS#11

OPRF server evaluation requires performing a scalar multiplication (`be * ks`) where:

- `be` is the blinded element received from the client
- `ks` is the server’s private key stored in the HSM

However, when using PKCS#11 with an HSM-protected private key, there's a limitation: a Diffie-Hellman (DH) operation returns only the X-coordinate of the resulting point (i.e., the shared secret). This means we do not know the Y-coordinate of the resulting point. For a given X on the curve, there are two valid Y values (one even and one odd). The workaround described below determines the correct Y value using only DH operations, without extracting the private key.

### Workaround

To recover the correct Y-coordinate, we use the compressed point serialization format defined as:

- `compressed_point = 0x02 | X` (for even Y)
- `compressed_point = 0x03 | X` (for odd Y)

> Here, the prefix `0x02` indicates an even Y, and `0x03` indicates an odd Y, modulo the field order.

The basic idea is to:

1. Perform two DH operations with the server key:
    - `X₁ = DH(be, ks)` → returns the X coordinate only
    - `X₂ = DH(be + G, ks)` → returns the X coordinate only  
      *(where `G` is the curve’s base point)*

2. Construct the two possible points from `X₁`:
    - `Pe = decompress(0x02 || X₁)` → candidate with even Y
    - `Po = decompress(0x03 || X₁)` → candidate with odd Y

3. Add each point to `be`:
    - `R1 = Pe + be`
    - `R2 = Po + be`

4. Compare the X-coordinate of the results with `X₂`:
    - If `R1.X == X₂`, then Y is even
    - If `R2.X == X₂`, then Y is odd

By determining which reconstructed point's X value matches the output of the second DH operation, we can identify the correct Y coordinate without needing to extract or directly observe it.

This workaround enables scalar multiplication with PKCS#11-based HSMs despite their limited point information.

# 3. Protocol exchange

This section outlines the processing steps executed by the Opaque protocol

**Parameters**

- `Cord` = Curve order = modulus used when creating a random scalar
- `G` = Curve generator point


**Functions:**

- `RNG(len)` = Random byte generator producing random byte stream of `len` bytes

## 3.1. Registration phase

### 3.1.1. Registration request (Client)

**Process:**

RegistrationRequest = createRegistrationRequest(password(`pw`))

```
Scalar blind(b) = Random => {1, 2, … cord - 1}
ECPoint blindedElement(be) = (G * H(pw)) * b
```

**Output:**

- RegistrationRequest = (`be`)
- Save: `b`

### 3.1.2. Registration response (Server)

**Process:**

```
RegistrationResponse = createRegistrationResponse(
blindedElement, ServerPublicKey (Ks), CredentialIdentifier (ci), OPRF seed (ops))

seed = HKDF expand(ops, ci+”OprfKey”)
serverRegKey(rs, Rs) = deriveKey(seed, "OPAQUE-DeriveKeyPair")
ECPoint evaluatedElement(ee) = be * rs
```

**Output:**

- ReqistrationResponse = (`ee`, `Rs`)

### 3.1.3. Finalize registration request (Client)

**Process:**

finalizeRegReq(password(`pw`), blind, EvalElm(`ee`), ServerPubKey (`Ks`),
ServerId (`Is`), ClientID (`Ic`))

```
Scalar blindInverse(bi) = b modInverse (cord)  
ECPoint unblindedElement(ue) = ee * bi  ==> (G * H(pw)) * rs
finalizeHash(fh) = H(pw | (G * H(pw)) * rs | “Finalize”)
stretchedHash(sh) = stretch(fh)
randomizedPass (rpw) = HKDF extract(fh | sh)
envelopeNonce(eNonce) = RNG(nonceSize)

maskingKey(mk) = HKDF.expand(rpw | “MaskingKey”)
authKey(ak) = HKDF.expand(rpw, eNonce | “AuthKey”)
exportKey(ek) = HKDF.expand(rpw, eNonce | “ExportKey”)

seed = HKDF.expand(rpw, eNonce | “PrivateKey”)
client regKeys(rc, Rc) = deriveDHKeyPair(seed)
cleartextCredentials (cc) = (Ks, Rc, Is, Ic)

authTag = MAC{ak}(eNonce | cc)
envelope = (eNonce, authTag)
```

**Output**

- RegistrationRecord = (`Rc`, `mk`, `envelope`)
- Save: (`evelope`, `Rc`, `mk`, `ek`)


### 3.2. Authentication phase

### 3.2.1. KE1 (Client)

**Process:**

generateKe1(password(`pw`))

```
Scalar blind(ab) = Random => {1, 2, … cord - 1}
ECPoint blindedElement(abe) = (G * H(pw)) * ab
clientNonce(cNonce) = RNG(nonceSize)
clientSeed(cSeed) = RNG(seedSize)
clientKeyPair(xc, Xc) = deriveDHKeyPair(cSeed)
```

**Output:**

- KE1 = (`abe`, `cNonce`, `Xc`)
- Save: `ab`

### 3.2.2. KE2 (Server)

**Process:**

generateKe2(ServerIdentity (`Is`), ServerPrivateKey(`ks`), ServerPublicKey(`Ks`), RegistrationRecord(`Rc`, `mk`, `envelope`), CredentialIdentifier(`ci`), OPRF Seed (`ops`),
KE1(`abe`, `cNonce`, `Xc`), ClientIdentity(`Ic`))

```
seed = HKDF expand(ops, ci+”OprfKey”)
(rs, Rs) = deriveKey(seed, "OPAQUE-DeriveKeyPair")
ECPoint evaluatedElement(aee) = abe * rs

maskingNonce (mNonce) = RNG(nonceSize)
credentialResponsePad(crp) = HKDF.expand(mk, mNonce |
“CredentialResponsePad”
maskedResponse (mr) = crp XOR (Ks | envelope)
credentialReponse (cr) = (aee, mNonce, mr)

serverNonce (sNonce) = RNG(nonceSize)
serverSeed (sSeed) = RNG(seedSize)
serverKeyPair (xs, Xs) = deriveDHKeyPair(sSeed)

dh1 = DH(Xc * xs)
dh2 = DH(Xc * ks)
dh3 = DH(Rc * xs)
ikm = (dh1 | dh2 | dh3)

preamble (pa) = preamble(Ic, ke1, Is, cr, sNonce, Xs, cntext)   
derivedKeys (km2, km3, sKey) = keyDerivation(ikm, preamble)
serverMac = Mac(km2, H(pa))
authRespse (ar) = (sNonce, Xs, serverMac)
```


**Output:**

- KE2 = (`cr`, `ar`)  ==> ((`aee`, `mNonce`, `mr`),(`sNonce`, `Xs`, `serverMac`))

### 3.2.3. KE3 (Client)

**Process:**

generateKe3(ClientIdentity(`Ic`), ServerIdentity(`Is`), KE2((`aee`, `mNonce`, `mr`),(`sNonce`, `Xs`, `serverMac`))

```
Scalar blindInverse(abi) = ab modInverse (cord)  
ECPoint unblindedElement(aue) = aee * bai ==> (G * H(pw)) * rs
finalizeHash(fh) = H(pw | (G * H(pw)) * rs | “Finalize”)

stretchedHash(sh) = stretch(fh)
randomizedPass (rpw) = HKDF extract(fh | sh)

maskingKey (mk) = HKDF.expand(rpw, “MaskingKey”)
credentialResponsePad (crp) = HKDF.expand(mk, mNonce |
"CredentialResponsePad")
(Ks | Envelope) = crp XOR mr
(eNonce | authTag) = Envelope

authKey(ak) = HKDF.expand(rpw, (eNonce | “AuthKey”))
exportKey(ek) = HKDF.expand(rpw, (eNonce | “ExportKey”))

seed = HKDF.expand(rpw, eNonce | “PrivateKey”)
client regKeys(rc, Rc) = deriveDHKeyPair(seed)
cleartextCredentials (cc) = (Ks, Rc, Is, Ic)

expectedAuthTag = MAC{ak}(eNonce | cc)

dh1 = DH(Xs * xc)
dh2 = DH(Ks * xc)
dh3 = DH(Xs * rc)
ikm = (dh1 | dh2 | dh3)

preamble (pa) = preamble(Ic, ke1, Is, ke2-cr, sNonce, Xs, context)
derivedKeys (km2, km3, sKey) = keyDerivation(ikm, preamble)
expectedServerMac = Mac(km2, H(pa))

clientMac = Mac{km3}(H(preamble | expectedServerMac))

Validate authTag = expectedAuthTag
Validate serverMac = expectedServerMac
```

**Output:**

- KE3 ke3 = `clientMac`
