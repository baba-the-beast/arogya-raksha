# ArogyaRaksha: Cryptographic Architecture & Formal Specification

**System:** ArogyaRaksha High-Assurance Clinical Security Platform  
**Compliance:** NIST SP 800-38D (GCM), NIST SP 800-131A (Key Lengths), RFC 7914 (scrypt), RFC 6238 (TOTP)  
**Classification:** Cryptographic Standard Specification  
**Document Version:** 2.0.0-PROD  

---

## 1. Cryptographic Primitive Summary

ArogyaRaksha employs modern, mathematically proven cryptographic primitives with zero reliance on deprecated algorithms (MD5, SHA-1 for hashing, DES, 3DES, or AES-CBC without MAC):

| Security Domain | Primitive / Standard | Parameters / Key Size | Security Objective | Justification |
|:---|:---|:---|:---|:---|
| **Data at Rest (PHI)** | AES-256-GCM (NIST SP 800-38D) | 256-bit key, 96-bit nonce, 128-bit GMAC tag | Confidentiality & Authenticity | Prevents bit-flipping, padding oracles, and tampering |
| **Subkey Derivation** | HKDF-SHA256 (RFC 5869) | Purpose-specific context labels | Cryptographic Domain Separation | Isolates keys across clinical data, TOTP, sessions, and webhooks |
| **Context Binding** | RFC 8785 Canonical JSON AAD | Deterministic JSON: `tenant_id`, `patient_id`, `version_id` | Anti-Splicing & Cross-Tenant Defense | Binds ciphertext cryptographically to patient & tenant ID |
| **Key Management** | KMS Envelope / KeyProvider | KEK wrapping ephemeral DEK, multi-version registry | Zero-Downtime Key Rotation | Enables re-encryption without application downtime |
| **Password Storage** | `scrypt` (RFC 7914) | $N=32768, r=8, p=1$, 128-bit salt | Credential Confidentiality | Memory-hard defense against GPU/ASIC offline brute force |
| **Multi-Factor Auth** | TOTP (RFC 6238) + AES-256-GCM | HMAC-SHA1, 30s window, Base32 encrypted at rest | Identity Assurance | Plaintext TOTP secret is never persisted to database |
| **Audit Log Integrity** | Recursive SHA-256 Hash Chain | 256-bit digest chained $Block_N \to Block_{N-1}$ with `tenant_id` | Non-Repudiation & Tamper-Evidence | Mathematically detects row deletion, insertion, or edit |
| **Entropy Source** | OS CSPRNG (`Crypto.Random`) | Platform entropy via kernel (`/dev/urandom`) | Unpredictability | Generates nonces, salts, and session tokens |

---

## 2. Authenticated Encryption with Associated Data (AEAD)

### 2.1 AES-256-GCM Specification
Galois/Counter Mode (GCM) is an authenticated encryption mode that provides both data confidentiality using counter mode and data integrity using Galois field multiplication ($GF(2^{128})$).

```
                      +-------------------+
                      |   256-bit Key K   |
                      +-------------------+
                                |
       +------------------------+------------------------+
       |                                                 |
+--------------+                                  +--------------+
| 96-bit Nonce |                                  |  RFC 8785 AAD|
+--------------+                                  +--------------+
       |                                                 |
       v                                                 v
[Counter Engine]  <--- Plaintext PHI --->           [GHASH in GF(2^128)]
       |                                                 |
       v                                                 v
[Ciphertext Bytes] -----------------------------> [128-bit GMAC Tag]
```

#### Mathematical Formulation:
1. **Counter Generation:** For each 128-bit block $i = 1, \dots, n$, the counter value is $CB_i = \text{Nonce} \parallel \text{uint32}(i+1)$. The initialization vector for the MAC tag is $CB_0 = \text{Nonce} \parallel \text{uint32}(1)$.
2. **Ciphertext Computation:**
   $$C_i = P_i \oplus \text{AES}_K(CB_i)$$
3. **Galois Field Authentication (GHASH):**
   Let $H = \text{AES}_K(0^{128})$ be the hash subkey. The authentication tag is computed by evaluating the polynomial in $GF(2^{128})$ over the bit-string concatenation of AAD, ciphertext, and their bit-lengths:
   $$S = \text{GHASH}_H(\text{AAD} \parallel 0^v \parallel C \parallel 0^u \parallel \text{len}(\text{AAD})_{64} \parallel \text{len}(C)_{64})$$
   $$\text{Tag} = \text{Trunc}_{128}(S \oplus \text{AES}_K(CB_0))$$

### 2.2 RFC 8785 Canonical JSON AAD Context Binding
Standard encryption encrypts plaintext into ciphertext without binding it to where it belongs. An attacker with database write access could transplant Patient A's valid encrypted diagnosis into Patient B's database row (ciphertext splicing or tenant transplantation).

To eliminate this vulnerability, ArogyaRaksha computes a deterministic, canonically formatted JSON AAD byte sequence for every record:
```json
{"patient_id": "P-001", "tenant_id": "tenant-alpha", "version_id": 1}
```
Serialized via `json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")`.

* **Encryption Phase:**
  ```python
  cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
  cipher.update(canonical_aad)
  ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
  ```
* **Decryption Phase:**
  ```python
  cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
  cipher.update(canonical_aad)
  plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
  ```
* **Security Guarantee:** If an attacker copies Patient 101's ciphertext to Patient 202, or attempts to transplant records across tenants, the constructed $\text{AAD}$ mismatches. The GMAC verification immediately fails with `ValueError("MAC check failed")`. The service catches this, logs `TAMPER_DETECTED`, and raises `IntegrityTamperedError`.
* **Zero Downgrade Fallback:** There are zero fallbacks to unauthenticated `aad=None`. Any missing or corrupt AAD fails closed.

### 2.3 HKDF-SHA256 Purpose-Specific Key Derivation
To prevent cryptographic cross-protocol key reuse attacks, master key material is never passed raw to ciphers. Keys are derived via HKDF-SHA256 (RFC 5869):
$$\text{Key}_{\text{purpose}} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{Salt}, \text{MasterKey}), \text{"ArogyaRaksha:Purpose:"} \parallel \text{purpose}, 32)$$

Supported purpose domains:
- `clinical_record`: Patient PHI at-rest encryption
- `totp_secret`: Multi-factor authentication secrets
- `session_token`: Server-side session authentication tokens
- `webhook_signature`: Outbound alert HMAC-SHA256 signatures

### 2.4 Nonce Management & Uniqueness Guarantee
* **Nonce Size:** 96 bits (12 bytes) strictly conforming to NIST SP 800-38D recommendation.
* **Nonce Generation:** Every single encryption invocation draws 12 fresh bytes from `Crypto.Random.get_random_bytes(12)`.
* **Collision Probability:** Under standard birthday paradox bounds, with a 96-bit random nonce, the probability of a nonce collision after $N = 2^{32}$ encryptions under the same key is less than $2^{-33} \approx 10^{-10}$, well within NIST safety margins.

---

## 3. Key Management & Cloud KMS Envelope Architecture

### 3.1 Cloud KMS Envelope Hierarchy
1. **Key Encryption Key (KEK):** Managed inside a Hardware Security Module (HSM) or Cloud KMS (Google Cloud KMS, AWS KMS, Azure Key Vault).
2. **Data Encryption Key (DEK):** Generated ephemerally or derived via purpose derivation. Encrypted under KEK before persistence.
3. **`CryptoEnvelope` Object:**
   ```json
   {
     "key_version": 1,
     "wrapped_dek": "hex...",
     "algorithm": "AES-256-GCM",
     "aad_canonical": {"tenant_id": "...", "patient_id": "...", "version_id": 1}
   }
   ```
4. **Fail-Closed Provider:** `ProductionKmsProvider` raises `NotImplementedError` or fails closed if cloud KMS endpoints are unreachable or unconfigured, preventing silent fallback to plaintext or insecure local keys.

### 3.2 Key Rotation Lifecycle (`scripts/rotate_keys.py`)
Key rotation executes without service downtime:
1. Administrator generates a new 256-bit key ($K_2$) and injects it into the environment as `MASTER_ENCRYPTION_KEY_V2`.
2. Application configuration sets `ACTIVE_KEY_VERSION = 2`. All new writes immediately encrypt under $K_2$.
3. The offline or background migration worker iterates over rows where `key_version < 2`:
   - Decrypts historical fields using $K_1$ and historical AAD ($\text{kv}=1$).
   - Re-encrypts fields using $K_2$ with fresh 96-bit nonces, generating new tags and target AAD ($\text{kv}=2$).
   - Atomically updates the row and sets `key_version = 2`.
4. Once all records reach version 2, $K_1$ is safely deprecated and decommissioned.

---

## 4. Credential & Identity Cryptography

### 4.1 Password Hashing with scrypt
Passwords are never stored in reversible or fast-hash formats. ArogyaRaksha uses `scrypt` as implemented by Werkzeug/Python:
$$\text{Hash} = \text{scrypt}(\text{password}, \text{salt}, N=32768, r=8, p=1)$$
* **CPU/Memory Cost ($N$):** $32,768$ iterations requiring 32 MB of RAM per hash evaluation.
* **Block Size ($r$):** $8$ (1024 bytes memory mixing).
* **Parallelization ($p$):** $1$ (single execution thread).
* **ASIC/GPU Resistance:** Unlike SHA-256 or bcrypt, which can be evaluated at billions of hashes/second on modern GPU farms, `scrypt` requires dedicated high-bandwidth memory access for every thread, making distributed dictionary attacks economically and technically non-viable.

### 4.2 Multi-Factor Authentication (TOTP)
* **Standard:** RFC 6238 Time-Based One-Time Password Algorithm.
* **Time Step:** $T_0 = 0$, $T_X = 30$ seconds.
* **Hash Primitive:** HMAC-SHA1 truncated to 6 decimal digits.
* **Secret Protection:** TOTP Base32 seeds are encrypted at rest with AES-256-GCM. The database columns `totp_secret_encrypted`, `totp_secret_nonce`, and `totp_secret_tag` ensure that a compromised database dump does not expose active second-factor authenticators.

---

## 5. Tamper-Evident Audit Hash Chain

### 5.1 Chain Formulation
To guarantee non-repudiation and detect any illicit modification or deletion of audit logs, the `audit_logs` table forms a cryptographically linked recursive blockchain:

$$Block_0 = \text{Genesis} \implies \text{current\_hash} = \text{SHA256}("0" \parallel \text{fields}_0)$$
$$Block_N \implies \text{current\_hash} = \text{SHA256}(\text{previous\_hash}_{N-1} \parallel \text{timestamp}_N \parallel \text{user\_id}_N \parallel \text{action}_N \parallel \text{resource}_N \parallel \text{ip}_N)$$

```
+--------------------+        +--------------------+        +--------------------+
|    Audit Log #1    |        |    Audit Log #2    |        |    Audit Log #3    |
| prev: "0000...000" | <----+ | prev: "a4f8...12b" | <----+ | prev: "7c39...89e" |
| curr: "a4f8...12b" |        | curr: "7c39...89e" |        | curr: "9d11...f04" |
+--------------------+        +--------------------+        +--------------------+
```

### 5.2 Verification Algorithm
1. The verification script (`audit_service.verify_chain()`) fetches all records ordered by `id ASC`.
2. For each record $N$:
   - Verifies that `previous_hash` strictly equals `current_hash` of record $N-1$.
   - Recomputes the expected SHA-256 digest over the canonical representation of record $N$'s fields.
   - Asserts that recomputed digest strictly matches stored `current_hash`.
3. If an adversary deletes a row, updates an action, or modifies an IP address, the entire subsequent chain breaks, identifying the exact record ID where tampering occurred.

---

## 6. Process Isolation & PRNG Entropy Preservation

### 6.1 Entropy Preservation & Fork Hazards
When multiprocessing WSGI servers fork worker processes, shared PRNG states can lead to duplicate random sequences across different worker processes:
* **Worker Model Choice:** Gunicorn is configured with **synchronous workers** (`-w 4`, `worker_class="sync"`).
* **Entropy Guarantee:** PyCryptodome's `Crypto.Random.get_random_bytes` draws directly from OS entropy pool (`os.urandom`), which automatically handles post-fork entropy reseeding at the Linux kernel level.
* **Coroutines Avoided:** We explicitly prohibit asynchronous greenlet/gevent worker models to eliminate risks of unseeded co-routine PRNG states.
