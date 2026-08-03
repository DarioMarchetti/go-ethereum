# ML-DSA test vectors

`empty-context.json` is a deterministic FIPS 204 ML-DSA-44 vector generated
with Cloudflare CIRCL v1.6.4. It covers the compact public-key verifier and the
FIPS external interface with an empty context.

`eip8051.json` covers both EIP-8051 precompile variants. The compact keys are
expanded during tests into `A_hat || tr || t1_hat`, using four-byte big-endian
field elements. The vector uses seed `000102...1f`, a fixed 32-byte message,
and ZKNOX ETHDILITHIUM's `sign_external_mu` implementation. For the two cases,
`mu` is computed exactly as the current EIP pseudocode requires:

- ML-DSA: `SHAKE256(tr[32] || message, 64)`
- ML-DSA-ETH: `KeccakPRNG(tr[32] || message, 64)`

The current EIP draft specifies a 32-byte `tr` and a 20,512-byte expanded key,
while its linked FIPS 204 KAT/reference code uses a 64-byte `tr` and the FIPS
empty-context prefix. Consequently, those linked signatures cannot be encoded
directly in the stated precompile ABI. This focused vector keeps the consensus
tests aligned with the draft's explicit ABI and pseudocode until the draft
resolves that mismatch.

The offline signing tests derive both key pairs from the same fixed seed and
produce deterministic signatures using an all-zero 32-byte randomizer. The
resulting compact public keys and signatures must match this ZKNOX vector byte
for byte, providing an independent cross-check of key generation and signing.
