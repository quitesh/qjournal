// SPDX-License-Identifier: LGPL-2.1-or-later
//
// fsprg v0.1  -  (seekable) forward-secure pseudorandom generator
// Copyright 2012 B. Poettering
// Contact: fsprg@point-at-infinity.org
//
// See "Practical Secure Logging: Seekable Sequential Key Generators"
// by G. A. Marson, B. Poettering for details:
// http://eprint.iacr.org/2013/397
//
// Rust port from systemd src/libsystemd/sd-journal/fsprg.c

/// Recommended security parameter (bit length of the RSA modulus).
pub const FSPRG_RECOMMENDED_SECPAR: u32 = 1536;

/// Recommended seed length in bytes (96 bits).
pub const FSPRG_RECOMMENDED_SEEDLEN: usize = 96 / 8;

/// Returns the master secret key size in bytes for the given security parameter.
pub fn mskinbytes(secpar: u32) -> usize {
    assert!(is_valid_secpar(secpar));
    2 + 2 * (secpar as usize / 2) / 8 // header, p, q
}

/// Returns the master public key size in bytes for the given security parameter.
pub fn mpkinbytes(secpar: u32) -> usize {
    assert!(is_valid_secpar(secpar));
    2 + secpar as usize / 8 // header, n
}

/// Returns the state size in bytes for the given security parameter.
pub fn stateinbytes(secpar: u32) -> usize {
    assert!(is_valid_secpar(secpar));
    2 + 2 * secpar as usize / 8 + 8 // header, n, x, epoch
}

fn is_valid_secpar(secpar: u32) -> bool {
    secpar % 16 == 0 && secpar >= 16 && secpar <= 16384
}

// --- Feature-gated implementation ---

#[cfg(feature = "fss")]
mod inner {
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::{One, Zero};
    use sha2::{Digest, Sha256};

    use super::*;

    const RND_GEN_P: u32 = 0x01;
    const RND_GEN_Q: u32 = 0x02;
    const RND_GEN_X: u32 = 0x03;

    // -----------------------------------------------------------------------
    // MPI helpers (big-endian, unsigned, zero-padded on the left)
    // -----------------------------------------------------------------------

    fn mpi_export(buf: &mut [u8], x: &BigUint) {
        let bytes = x.to_bytes_be();
        assert!(bytes.len() <= buf.len());
        let pad = buf.len() - bytes.len();
        buf[..pad].fill(0);
        buf[pad..].copy_from_slice(&bytes);
    }

    fn mpi_import(buf: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buf)
    }

    // -----------------------------------------------------------------------
    // Uint64 helpers (big-endian)
    // -----------------------------------------------------------------------

    fn uint64_export(buf: &mut [u8], x: u64) {
        assert!(buf.len() == 8);
        buf.copy_from_slice(&x.to_be_bytes());
    }

    fn uint64_import(buf: &[u8]) -> u64 {
        assert!(buf.len() == 8);
        u64::from_be_bytes(buf.try_into().unwrap())
    }

    // -----------------------------------------------------------------------
    // Deterministic PRNG (SHA-256 based, matching gcry_md with no HMAC flag)
    //
    // The C code uses gcry_md_open(&hd, GCRY_MD_SHA256, 0) — plain hash, not
    // HMAC.  It feeds: seed || idx(4 bytes BE) as the base state, then for each
    // 32-byte block it clones, appends ctr(4 bytes BE), finalises, and copies.
    // -----------------------------------------------------------------------

    fn det_randomize(buf: &mut [u8], seed: &[u8], idx: u32) {
        let mut remaining = buf.len();
        let mut offset = 0;
        let mut ctr: u32 = 0;

        // Pre-compute the "base" hash state: H(seed || idx_be)
        let mut base = Sha256::new();
        base.update(seed);
        base.update(idx.to_be_bytes());

        while remaining > 0 {
            let mut h = base.clone();
            h.update(ctr.to_be_bytes());
            let digest = h.finalize();
            let cpylen = remaining.min(32);
            buf[offset..offset + cpylen].copy_from_slice(&digest[..cpylen]);
            offset += cpylen;
            remaining -= cpylen;
            ctr += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Secpar header encoding
    // -----------------------------------------------------------------------

    fn store_secpar(buf: &mut [u8], secpar: u16) {
        let val = secpar / 16 - 1;
        buf[0] = (val >> 8) as u8;
        buf[1] = val as u8;
    }

    fn read_secpar(buf: &[u8]) -> u16 {
        let val = (buf[0] as u16) << 8 | buf[1] as u16;
        16 * (val + 1)
    }

    // -----------------------------------------------------------------------
    // Prime generation: deterministically generate a prime ≡ 3 (mod 4)
    // -----------------------------------------------------------------------

    fn genprime3mod4(bits: u32, seed: &[u8], idx: u32) -> BigUint {
        let buflen = bits as usize / 8;
        assert!(bits % 8 == 0 && buflen > 0);

        let mut buf = vec![0u8; buflen];
        det_randomize(&mut buf, seed, idx);
        buf[0] |= 0xc0; // set upper two bits so n = p*q has maximum size
        buf[buflen - 1] |= 0x03; // set lower two bits to ensure ≡ 3 (mod 4)

        let mut p = mpi_import(&buf);
        while !is_probably_prime(&p) {
            p += 4u32;
        }
        p
    }

    /// Miller-Rabin primality test with 25 rounds.
    fn is_probably_prime(n: &BigUint) -> bool {
        let one = BigUint::one();
        let two = &one + &one;
        let three = &two + &one;

        if *n < two {
            return false;
        }
        if *n == two || *n == three {
            return true;
        }
        if n.is_even() {
            return false;
        }

        // Write n-1 as 2^r * d
        let n_minus_1 = n - &one;
        let mut d = n_minus_1.clone();
        let mut r: u32 = 0;
        while d.is_even() {
            d >>= 1;
            r += 1;
        }

        // Deterministic witnesses: use small primes as bases.
        // For numbers up to ~768 bits (our half-secpar), 25 rounds with
        // small-prime bases gives overwhelming confidence.
        let witnesses: [u32; 25] = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
            67, 71, 73, 79, 83, 89, 97,
        ];

        'outer: for &a in &witnesses {
            let a = BigUint::from(a);
            if a >= *n {
                continue;
            }
            let mut x = a.modpow(&d, n);
            if x == one || x == n_minus_1 {
                continue;
            }
            for _ in 0..r - 1 {
                x = x.modpow(&two, n);
                if x == n_minus_1 {
                    continue 'outer;
                }
            }
            return false;
        }
        true
    }

    // -----------------------------------------------------------------------
    // Quadratic residue generation
    // -----------------------------------------------------------------------

    fn gensquare(n: &BigUint, seed: &[u8], idx: u32, secpar: u32) -> BigUint {
        let buflen = secpar as usize / 8;
        let mut buf = vec![0u8; buflen];
        det_randomize(&mut buf, seed, idx);
        buf[0] &= 0x7f; // clear upper bit so x < n
        let x = mpi_import(&buf);
        assert!(x < *n);
        x.modpow(&BigUint::from(2u32), n)
    }

    // -----------------------------------------------------------------------
    // Compute 2^m (mod phi(p)) for a prime p, where phi(p) = p - 1
    // Uses square-and-multiply.
    // -----------------------------------------------------------------------

    fn twopowmodphi(m: u64, p: &BigUint) -> BigUint {
        let one = BigUint::one();
        let phi = p - &one;

        // Count number of bits needed to represent m
        let mut nbits = 0u32;
        while nbits < 64 && (1u64 << nbits) <= m {
            nbits += 1;
        }

        let mut r = BigUint::one();
        let mut n = nbits;
        while n > 0 {
            n -= 1;
            // r = r * r mod phi
            r = (&r * &r) % &phi;
            if m & (1u64 << n) != 0 {
                // r = 2*r mod phi
                r = &r + &r;
                if r >= phi {
                    r -= &phi;
                }
            }
        }
        r
    }

    // -----------------------------------------------------------------------
    // CRT helpers
    // -----------------------------------------------------------------------

    fn crt_decompose(x: &BigUint, p: &BigUint, q: &BigUint) -> (BigUint, BigUint) {
        (x % p, x % q)
    }

    fn crt_compose(
        xp: &BigUint,
        xq: &BigUint,
        p: &BigUint,
        q: &BigUint,
    ) -> BigUint {
        // a = (xq - xp) mod q
        // We need modular subtraction: (xq - xp) mod q
        let a = if xq >= xp {
            (xq - xp) % q
        } else {
            q - ((xp - xq) % q)
        };
        // u = p^(-1) mod q
        let u = mod_inverse(p, q).expect("p and q are coprime");
        // a = a * u mod q
        let a = (&a * &u) % q;
        // x = p * a + xp
        p * &a + xp
    }

    /// Compute the modular multiplicative inverse of a mod m using the extended
    /// Euclidean algorithm.  Returns None if gcd(a, m) != 1.
    fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        use num_bigint::BigInt;

        let a = BigInt::from(a.clone());
        let m_int = BigInt::from(m.clone());

        let mut old_r = a;
        let mut r = m_int.clone();
        let mut old_s = BigInt::one();
        let mut s = BigInt::zero();

        while !r.is_zero() {
            let quotient = &old_r / &r;
            let temp_r = r.clone();
            r = &old_r - &quotient * &r;
            old_r = temp_r;
            let temp_s = s.clone();
            s = &old_s - &quotient * &s;
            old_s = temp_s;
        }

        if old_r != BigInt::one() {
            return None;
        }

        // Ensure result is positive
        let result = ((old_s % &m_int) + &m_int) % &m_int;
        Some(result.to_biguint().unwrap())
    }

    // =======================================================================
    // Public API
    // =======================================================================

    /// Generate master key pair (msk, mpk) from seed.
    ///
    /// If seed is None, generates a random seed using the system CSPRNG.
    pub fn gen_mk(
        seed: Option<&[u8]>,
        secpar: u32,
    ) -> (Vec<u8>, Vec<u8>) {
        assert!(is_valid_secpar(secpar));

        let owned_seed;
        let seed = match seed {
            Some(s) => s,
            None => {
                use rand::RngCore;
                owned_seed = {
                    let mut buf = vec![0u8; FSPRG_RECOMMENDED_SEEDLEN];
                    rand::thread_rng().fill_bytes(&mut buf);
                    buf
                };
                &owned_seed
            }
        };

        let secpar16 = secpar as u16;
        let half = (secpar / 2) as usize;

        let p = genprime3mod4(secpar / 2, seed, RND_GEN_P);
        let q = genprime3mod4(secpar / 2, seed, RND_GEN_Q);

        // msk = [secpar_header(2)][p(half/8)][q(half/8)]
        let msk_len = mskinbytes(secpar);
        let mut msk = vec![0u8; msk_len];
        store_secpar(&mut msk[0..2], secpar16);
        mpi_export(&mut msk[2..2 + half / 8], &p);
        mpi_export(&mut msk[2 + half / 8..2 + 2 * half / 8], &q);

        // mpk = [secpar_header(2)][n(secpar/8)]
        let n = &p * &q;
        let mpk_len = mpkinbytes(secpar);
        let mut mpk = vec![0u8; mpk_len];
        store_secpar(&mut mpk[0..2], secpar16);
        mpi_export(&mut mpk[2..2 + secpar as usize / 8], &n);

        (msk, mpk)
    }

    /// Generate initial state (epoch 0) from master public key and seed.
    pub fn gen_state0(mpk: &[u8], seed: &[u8]) -> Vec<u8> {
        let secpar = read_secpar(mpk) as u32;
        let n_len = secpar as usize / 8;

        let n = mpi_import(&mpk[2..2 + n_len]);
        let x = gensquare(&n, seed, RND_GEN_X, secpar);

        let state_len = stateinbytes(secpar);
        let mut state = vec![0u8; state_len];

        // Copy mpk header + n
        state[..2 + n_len].copy_from_slice(&mpk[..2 + n_len]);
        // Write x
        mpi_export(&mut state[2 + n_len..2 + 2 * n_len], &x);
        // Epoch = 0 (already zeroed)

        state
    }

    /// Evolve the state forward by one epoch: x' = x^2 mod n, epoch++.
    pub fn evolve(state: &mut [u8]) {
        let secpar = read_secpar(state) as usize;
        let n_len = secpar / 8;

        let n = mpi_import(&state[2..2 + n_len]);
        let x = mpi_import(&state[2 + n_len..2 + 2 * n_len]);
        let epoch = uint64_import(&state[2 + 2 * n_len..2 + 2 * n_len + 8]);

        let x_new = x.modpow(&BigUint::from(2u32), &n);
        let epoch_new = epoch + 1;

        mpi_export(&mut state[2 + n_len..2 + 2 * n_len], &x_new);
        uint64_export(
            &mut state[2 + 2 * n_len..2 + 2 * n_len + 8],
            epoch_new,
        );
    }

    /// Read the current epoch from a state buffer.
    pub fn get_epoch(state: &[u8]) -> u64 {
        let secpar = read_secpar(state) as usize;
        uint64_import(&state[2 + 2 * secpar / 8..2 + 2 * secpar / 8 + 8])
    }

    /// Seek to an arbitrary epoch using the master secret key.
    pub fn seek(
        state: &mut Vec<u8>,
        epoch: u64,
        msk: &[u8],
        seed: &[u8],
    ) {
        let secpar = read_secpar(msk) as u32;
        let half = (secpar / 2) as usize;
        let n_len = secpar as usize / 8;

        let p = mpi_import(&msk[2..2 + half / 8]);
        let q = mpi_import(&msk[2 + half / 8..2 + 2 * half / 8]);
        let n = &p * &q;

        let x = gensquare(&n, seed, RND_GEN_X, secpar);

        // CRT decompose
        let (xp, xq) = crt_decompose(&x, &p, &q);

        // Compute 2^epoch mod phi(p) and 2^epoch mod phi(q)
        let kp = twopowmodphi(epoch, &p);
        let kq = twopowmodphi(epoch, &q);

        // x^(2^epoch) mod p and mod q
        let xp = xp.modpow(&kp, &p);
        let xq = xq.modpow(&kq, &q);

        // CRT compose
        let xm = crt_compose(&xp, &xq, &p, &q);

        // Write state
        let state_len = stateinbytes(secpar);
        state.resize(state_len, 0);
        store_secpar(&mut state[0..2], secpar as u16);
        mpi_export(&mut state[2..2 + n_len], &n);
        mpi_export(&mut state[2 + n_len..2 + 2 * n_len], &xm);
        uint64_export(
            &mut state[2 + 2 * n_len..2 + 2 * n_len + 8],
            epoch,
        );
    }

    /// Derive a key of length `keylen` from the current state.
    ///
    /// The `idx` parameter allows deriving multiple independent keys from the
    /// same state/epoch.
    pub fn get_key(state: &[u8], keylen: usize, idx: u32) -> Vec<u8> {
        let secpar = read_secpar(state) as usize;
        // seed for det_randomize is state[2..2 + 2*secpar/8 + 8] = n || x || epoch
        let seed_len = 2 * secpar / 8 + 8;
        let seed = &state[2..2 + seed_len];

        let mut key = vec![0u8; keylen];
        det_randomize(&mut key, seed, idx);
        key
    }
}

#[cfg(feature = "fss")]
pub use inner::*;
