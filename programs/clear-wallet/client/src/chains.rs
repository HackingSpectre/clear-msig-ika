//! Off-chain mirrors of the on-chain destination-chain serializers.
//!
//! These produce the EXACT byte sequence the program produces from inside
//! `ika_sign`. The e2e test (and any relayer) needs the raw preimage to send
//! along with the gRPC `Sign` request — Ika hashes the preimage with the
//! configured `hash_scheme` and verifies it matches the on-chain
//! `MessageApproval.message_hash`.
//!
//! Keep these in lockstep with `clear_wallet::chains::*`. The on-chain code
//! is `#[no_std]` and uses fixed-size buffers; here we use `Vec<u8>` for
//! convenience but the wire bytes are identical.
//!
//! Each module also exposes a `sighash` helper that computes the same
//! 32-byte hash the program produces, so off-chain code can verify proposals
//! before submitting them and so unit tests can compare against reference
//! implementations (rust-bitcoin, etc.).

pub mod bitcoin {
    //! Bitcoin P2WPKH BIP143 sighash mirror.
    //!
    //! Single-input, single-output P2WPKH. Identical wire bytes to
    //! `clear_wallet::chains::bitcoin::build_sighash`. Returns `sha256d` of
    //! the BIP143 preimage — that's the 32 bytes Bitcoin's `OP_CHECKSIG`
    //! verifier expects to be ECDSA-signed.
    //!
    //! Spec: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

    use sha2::{Digest, Sha256};

    pub struct P2wpkhSpend {
        pub version: u32,
        pub lock_time: u32,
        pub sequence: u32,
        pub sighash_type: u32, // 0x01 = SIGHASH_ALL
        pub prev_txid: [u8; 32],
        pub prev_vout: u32,
        pub prev_amount_sats: u64,
        pub sender_pkh: [u8; 20],
        pub recipient_pkh: [u8; 20],
        pub send_amount_sats: u64,
    }

    impl P2wpkhSpend {
        /// Returns the full BIP143 preimage bytes (182 bytes for the layout
        /// fixed by the on-chain serializer).
        pub fn bip143_preimage(&self) -> Vec<u8> {
            let mut outpoint = [0u8; 36];
            outpoint[..32].copy_from_slice(&self.prev_txid);
            outpoint[32..36].copy_from_slice(&self.prev_vout.to_le_bytes());

            let hash_prevouts = sha256d(&outpoint);
            let hash_sequence = sha256d(&self.sequence.to_le_bytes());

            // P2WPKH output: amount(8 LE) || varint(22) || OP_0 push20 pkh
            let mut output_buf = [0u8; 8 + 1 + 22];
            output_buf[..8].copy_from_slice(&self.send_amount_sats.to_le_bytes());
            output_buf[8] = 22;
            output_buf[9] = 0x00;
            output_buf[10] = 0x14;
            output_buf[11..31].copy_from_slice(&self.recipient_pkh);
            let hash_outputs = sha256d(&output_buf);

            // scriptCode = 0x19 76 a9 14 <pkh> 88 ac
            let mut script_code = [0u8; 26];
            script_code[0] = 0x19;
            script_code[1] = 0x76;
            script_code[2] = 0xa9;
            script_code[3] = 0x14;
            script_code[4..24].copy_from_slice(&self.sender_pkh);
            script_code[24] = 0x88;
            script_code[25] = 0xac;

            let mut preimage = Vec::with_capacity(182);
            preimage.extend_from_slice(&self.version.to_le_bytes());
            preimage.extend_from_slice(&hash_prevouts);
            preimage.extend_from_slice(&hash_sequence);
            preimage.extend_from_slice(&outpoint);
            preimage.extend_from_slice(&script_code);
            preimage.extend_from_slice(&self.prev_amount_sats.to_le_bytes());
            preimage.extend_from_slice(&self.sequence.to_le_bytes());
            preimage.extend_from_slice(&hash_outputs);
            preimage.extend_from_slice(&self.lock_time.to_le_bytes());
            preimage.extend_from_slice(&self.sighash_type.to_le_bytes());
            assert_eq!(preimage.len(), 182);
            preimage
        }

        /// Returns the 32-byte sighash that the dWallet network should sign:
        /// `sha256d(bip143_preimage)`.
        pub fn sighash(&self) -> [u8; 32] {
            sha256d(&self.bip143_preimage())
        }
    }

    fn sha256d(data: &[u8]) -> [u8; 32] {
        let first = Sha256::digest(data);
        let second = Sha256::digest(first);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ── Reference helpers ───────────────────────────────────────────
        //
        // We compare our hand-rolled BIP143 sighash against rust-bitcoin's
        // canonical implementation, then sign with libsecp256k1 and verify.
        // This proves both the on-chain serializer (which produces the same
        // bytes via the no_std builder) and the off-chain mirror are
        // byte-correct against the network rules.

        use bitcoin::absolute::LockTime;
        use bitcoin::consensus::Decodable;
        use bitcoin::hashes::{hash160, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        use bitcoin::transaction::Version;
        use bitcoin::{
            Address as BtcAddress, Amount, CompressedPublicKey, Network, OutPoint, PublicKey,
            ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        fn pkh_of(secp: &Secp256k1<bitcoin::secp256k1::All>, sk: &SecretKey) -> [u8; 20] {
            let pk = bitcoin::secp256k1::PublicKey::from_secret_key(secp, sk);
            let bpk = PublicKey::new(pk);
            let h = hash160::Hash::hash(&bpk.to_bytes());
            *h.as_byte_array()
        }

        #[test]
        fn bip143_sighash_matches_rust_bitcoin_and_verifies() {
            let secp = Secp256k1::new();
            // Deterministic key for the test (NOT for production).
            let sender_sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
            let recipient_sk = SecretKey::from_slice(&[0x22u8; 32]).unwrap();

            let sender_pkh = pkh_of(&secp, &sender_sk);
            let recipient_pkh = pkh_of(&secp, &recipient_sk);

            // Tx parameters.
            let prev_txid_bytes: [u8; 32] = [
                0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
                0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
                0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
                0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
            ];
            let prev_vout: u32 = 0;
            let prev_amount_sats: u64 = 100_000_000; // 1 BTC
            let send_amount_sats: u64 = 99_990_000;  // ~10k sats fee
            let version: u32 = 2;
            let lock_time: u32 = 0;
            let sequence: u32 = 0xfffffffd;
            let sighash_type: u32 = 0x01; // SIGHASH_ALL

            // ── Our off-chain mirror ────────────────────────────────────
            let spend = P2wpkhSpend {
                version,
                lock_time,
                sequence,
                sighash_type,
                prev_txid: prev_txid_bytes,
                prev_vout,
                prev_amount_sats,
                sender_pkh,
                recipient_pkh,
                send_amount_sats,
            };
            let our_sighash = spend.sighash();

            // ── rust-bitcoin reference ──────────────────────────────────
            // Build the same logical transaction and use SighashCache to
            // produce the canonical BIP143 sighash. rust-bitcoin's `Txid`
            // is internal byte order; we use the same bytes our spend uses,
            // which the on-chain code treats as opaque too.
            let prev_txid = Txid::from_byte_array(prev_txid_bytes);

            let sender_compressed = CompressedPublicKey::from_private_key(
                &secp,
                &bitcoin::PrivateKey::new(sender_sk, Network::Bitcoin),
            )
            .unwrap();
            let recipient_compressed = CompressedPublicKey::from_private_key(
                &secp,
                &bitcoin::PrivateKey::new(recipient_sk, Network::Bitcoin),
            )
            .unwrap();
            let sender_addr = BtcAddress::p2wpkh(&sender_compressed, Network::Bitcoin);
            let recipient_addr = BtcAddress::p2wpkh(&recipient_compressed, Network::Bitcoin);

            let tx = Transaction {
                version: Version(version as i32),
                lock_time: LockTime::from_consensus(lock_time),
                input: vec![TxIn {
                    previous_output: OutPoint { txid: prev_txid, vout: prev_vout },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(sequence),
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(send_amount_sats),
                    script_pubkey: recipient_addr.script_pubkey(),
                }],
            };

            let mut cache = SighashCache::new(&tx);
            let ref_sighash = cache
                .p2wpkh_signature_hash(
                    0,
                    &sender_addr.script_pubkey(),
                    Amount::from_sat(prev_amount_sats),
                    EcdsaSighashType::All,
                )
                .expect("p2wpkh_signature_hash");

            assert_eq!(
                hex::encode(our_sighash),
                hex::encode(ref_sighash.to_byte_array()),
                "our BIP143 sighash must match rust-bitcoin's",
            );

            // ── Sign + verify with libsecp256k1 ─────────────────────────
            // Sign our sighash and verify using the canonical secp256k1
            // verifier. This is the same operation Bitcoin's OP_CHECKSIG
            // performs, so a successful verification proves both our hash
            // and our key derivation are interoperable with bitcoind.
            let msg = Message::from_digest(our_sighash);
            let signature = secp.sign_ecdsa(&msg, &sender_sk);
            let sender_pk =
                bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sender_sk);
            secp.verify_ecdsa(&msg, &signature, &sender_pk)
                .expect("ECDSA verification failed");

            // Sanity-check that the witness program (HASH160 of the pubkey)
            // matches what we asserted on as `sender_pkh`.
            let onchain_witness_program = sender_addr.witness_program().unwrap();
            assert_eq!(
                onchain_witness_program.program().as_bytes(),
                &sender_pkh,
                "sender_pkh must equal the address's witness program",
            );

            // Round-trip the rust-bitcoin tx through consensus encoding too,
            // just to make sure our test fixture is itself a valid tx.
            let raw = bitcoin::consensus::encode::serialize(&tx);
            let _decoded = Transaction::consensus_decode(&mut &raw[..]).unwrap();
        }

        /// Cross-check: our preimage + the on-chain serializer produce
        /// identical bytes. We can't link the on-chain `chains::bitcoin::
        /// build_sighash` directly (it takes an `Intent` zero-copy struct),
        /// so this test reproduces the byte layout the on-chain serializer
        /// emits and asserts it matches our `P2wpkhSpend::bip143_preimage`.
        ///
        /// If this test ever drifts from the on-chain `clear_wallet::chains::
        /// bitcoin::build_sighash`, the off-chain mirror has rotted — the two
        /// must be byte-identical or `ika_sign` will produce a hash the
        /// dWallet network can't verify.
        #[test]
        fn off_chain_preimage_matches_on_chain_layout() {
            let spend = P2wpkhSpend {
                version: 2,
                lock_time: 0,
                sequence: 0xfffffffd,
                sighash_type: 1,
                prev_txid: [0xab; 32],
                prev_vout: 7,
                prev_amount_sats: 50_000,
                sender_pkh: [0xcd; 20],
                recipient_pkh: [0xef; 20],
                send_amount_sats: 49_000,
            };
            let preimage = spend.bip143_preimage();

            // Manually pin the byte layout per BIP143 §2:
            //  4   nVersion
            //  32  hashPrevouts (sha256d of outpoint)
            //  32  hashSequence (sha256d of sequence_le)
            //  36  outpoint (txid || vout_le)
            //  26  scriptCode (0x19 76 a9 14 <pkh> 88 ac)
            //  8   amount
            //  4   nSequence
            //  32  hashOutputs
            //  4   nLockTime
            //  4   sighash_type
            assert_eq!(preimage.len(), 4 + 32 + 32 + 36 + 26 + 8 + 4 + 32 + 4 + 4);
            assert_eq!(&preimage[0..4], &2u32.to_le_bytes());
            // outpoint at offset 68
            assert_eq!(&preimage[68..100], &[0xab; 32]);
            assert_eq!(&preimage[100..104], &7u32.to_le_bytes());
            // scriptCode header at 104..108
            assert_eq!(&preimage[104..108], &[0x19, 0x76, 0xa9, 0x14]);
            assert_eq!(&preimage[108..128], &[0xcd; 20]);
            assert_eq!(&preimage[128..130], &[0x88, 0xac]);
            // amount at 130..138
            assert_eq!(&preimage[130..138], &50_000u64.to_le_bytes());
            // sequence at 138..142
            assert_eq!(&preimage[138..142], &0xfffffffd_u32.to_le_bytes());
            // locktime at 174..178
            assert_eq!(&preimage[174..178], &0u32.to_le_bytes());
            // sighash_type at 178..182
            assert_eq!(&preimage[178..182], &1u32.to_le_bytes());
        }
    }
}

pub mod evm {
    /// EIP-1559 RLP-encoded transaction preimage (the bytes that get
    /// keccak256-hashed to produce the sighash).
    pub struct Tx1559 {
        pub chain_id: u64,
        pub nonce: u64,
        pub max_priority_fee_per_gas: u64,
        pub max_fee_per_gas: u64,
        pub gas_limit: u64,
        pub to: [u8; 20],
        pub value: u64,
        pub data: Vec<u8>,
    }

    impl Tx1559 {
        /// Returns `0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data, []])`
        pub fn rlp_preimage(&self) -> Vec<u8> {
            let mut inner = Vec::new();
            rlp_u64(&mut inner, self.chain_id);
            rlp_u64(&mut inner, self.nonce);
            rlp_u64(&mut inner, self.max_priority_fee_per_gas);
            rlp_u64(&mut inner, self.max_fee_per_gas);
            rlp_u64(&mut inner, self.gas_limit);
            rlp_bytes(&mut inner, &self.to);
            rlp_u64(&mut inner, self.value);
            rlp_bytes(&mut inner, &self.data);
            // Empty access list = empty list
            inner.push(0xc0);

            let mut out = Vec::with_capacity(inner.len() + 8);
            out.push(0x02); // EIP-1559 type byte
            rlp_list_header(&mut out, inner.len());
            out.extend_from_slice(&inner);
            out
        }
    }

    fn rlp_u64(out: &mut Vec<u8>, val: u64) {
        if val == 0 {
            return rlp_bytes(out, &[]);
        }
        let bytes = val.to_be_bytes();
        let leading = bytes.iter().take_while(|&&b| b == 0).count();
        rlp_bytes(out, &bytes[leading..])
    }

    fn rlp_bytes(out: &mut Vec<u8>, data: &[u8]) {
        if data.len() == 1 && data[0] < 0x80 {
            out.push(data[0]);
        } else if data.len() < 56 {
            out.push(0x80 + data.len() as u8);
            out.extend_from_slice(data);
        } else {
            let len_bytes = encode_len_be(data.len());
            out.push(0xb7 + len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
            out.extend_from_slice(data);
        }
    }

    fn rlp_list_header(out: &mut Vec<u8>, payload_len: usize) {
        if payload_len < 56 {
            out.push(0xc0 + payload_len as u8);
        } else {
            let len_bytes = encode_len_be(payload_len);
            out.push(0xf7 + len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
    }

    fn encode_len_be(len: usize) -> Vec<u8> {
        let bytes = (len as u64).to_be_bytes();
        let leading = bytes.iter().take_while(|&&b| b == 0).count();
        bytes[leading..].to_vec()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rlp_minimal() {
            // Reference EIP-1559 tx vector: empty data, common fields.
            let tx = Tx1559 {
                chain_id: 1,
                nonce: 0,
                max_priority_fee_per_gas: 1_500_000_000,
                max_fee_per_gas: 30_000_000_000,
                gas_limit: 21_000,
                to: [0x42; 20],
                value: 1_000_000_000_000_000, // 0.001 ETH in wei
                data: vec![],
            };
            let preimage = tx.rlp_preimage();
            // Sanity: starts with 0x02
            assert_eq!(preimage[0], 0x02);
            // Sanity: contains the recipient bytes
            assert!(preimage.windows(20).any(|w| w == [0x42u8; 20]));
        }
    }
}
