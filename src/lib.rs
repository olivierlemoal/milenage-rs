//! Milenage authentication algorithm
//! as proposed by ETSI SAGE for 3G authentication.
//!
//! See 3GPP TS [35.205 (General)](https://www.3gpp.org/ftp/Specs/archive/35_series/35.205/),
//! [3GPP TS 35.206 (Algorithm specification)](https://www.3gpp.org/ftp/Specs/archive/35_series/35.206/)
//! and [3GPP TS 35.208 (Design conformance test data)](https://www.3gpp.org/ftp/Specs/archive/35_series/35.208/).
//!
//!
//! # Usage example
//! ```
//!#[macro_use]
//!extern crate hex_literal;
//!extern crate milenage;
//!use milenage::Milenage;
//!
//!fn main() {
//!        // Use Test set 2 from 3GPP 35.208
//!        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
//!        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
//!        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
//!
//!        let mut m = Milenage::new_with_op(k, op);
//!        let (res, ck, ik, ak) = m.f2345(&rand);
//!        
//!        assert_eq!(m.res.unwrap(), hex!("a54211d5e3ba50bf"));
//!        // or
//!        assert_eq!(res, hex!("a54211d5e3ba50bf"));
//!        assert_eq!(ck, hex!("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
//!        assert_eq!(ik, hex!("f769bcd751044604127672711c6d3441"));
//!        assert_eq!(ak, hex!("aa689c648370"));
//!}
//!
//! ```

extern crate aes_soft as aes;
extern crate block_modes;
#[cfg_attr(test, macro_use)]
extern crate hex_literal;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockCipher;
use aes::Aes128;

/// xor two 16 bytes array
fn xor(a1: &[u8; 16], a2: &[u8; 16]) -> [u8; 16] {
    let mut output = [0u8; 16];
    for i in 0..16 {
        output[i] = a1[i] ^ a2[i];
    }
    output
}

#[derive(Debug, Default)]
/// Milenage instance
pub struct Milenage {
    /// AK is a 48-bit anonymity key that is the output of either of the functions f5.
    pub ak: Option<[u8; 6]>,
    /// CK is a 128-bit confidentiality key that is the output of the function f3.
    pub ck: Option<[u8; 16]>,
    /// IK is a 128-bit integrity key that is the output of the function f4.
    pub ik: Option<[u8; 16]>,
    /// K is a 128-bit subscriber key that is an input to the functions f1, f1*, f2, f3, f4, f5 and f5*.
    pub k: [u8; 16],
    /// MACA is a 64-bit network authentication code that is the output of the function f1.
    pub maca: Option<[u8; 8]>,
    /// MACS is a 64-bit resynchronisation authentication code that is the output of the function f1*.
    pub macs: Option<[u8; 8]>,
    /// OP is a 128-bit Operator Variant Algorithm Configuration Field that is a component of the
    /// functions f1, f1*, f2, f3, f4, f5 and f5*.
    pub op: Option<[u8; 16]>,
    /// OPc is a 128-bit value derived from OP and K and used within the computation of the functions.
    pub opc: [u8; 16],
    /// RES is a 64-bit signed response that is the output of the function f2.
    pub res: Option<[u8; 8]>,
}

impl Milenage {
    ///  Returns a new initialized Milenage from K and OP
    pub fn new_with_op(k: [u8; 16], op: [u8; 16]) -> Milenage {
        let mut m = Milenage {
            k: k,
            op: Some(op),
            ..Default::default()
        };
        m.compute_opc();
        m
    }

    ///  Returns a new initialized Milenage from K and OPc
    pub fn new_with_opc(k: [u8; 16], opc: [u8; 16]) -> Milenage {
        Milenage {
            k: k,
            opc: opc,
            ..Default::default()
        }
    }

    /// F1 is the network authentication function.
    /// F1 computes network authentication code MAC-A from key K, random challenge RAND,
    /// sequence number SQN and authentication management field AMF.
    pub fn f1(&mut self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let mac = self.f1base(rand, sqn, amf);
        let mut maca = [0u8; 8];
        maca.copy_from_slice(&mac[..8]);

        self.maca = Some(maca);
        maca
    }

    /// F1Star is the re-synchronisation message authentication function.
    /// F1Star computes resynch authentication code MAC-S from key K, random challenge RAND,
    /// sequence number SQN and authentication management field AMF.
    pub fn f1star(&mut self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 8] {
        let mac = self.f1base(rand, sqn, amf);
        let mut macs = [0u8; 8];
        macs.copy_from_slice(&mac[8..]);

        self.macs = Some(macs);
        macs
    }

    /// Used by f1 and f1star
    fn f1base(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 16] {
        let rijndael_input: [u8; 16] = xor(&self.opc, rand);
        let temp = self.rijndael_encrypt(&rijndael_input);

        let mut in1 = [0u8; 16];
        in1[..6].copy_from_slice(sqn);
        in1[6..8].copy_from_slice(amf);
        in1[8..14].copy_from_slice(sqn);
        in1[14..16].copy_from_slice(amf);

        let mut rijndael_input = [0u8; 16];

        /* XOR op_c and in1, rotate by r1=64, and XOR *
         * on the constant c1 (which is all zeroes)   */

        for i in 0..16 {
            rijndael_input[(i + 8) % 16] = in1[i] ^ self.opc[i];
        }

        /* XOR on the value temp computed before */
        for (i, elem) in rijndael_input.iter_mut().enumerate() {
            *elem ^= temp[i];
        }

        let mut out1 = self.rijndael_encrypt(&rijndael_input);

        for (i, elem) in out1.iter_mut().enumerate() {
            *elem ^= &self.opc[i];
        }

        out1
    }

    /// F2345 takes key K and random challenge RAND, and returns response RES,
    /// confidentiality key CK, integrity key IK and anonymity key AK.
    pub fn f2345(&mut self, rand: &[u8; 16]) -> ([u8; 8], [u8; 16], [u8; 16], [u8; 6]) {
        let rijndael_input = xor(&self.opc, rand);
        let temp = self.rijndael_encrypt(&rijndael_input);

        // To obtain output block OUT2: XOR OPc and TEMP, rotate by r2=0, and XOR on the
        // constant c2 (which is all zeroes except that the last bit is 1).

        let mut rijndael_input = xor(&temp, &self.opc);
        rijndael_input[15] ^= 1;

        let out = self.rijndael_encrypt(&rijndael_input);
        let tmp = xor(&out, &self.opc);

        let mut res = [0u8; 8];
        let mut ak = [0u8; 6];

        res.copy_from_slice(&tmp[8..]);
        ak.copy_from_slice(&tmp[..6]);

        // To obtain output block OUT3: XOR OPc and TEMP, rotate by r3=32, and XOR on the
        // constant c3 (which is all zeroes except that the next to last bit is 1).

        let mut rijndael_input = [0u8; 16];
        for i in 0..16 {
            rijndael_input[(i + 12) % 16] = temp[i] ^ self.opc[i]
        }
        rijndael_input[15] ^= 2;

        let out = self.rijndael_encrypt(&rijndael_input);
        let ck = xor(&out, &self.opc);

        // To obtain output block OUT4: XOR OPc and TEMP, rotate by r4=64, and XOR on the
        // constant c4 (which is all zeroes except that the 2nd from last bit is 1).

        let mut rijndael_input = [0u8; 16];
        for i in 0..16 {
            rijndael_input[(i + 8) % 16] = temp[i] ^ self.opc[i]
        }
        rijndael_input[15] ^= 4;

        let out = self.rijndael_encrypt(&rijndael_input);
        let ik = xor(&out, &self.opc);

        self.res = Some(res);
        self.ck = Some(ck);
        self.ik = Some(ik);
        self.ak = Some(ak);
        (res, ck, ik, ak)
    }

    /// F5Star is the anonymity key derivation function for the re-synchronisation message.
    /// F5Star takes key K and random challenge RAND, and returns resynch anonymity key AK.
    pub fn f5star(&mut self, rand: &[u8; 16]) -> [u8; 6] {
        let mut rijndael_input = xor(&self.opc, rand);
        let temp = self.rijndael_encrypt(&rijndael_input);

        // To obtain output block OUT5: XOR OPc and TEMP, rotate by r5=96, and XOR on the
        // constant c5 (which is all zeroes except that the 3rd from last bit is 1).
        for i in 0..16 {
            rijndael_input[(i + 4) % 16] = temp[i] ^ self.opc[i];
        }
        rijndael_input[15] ^= 8;

        let mut out = self.rijndael_encrypt(&rijndael_input);
        for (i, elem) in out.iter_mut().enumerate() {
            *elem ^= &self.opc[i];
        }

        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out[..6]);

        self.ak = Some(ak);
        ak
    }

    /// Derive OP with K to produce OPc
    fn compute_opc(&mut self) {
        let op = match self.op {
            Some(v) => v,
            None => panic!("No OP value provided"),
        };
        let ciphered_opc = self.rijndael_encrypt(&op);
        self.opc = xor(&ciphered_opc, &op);
    }

    fn rijndael_encrypt(&self, input: &[u8; 16]) -> [u8; 16] {
        use crate::aes::cipher::NewBlockCipher;

        let key = GenericArray::from_slice(&self.k);
        let cipher = Aes128::new(key);
        let mut block = GenericArray::clone_from_slice(input);
        cipher.encrypt_block(&mut block);
        let mut output = [0u8; 16];
        output.copy_from_slice(&block);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Use Test set 2 from 3GPP 35.208

    #[test]
    fn test_f1star() {
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let sqn = hex!("ff9bb4d0b607");
        let amf = hex!("b9b9");
        let mut m = Milenage::new_with_op(k, op);
        let maca = m.f1star(&rand, &sqn, &amf);
        assert_eq!(maca, hex!("01cfaf9ec4e871e9"));
    }

    #[test]
    fn test_f1() {
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let sqn = hex!("ff9bb4d0b607");
        let amf = hex!("b9b9");
        let mut m = Milenage::new_with_op(k, op);
        let maca = m.f1(&rand, &sqn, &amf);
        assert_eq!(maca, hex!("4a9ffac354dfafb3"));
    }

    #[test]
    fn test_f2345() {
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let mut m = Milenage::new_with_op(k, op);
        let (res, ck, ik, ak) = m.f2345(&rand);
        println!("{:?}", (res, ck, ik, ak));
        assert_eq!(res, hex!("a54211d5e3ba50bf"));
        assert_eq!(ck, hex!("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
        assert_eq!(ik, hex!("f769bcd751044604127672711c6d3441"));
        assert_eq!(ak, hex!("aa689c648370"));
    }

    #[test]
    fn test_f5star() {
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");
        let mut m = Milenage::new_with_op(k, op);
        let ak = m.f5star(&rand);
        assert_eq!(ak, hex!("451e8beca43b"));
    }

    #[test]
    fn test_compute_opc() {
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let m = Milenage::new_with_op(k, op);
        assert_eq!(m.opc, hex!("cd63cb71954a9f4e48a5994e37a02baf"));
    }
}
