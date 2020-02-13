# Milenage-rs

MILENAGE authentication algorithm as proposed by ETSI SAGE for 3G authentication.

See 3GPP TS [35.205 (General)](https://www.3gpp.org/ftp/Specs/archive/35_series/35.205/),
[3GPP TS 35.206 (Algorithm specification)](https://www.3gpp.org/ftp/Specs/archive/35_series/35.206/)
and [3GPP TS 35.208 (Design conformance test data)](https://www.3gpp.org/ftp/Specs/archive/35_series/35.208/).


# Usage example
```rust
#[macro_use]
extern crate hex_literal;
extern crate milenage;
use milenage::Milenage;

fn main() {
        // Use Test set 2 from 3GPP 35.208
        let k = hex!("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = hex!("cdc202d5123e20f62b6d676ac72cb318");
        let rand = hex!("23553cbe9637a89d218ae64dae47bf35");

        let mut m = Milenage::new_with_op(k, op);
        let (res, ck, ik, ak) = m.f2345(&rand);
        
        assert_eq!(m.res.unwrap(), hex!("a54211d5e3ba50bf"));
        // or
        assert_eq!(res, hex!("a54211d5e3ba50bf"));
        assert_eq!(ck, hex!("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
        assert_eq!(ik, hex!("f769bcd751044604127672711c6d3441"));
        assert_eq!(ak, hex!("aa689c648370"));
}
```