extern crate openssl;
use openssl::rand::rand_bytes;
use openssl::rsa::{Rsa, Padding};

extern crate num;
use num::bigint::{BigInt};

extern crate simple_asn1;
use simple_asn1::{from_der, ASN1Block};
//use num::bigint::ToBigInt;

#[macro_use]
extern crate hex_literal;

fn find_bitstrings(asns: Vec<ASN1Block>, mut result: &mut Vec<Vec<u8>>) {
    for asn in asns.iter() {
        match asn {
            ASN1Block::BitString(_, _, _, bytes) => result.push(bytes.to_vec()),
            ASN1Block::Sequence(_, _,  blocks) => find_bitstrings(blocks.to_vec(), &mut result),
            _ => (),
        }
    }
}

fn rsa_public_encrypt_pkcs1(der_pubkey: &[u8], message: &[u8]) -> Vec<u8> {
    // Outer ASN.1 encodes 1.2.840.113549.1.1 OID and wraps a bitstring, find it
    let asns: Vec<ASN1Block> = from_der(&der_pubkey).unwrap();
    println!("asns = {:?}", asns);
    for asn in asns.iter() {
        println!("asn = {:?}", asn);
    }
    let mut result: Vec<Vec<u8>> = vec![];
    find_bitstrings(asns, &mut result);

    let inner_asn: Vec<ASN1Block> = from_der(&result[0]).unwrap();
    println!("inner_asn {:?}", inner_asn[0]);
    let (n, e) =
    match &inner_asn[0] {
        ASN1Block::Sequence(_, _, blocks) => {
            let n = match &blocks[0] {
                ASN1Block::Integer(_, _, n) => Some(n),
                _ => None,
            };

            let e = match &blocks[1] {
                ASN1Block::Integer(_, _, e) => Some(e),
                _ => None,
            };
            (n, e)

        },
        _ => (None, None)
    };
    let n = n.unwrap();
    let e = e.unwrap();
    /* Use known public key, with private key below (d):
>>> from Crypto.PublicKey import RSA
>>> k=RSA.generate(1024)
>>> k.n
113889577269866764888162521695342384769718705047758873186348171472787988245392312079266510368280046404688970403185126250222444669726667930171869419823867541105173455309847713448466713311624703684890592599833780693363994770448248233860935468783221802617277409592695136334705727584980167350121713870221244857169L
>>> "%x"%k.n
'a22f23e63669cb7fdcf826a247602218ce80e29a8bd88760f2eb5853c5cc0661d56d30d199ea6440d8246a366e7d89a8ddeb2f916b8a1c847b45b10fcc35597db49142ea4af837186799235d26048f342f895e9209899c75e03f458c6a1da871e30fb9e2fb62e302892b374f600a07795b7b2a9fc443781ef83662a3bd0b7b51'
>>> k.e
65537L
>>> k.d
40700791754849161549134907313832094750928205302707792070089575721564421207796105119375329040625707109636089168149272043371833874142366748440657242194406231248886791542945150873105150906215679244423936584889551021751243376000414534186522888244391573249308013493939161872118420397573215905050572428285578536753L
>>> k.p
9569823463577902979641424636117332772511826704670193825609184579118139375395989250777841602987861560675270720769540872904739257850603554926730219889720821L
>>> k.q
11900906814354804716183085274541089379162397753607283672034245115787531998779249843158689678652677244453874841842494570412291273068176083060346416454382189L
>>> k.u
6737220418398501119800713305710839047714661238527265489283474045320879746680076187723551407806712716303823549254222066539126025674709586041887580042377661L
>>> k.d
40700791754849161549134907313832094750928205302707792070089575721564421207796105119375329040625707109636089168149272043371833874142366748440657242194406231248886791542945150873105150906215679244423936584889551021751243376000414534186522888244391573249308013493939161872118420397573215905050572428285578536753L
*/
    let n = BigInt::from_bytes_be(num::bigint::Sign::Plus, &hex!("a22f23e63669cb7fdcf826a247602218ce80e29a8bd88760f2eb5853c5cc0661d56d30d199ea6440d8246a366e7d89a8ddeb2f916b8a1c847b45b10fcc35597db49142ea4af837186799235d26048f342f895e9209899c75e03f458c6a1da871e30fb9e2fb62e302892b374f600a07795b7b2a9fc443781ef83662a3bd0b7b51"));

    println!("N={:?}\ne={:?}", n, e);

    // PKCS#1 padding https://tools.ietf.org/html/rfc8017#section-7.2.1 RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)
    let k = n.bits() / 8; // bytes in modulus
    if k != 1024/8 { panic!("expected 1024-bit modulus"); }
    println!("k = {}", k);

    if message.len() > k - 11 {
        panic!("message too long");
    }
    let mut padding = vec![0; k - message.len() - 3];
    rand_bytes(&mut padding).unwrap();

    let mut encoded_m = vec![0x00, 0x02];
    encoded_m.append(&mut padding.to_vec());
    encoded_m.append(&mut vec![0x00]);
    encoded_m.extend_from_slice(&message);
    println!("encoded_m = {:?}", encoded_m);

    // TODO: ensure this is OS2IP https://tools.ietf.org/html/rfc8017#section-4.2
    let m = BigInt::from_bytes_be(num::bigint::Sign::Plus, &encoded_m);

    // TODO: PKCS#1 padding
    //
    let ciphertext_bigint = m.modpow(&e, &n);
    // TODO: convert bigint to octet string
    // 4.1. I2OSP https://tools.ietf.org/html/rfc8017#section-4.1

    println!("m = 0x{:}", m.to_str_radix(16));
    println!("ciphertext = 0x{:}", ciphertext_bigint.to_str_radix(16));

    let (_sign, ciphertext) = ciphertext_bigint.to_bytes_be();
    return ciphertext;
}

fn main() {
    /*
     $ openssl asn1parse -inform DER -in /tmp/d
    0:d=0  hl=3 l= 159 cons: SEQUENCE
    3:d=1  hl=2 l=  13 cons: SEQUENCE
    5:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   16:d=2  hl=2 l=   0 prim: NULL
   18:d=1  hl=3 l= 141 prim: BIT STRING
   */
    let packet_public_key_data = [48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129, 137, 2, 129, 129, 0, 149, 92, 126, 71, 214, 186, 100, 139, 40, 104, 65, 254, 200, 105, 71, 66, 241, 84, 172, 206, 206, 217, 49, 214, 16, 50, 6, 234, 97, 21, 170, 139, 234, 88, 220, 105, 27, 115, 56, 103, 53, 234, 84, 255, 129, 147, 41, 146, 68, 39, 120, 208, 141, 142, 39, 242, 182, 97, 4, 204, 236, 190, 104, 101, 234, 46, 71, 248, 55, 88, 213, 56, 145, 154, 142, 184, 144, 55, 105, 241, 179, 205, 174, 107, 40, 77, 46, 201, 197, 51, 20, 246, 95, 207, 227, 5, 210, 42, 107, 135, 219, 126, 207, 216, 181, 2, 130, 57, 203, 239, 232, 68, 220, 131, 211, 86, 168, 125, 193, 91, 148, 153, 109, 76, 109, 50, 2, 139, 2, 3, 1, 0, 1];


    let rsa = Rsa::public_key_from_der(&packet_public_key_data).unwrap();
    let mut shared = [0; 16];
    rand_bytes(&mut shared).unwrap();
    println!("shared = {:?}!", shared);
    //let shared = [180, 233, 250, 239, 186, 185, 101, 205, 175, 174, 26, 1, 88, 93, 213, 250];
    let packet_verify_token_data = [225, 26, 51, 196];

    let message = [1,2,3,4];
    let ciphertext = rsa_public_encrypt_pkcs1(&packet_public_key_data, &message);
    println!("ciphertext = {:?}", ciphertext);

    let mut shared_e = vec![0; rsa.size() as usize];
    let mut token_e = vec![0; rsa.size() as usize];
    rsa.public_encrypt(&shared, &mut shared_e, Padding::PKCS1).unwrap();
    rsa.public_encrypt(&packet_verify_token_data, &mut token_e, Padding::PKCS1).unwrap();

    println!("shared_e = {:?}", &shared_e);
    println!("token_e = {:?}", &token_e);
}
