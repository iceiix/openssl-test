extern crate openssl;
use openssl::rand::rand_bytes;
use openssl::rsa::{Rsa, Padding};

extern crate num;

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
    /*
    let mut shared = [0; 16];
    rand_bytes(&mut shared).unwrap();
    println!("shared = {:?}!", shared);
    */
    let shared = [180, 233, 250, 239, 186, 185, 101, 205, 175, 174, 26, 1, 88, 93, 213, 250];
    let packet_verify_token_data = [225, 26, 51, 196];

    let mut shared_e = vec![0; rsa.size() as usize];
    let mut token_e = vec![0; rsa.size() as usize];
    rsa.public_encrypt(&shared, &mut shared_e, Padding::PKCS1).unwrap();
    rsa.public_encrypt(&packet_verify_token_data, &mut token_e, Padding::PKCS1).unwrap();

    println!("shared_e = {:?}", &shared_e);
    println!("token_e = {:?}", &token_e);
}
