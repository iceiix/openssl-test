extern crate openssl;
use openssl::rand::rand_bytes;

fn main() {
    let mut shared = [0; 16];
    rand_bytes(&mut shared).unwrap();

    println!("Hello, {:?}!", shared);
}
