use csv_keys::Mnemonic;
use csv_keys::bip44;
use csv_hash::ChainId;

fn main() {
    let mnemonic_phrase = "three fun melt jacket clump song minimum clinic scrap fiscal camera claw";
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase).unwrap();
    let seed = mnemonic.to_seed(None);
    let seed_array = *seed.as_bytes();
    
    let chain = ChainId::new("ethereum");
    let key = bip44::derive_key(&seed_array, &chain, 0, 0).unwrap();
    let address = bip44::derive_address_from_key(key.expose_secret(), &chain).unwrap();
    
    println!("Derived address: {}", address);
    println!("Private key: {}", hex::encode(key.expose_secret()));
}
