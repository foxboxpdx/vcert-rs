// Utility functions
use regex::Regex;
use rand::random;

pub fn validate_hostname(name: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = 
            Regex::new(r"^([a-zA-Z0-9\-_]+(\.)?)+$").unwrap();
    }
    RE.is_match(name)
}

pub fn generate_pass() -> String {
    (0..30).map(|_| (0x20u8 + (random::<f32>() * 96.0) as u8) as char).collect()
}

