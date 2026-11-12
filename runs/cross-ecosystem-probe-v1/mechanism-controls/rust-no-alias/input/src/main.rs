fn main() {
    let matcher = regex::Regex::new("^SBOM$").unwrap();
    println!("{}", matcher.is_match("SBOM"));
}
