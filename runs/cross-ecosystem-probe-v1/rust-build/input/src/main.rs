fn main() {
    let matcher = regex_alias::Regex::new("^SBOM$").unwrap();
    println!("{}", matcher.is_match("SBOM"));
}
