//! Declare necessary build options.  

fn main() {
    println!("cargo::rustc-link-arg-bins=-nostartfiles");
    println!("cargo::rustc-link-arg-bins=--entry=entry");
}
