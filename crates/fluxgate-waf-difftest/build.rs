//! Compile the vendored libinjection SQLi engine (single translation unit) as a
//! static lib for the differential test to link against. No autotools — just `cc`.

fn main() {
    cc::Build::new()
        .file("vendor/libinjection/libinjection_sqli.c")
        .file("vendor/libinjection/libinjection_xss.c")
        .file("vendor/libinjection/libinjection_html5.c")
        .include("vendor/libinjection")
        .warnings(false)
        .compile("libinjection_oracle");
    println!("cargo:rerun-if-changed=vendor/libinjection/libinjection_sqli.c");
    println!("cargo:rerun-if-changed=vendor/libinjection/libinjection_sqli_data.h");
    println!("cargo:rerun-if-changed=vendor/libinjection/libinjection_xss.c");
    println!("cargo:rerun-if-changed=vendor/libinjection/libinjection_xss.h");
    println!("cargo:rerun-if-changed=vendor/libinjection/libinjection_html5.c");
    println!("cargo:rerun-if-changed=vendor/libinjection/libinjection_html5.h");
}
