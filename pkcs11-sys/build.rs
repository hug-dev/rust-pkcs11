use std::env;
use std::path::PathBuf;

fn main() {
    // Generate bindings.
    let bindings = bindgen::Builder::default()
        .header("pkcs11.h")
        .dynamic_library_name("Pkcs11")
        // The PKCS11 library works in a slightly different way to most shared libraries. We have
        // to call `C_GetFunctionList`, which returns a list of pointers to the _actual_ library
        // functions. This is the only function we need to create a binding for.
        .whitelist_function("C_GetFunctionList")
        // This is needed because no types will be generated if `whitelist_function` is used.
        // Unsure if this is a bug.
        .whitelist_type("*")
        // Derive the `Debug` trait for the generated structs where possible.
        .derive_debug(true)
        // Derive the `Default` trait for the generated structs where possible.
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/pkcs11_bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("pkcs11_bindings.rs"))
        .expect("Couldn't write bindings!");
}
