#[cfg(feature = "c_bitcoin_impl")]
fn select_c_bitcoin_impl() {
    println!("cargo:rerun-if-changed=c/bitcoin/");

    #[cfg(feature = "dynamic_bindgen")]
    {
        let out_dir_str = std::env::var_os("OUT_DIR").unwrap();
        let out_dir = std::path::Path::new(&out_dir_str);

        bindgen::Builder::default()
            .header("c/bitcoin/hash.h")
            .allowlist_function("secp256k1_sha256_initialize")
            .allowlist_function("secp256k1_sha256_write")
            .allowlist_function("secp256k1_sha256_finalize")
            .use_core()
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(out_dir.join("bindings.rs"))
            .expect("Couldn't write bindings");
    }

    cc::Build::new()
        .include("c/bitcoin")
        .flag("-DSECP256K1_INLINE=")
        .flag("-DSECP256K1_GNUC_PREREQ=")
        .file("c/bitcoin/hash_impl.c")
        .compile("libbitcoin_sha256.a");
}

#[cfg(feature = "c_mbedtls_impl")]
fn select_c_mbedtls_impl() {
    println!("cargo:rerun-if-changed=c/mbedtls/");

    #[cfg(feature = "dynamic_bindgen")]
    {
        let out_dir_str = std::env::var_os("OUT_DIR").unwrap();
        let out_dir = std::path::Path::new(&out_dir_str);

        bindgen::Builder::default()
            .header("c/mbedtls/mbedtls/sha256.h")
            .allowlist_function("mbedtls_sha256_init")
            .allowlist_function("mbedtls_sha256_starts")
            .allowlist_function("mbedtls_sha256_update")
            .allowlist_function("mbedtls_sha256_finish")
            .allowlist_function("mbedtls_sha256_free")
            .use_core()
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(out_dir.join("bindings.rs"))
            .expect("Couldn't write bindings");
    }

    cc::Build::new()
        .include("c/mbedtls")
        .file("c/mbedtls/source/sha256.c")
        .compile("libmbedtls_sha256.a");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let mut features_count = 0;

    #[cfg(feature = "rust_impl")]
    {
        features_count += 1;
    }
    #[cfg(feature = "sha2_impl")]
    {
        features_count += 1;
    }
    #[cfg(feature = "c_bitcoin_impl")]
    {
        features_count += 1;
    }
    #[cfg(feature = "c_mbedtls_impl")]
    {
        features_count += 1;
    }

    match features_count {
        0 => {
            panic!("at least one implementation should be selected");
        }
        1 => {}
        _ => {
            panic!("too many implementations ({}) was selected", features_count);
        }
    }

    #[cfg(feature = "c_bitcoin_impl")]
    select_c_bitcoin_impl();
    #[cfg(feature = "c_mbedtls_impl")]
    select_c_mbedtls_impl();
}
