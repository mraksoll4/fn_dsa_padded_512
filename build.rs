fn main() {
    // Source directories
    let common_dir = "src/common";
    let fndsapadded512_dir = "src/fndsapadded512";
    
    // C source files from common directory
    let common_files = [
        "src/common/fips202.c",
        "src/common/randombytes.c", 
        "src/common/memory_cleanse.c",
    ];
    
    // C source files from fndsapadded512 directory
    let fndsapadded512_files = [
        "src/fndsapadded512/codec.c",
        "src/fndsapadded512/common.c", 
        "src/fndsapadded512/fft.c",
        "src/fndsapadded512/fpr.c",
        "src/fndsapadded512/keygen.c",
        "src/fndsapadded512/pqclean.c",
        "src/fndsapadded512/rng.c",
        "src/fndsapadded512/sign.c",
        "src/fndsapadded512/vrfy.c",		
    ];

    // Combine all files
    let mut all_files = Vec::new();
    all_files.extend_from_slice(&common_files);
    all_files.extend_from_slice(&fndsapadded512_files);

    // Build C library
    cc::Build::new()
        .files(&all_files)
        .include(common_dir)
        .include(fndsapadded512_dir)
        .flag("-O3")
        .flag("-std=c99")
        .compile("fn-dsa-padded-512-clean");

    // Tell cargo to link the library
    println!("cargo:rustc-link-lib=static=fn-dsa-padded-512-clean");

    // Tell cargo to rerun build script if C files change
    for file in &all_files {
        println!("cargo:rerun-if-changed={}", file);
    }
    
    // Watch header files too
    println!("cargo:rerun-if-changed=src/common");
    println!("cargo:rerun-if-changed=src/fndsapadded512");
}