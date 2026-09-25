//! Compiles the Slint UI (spec §K S15).

fn main() {
    slint_build::compile("ui/main.slint").expect("compiling the Slint UI");
    println!("cargo:rerun-if-changed=ui/main.slint");
}
