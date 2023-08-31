use {flatc_rust, std::path::Path};

fn main() {
    println!("cargo:rerun-if-changed=schema");
    flatc_rust::run(flatc_rust::Args {
        inputs: &[Path::new("schema/snapshot.fbs")],
        out_dir: Path::new("target/schema/"),
        ..Default::default()
    })
    .expect("flatc");
}
