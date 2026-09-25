//! Generates the gRPC client and server from `proto/linuxreflect.proto`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        // The CLI can then print daemon messages as JSON directly.
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["proto/linuxreflect.proto"], &["proto"])?;
    Ok(())
}
