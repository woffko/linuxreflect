//! Generates the gRPC client and server from `proto/linuxreflect.proto`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        // The CLI can then print daemon messages as JSON directly.
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        // protoc before 3.15 (Ubuntu 22.04 ships 3.12, the release builds'
        // glibc baseline) refuses proto3 `optional` fields without this
        // flag; later versions accept it and ignore it.
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["proto/linuxreflect.proto"], &["proto"])?;
    Ok(())
}
