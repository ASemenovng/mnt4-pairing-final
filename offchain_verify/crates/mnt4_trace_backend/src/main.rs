use mnt4_trace_backend::{build_artifact, write_artifacts, TraceRequest};
use std::{env, fs, path::PathBuf};

fn usage() -> ! {
    eprintln!(
        "Usage:\n  mnt4-trace-backend --out-dir <dir> [--request <request.json>]\n\nIf --request is omitted, the backend builds the default fixed-Q single-pair artifact."
    );
    std::process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let mut out_dir: Option<PathBuf> = None;
    let mut request_path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out-dir" => out_dir = args.next().map(PathBuf::from),
            "--request" => request_path = args.next().map(PathBuf::from),
            "--help" | "-h" => usage(),
            _ => {
                eprintln!("unknown argument: {arg}");
                usage();
            }
        }
    }
    let out_dir =
        out_dir.unwrap_or_else(|| PathBuf::from("cache/mnt4_trace_backend/default_fixed_q"));
    let request = if let Some(path) = request_path {
        let data =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str::<TraceRequest>(&data)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
    } else {
        TraceRequest {
            mode: mnt4_trace_backend::BackendMode::FixedQ,
            points: vec![],
            q: None,
            context: mnt4_trace_backend::DEFAULT_CONTEXT_HEX.to_string(),
            epoch: 1,
            nonce: 0,
            valid_until: 0,
            fixed_q_id: Some("arkworks-mnt4-753-g2-generator".to_string()),
        }
    };
    let artifact = build_artifact(&request).unwrap_or_else(|e| panic!("build artifact: {e}"));
    write_artifacts(&out_dir, &artifact).unwrap_or_else(|e| panic!("write artifacts: {e}"));
    println!("wrote {}", out_dir.display());
    println!("pairingDigest={}", artifact.pairing_digest);
    println!("millerDigest={}", artifact.miller_digest);
    println!("traceRoot={}", artifact.trace_root);
}
