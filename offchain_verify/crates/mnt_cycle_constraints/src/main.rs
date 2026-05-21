use std::{env, fs, path::PathBuf};

fn main() {
    let mut args = env::args().skip(1);
    let mut out: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            "--help" | "-h" => {
                eprintln!("Usage: mnt-cycle-constraints-report [--out <report.md>]");
                return;
            }
            _ => panic!("unknown argument: {arg}"),
        }
    }
    let report = mnt_cycle_constraints::render_markdown_report();
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create report parent");
        }
        fs::write(&path, &report).expect("write report");
        println!("wrote {}", path.display());
    } else {
        print!("{report}");
    }
}
