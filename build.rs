//! Embed the exact source revision of this binary and of assembly-pack, so every
//! pipeline log says which code produced a cache (the binary is committed to
//! wonderland-automation and is otherwise untraceable).
use std::process::Command;

fn describe(dir: &str) -> String {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).current_dir(dir).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let sha = git(&["rev-parse", "--short=10", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&["status", "--porcelain", "--", "."]).map_or(false, |s| !s.is_empty());
    format!("{sha}{}", if dirty { "-dirty" } else { "" })
}

fn main() {
    println!("cargo:rerun-if-changed=src");
    // logs/HEAD changes on every commit and checkout; HEAD itself only on checkout
    println!("cargo:rerun-if-changed=.git/logs/HEAD");
    println!("cargo:rerun-if-changed=../Assembly/.git/logs/HEAD");
    println!("cargo:rerun-if-changed=../Assembly/modules/pack/src");
    println!("cargo:rustc-env=LUPDATE_GIT={}", describe("."));
    println!("cargo:rustc-env=ASSEMBLY_GIT={}", describe("../Assembly"));
}
