use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use argh::FromArgs;
use assembly_pack::{
    md5::{self, MD5Sum},
    txt::{LineEnding, Manifest, VersionLine},
};
use color_eyre::eyre::Context;

use crate::{
    fsutil::{atomic_write, convert_atomic},
    ProjectArgs,
};

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "finalize")]
/// post-process cache: filter trunk, generate frontend/version manifests, copy patcher
pub struct Args {
    /// version number
    #[argh(option, short = 'v', default = "1")]
    version: u32,

    /// version name
    #[argh(option, short = 'n')]
    name: Option<String>,

    /// path to patcher directory (default: "patcher")
    #[argh(option, default = "PathBuf::from(\"patcher\")")]
    patcher: PathBuf,


    /// compression level 0-9 (default: 1, fastest; 9 = smallest but slowest)
    #[argh(option, short = 'c', default = "1")]
    compression: u32,

}

fn hash_to_path(hash: &MD5Sum) -> String {
    let hash_str = format!("{}", hash);
    let mut chars = hash_str.chars();
    let c1 = chars.next().unwrap();
    let c2 = chars.next().unwrap();
    format!("{}/{}/{}.sd0", c1, c2, hash_str)
}

fn new_manifest(version_num: u32, version_name: &str) -> Manifest {
    Manifest {
        version: VersionLine::new(version_num, version_name.to_owned()),
        files: BTreeMap::new(),
    }
}

/// Write a manifest the way the patcher expects it
fn write_manifest(path: &Path, manifest: &Manifest) -> color_eyre::Result<()> {
    atomic_write(path, |w| manifest.write(w, LineEnding::CrLf))
        .wrap_err_with(|| format!("Failed to write {}", path.display()))
}

fn read_manifest(path: &Path) -> color_eyre::Result<Manifest> {
    Manifest::from_file(path).wrap_err_with(|| format!("Failed to read {}", path.display()))
}

/// Whether a manifest path is under an excluded name at the root of the project.
///
/// This compares whole path components. Substring matching dropped real files:
/// `.git` as the regex the old script used also matches `digital_screen.psb`,
/// `agitems.scm` and `build_section_agitate.kf`.
fn should_exclude(path: &str, excluded: &[String]) -> bool {
    let relative = path.split_once('/').map_or(path, |(_, rest)| rest);
    let first = relative.split('/').next().unwrap_or_default();
    excluded.iter().any(|x| x.eq_ignore_ascii_case(first))
}

/// Filter trunk.txt: normalize paths, lowercase, remove excluded entries, recalculate line hashes
fn filter_trunk(
    cache_dir: &Path,
    manifest_name: &str,
    version_num: u32,
    version_name: &str,
    excluded: &[String],
) -> color_eyre::Result<()> {
    let trunk_path = cache_dir.join(manifest_name).with_extension("txt");
    log::info!("Filtering {}", trunk_path.display());

    let mut filtered = new_manifest(version_num, version_name);
    for (path, (meta, _)) in read_manifest(&trunk_path)?.files {
        let path = path.replace('\\', "/").to_lowercase();
        if should_exclude(&path, excluded) {
            log::info!("Excluding {path} from trunk");
            continue;
        }
        filtered.add_file(path, meta);
    }

    log::info!("Filtered trunk: {} entries", filtered.files.len());
    write_manifest(&trunk_path, &filtered)
}

/// Generate frontend.txt, the manifest of the patcher's "download during play"
/// option. It lists everything trunk.txt does, so both options install the game.
fn generate_frontend(
    cache_dir: &Path,
    manifest_name: &str,
    version_num: u32,
    version_name: &str,
) -> color_eyre::Result<()> {
    let trunk_path = cache_dir.join(manifest_name).with_extension("txt");
    let mut frontend = new_manifest(version_num, version_name);
    frontend.files = read_manifest(&trunk_path)?.files;
    log::info!("Frontend: {} entries", frontend.files.len());
    write_manifest(&cache_dir.join("frontend.txt"), &frontend)
}

/// Copy patcher.ini to cache dir
fn copy_patcher(patcher_dir: &Path, cache_dir: &Path) -> color_eyre::Result<()> {
    let src = patcher_dir.join("patcher.ini");
    let dst = cache_dir.join("patcher.ini");
    log::info!("Copying {} to {}", src.display(), dst.display());
    fs::copy(&src, &dst)
        .wrap_err_with(|| format!("Failed to copy {} to {}", src.display(), dst.display()))?;
    Ok(())
}

/// Hash and compress specific files, writing a version manifest
fn make_version(
    cache_dir: &Path,
    filename: &str,
    version_num: u32,
    version_name: &str,
    files: &[&str],
    compression_level: u32,
) -> color_eyre::Result<()> {
    let output_path = cache_dir.join(filename);
    log::info!("Generating {}", output_path.display());

    let mut manifest = new_manifest(version_num, version_name);

    for &file in files {
        let file_path = cache_dir.join(file);

        // Get raw hash to determine SD0 output path
        let raw_meta = md5::md5sum(&file_path)
            .wrap_err_with(|| format!("Failed to hash {}", file_path.display()))?;

        let compressed_path = cache_dir.join(hash_to_path(&raw_meta.hash));

        log::info!("Compressing {}", file_path.display());
        let pair = convert_atomic(compression_level, &file_path, &compressed_path)
            .wrap_err_with(|| format!("Failed to compress {}", file_path.display()))?;

        manifest.add_file(file.replace('\\', "/"), pair);
    }

    write_manifest(&output_path, &manifest)
}

pub fn run(args: ProjectArgs<Args>) -> color_eyre::Result<()> {
    let paths = args.paths();
    let cache_dir = &paths.cache_dir;
    let manifest_name = args.project.manifest.to_str().unwrap_or("trunk");

    let vnum = args.cmd.version;
    let vname = args.cmd.name.unwrap_or_else(|| vnum.to_string());

    let pki_name = format!(
        "{}.pki",
        args.project.pki.to_str().unwrap_or("primary")
    );

    let compression_level = args.cmd.compression;
    if compression_level > 9 {
        return Err(color_eyre::eyre::eyre!(
            "Compression level must be 0-9, got {compression_level}"
        ));
    }

    log::info!("[Finalize] Filtering trunk");
    filter_trunk(cache_dir, manifest_name, vnum, &vname, &args.general.exclude_root)?;

    log::info!("[Finalize] Generating frontend");
    generate_frontend(cache_dir, manifest_name, vnum, &vname)?;

    log::info!("[Finalize] Copying patcher.ini");
    copy_patcher(&args.cmd.patcher, cache_dir)?;

    log::info!("[Finalize] Generating hotfix.txt");
    make_version(cache_dir, "hotfix.txt", vnum, &vname, &[], compression_level)?;

    log::info!("[Finalize] Generating index.txt");
    make_version(
        cache_dir,
        "index.txt",
        vnum,
        &vname,
        &["frontend.txt", &pki_name, &format!("{manifest_name}.txt")],
        compression_level,
    )?;

    log::info!("[Finalize] Generating version.txt");
    make_version(cache_dir, "version.txt", vnum, &vname, &["index.txt"], compression_level)?;

    log::info!("[Finalize] Done");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusion_only_matches_configured_root_names() {
        let excluded: Vec<String> = [".github", ".gitignore", "generator_config.txt", "README.md"]
            .map(String::from)
            .to_vec();
        for clutter in [
            "client/.github/workflows/build-cache.yml",
            "client/generator_config.txt",
            "client/readme.md",
            "client/.gitignore",
        ] {
            assert!(should_exclude(clutter, &excluded), "{clutter}");
        }
        for content in [
            "client/res/forkp/effects/environment/digital_screen/digital_screen.psb",
            "client/res/macros/agitems.scm",
            "client/res/animations/objects/build_section_agitate.kf",
            "client/res/somewhere/readme.md",
            "client/res/generator_config.txt",
        ] {
            assert!(!should_exclude(content, &excluded), "{content}");
        }
        assert!(!should_exclude("client/readme.md", &[]));
    }
}
