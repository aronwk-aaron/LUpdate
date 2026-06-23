use std::{
    collections::HashSet,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use argh::FromArgs;
use assembly_pack::{
    crc::calculate_crc,
    md5::{self, MD5Sum},
    pki::parser::parse_pki_file,
    sd0::fs::Converter,
};
use color_eyre::eyre::Context;

use crate::ProjectArgs;

const CRLF: &str = "\r\n";

const DEFAULT_FRONTEND_PACK_PATTERN: &str = "front";

const EXCLUDE_PATTERNS: &[&str] = &[
    ".git",
    "generator_config.txt",
    "generator_config_ci.txt",
    "README.md",
];

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

    /// substring to match pack archive names for frontend (default: "front")
    #[argh(option, default = "DEFAULT_FRONTEND_PACK_PATTERN.to_string()")]
    frontend_pack_pattern: String,

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

/// Write a manifest file with CRLF line endings (matching LU client expectations)
fn write_manifest_crlf(
    path: &Path,
    version_num: u32,
    version_name: &str,
    lines: &[String],
) -> color_eyre::Result<()> {
    let file = File::create(path)
        .wrap_err_with(|| format!("Failed to create {}", path.display()))?;
    let mut w = BufWriter::new(file);

    let vnum_hash = MD5Sum::compute(&version_num.to_string());
    write!(w, "[version]{CRLF}")?;
    write!(w, "{},{},{}{CRLF}", version_num, vnum_hash, version_name)?;
    write!(w, "[files]")?;
    for line in lines {
        write!(w, "{CRLF}{line}")?;
    }

    Ok(())
}

fn should_exclude(line: &str) -> bool {
    EXCLUDE_PATTERNS.iter().any(|pat| line.contains(pat))
}

/// Read a manifest file, skipping the 3-line header, returning entry lines
fn read_manifest_entries(path: &Path) -> color_eyre::Result<Vec<String>> {
    let file = File::open(path)
        .wrap_err_with(|| format!("Failed to open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines_iter = reader.lines();

    // Skip header: [version], version line, [files]
    for _ in 0..3 {
        lines_iter.next();
    }

    let mut entries = Vec::new();
    for line_result in lines_iter {
        let line = line_result?;
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            entries.push(trimmed);
        }
    }

    Ok(entries)
}

/// Filter trunk.txt: normalize paths, lowercase, remove excluded entries, recalculate line hashes
fn filter_trunk(
    cache_dir: &Path,
    manifest_name: &str,
    version_num: u32,
    version_name: &str,
) -> color_eyre::Result<()> {
    let trunk_path = cache_dir.join(manifest_name).with_extension("txt");
    log::info!("Filtering {}", trunk_path.display());

    let entries = read_manifest_entries(&trunk_path)?;
    let mut filtered = Vec::new();

    for entry in entries {
        // Normalize: backslash to forward slash, lowercase
        let entry = entry.replace('\\', "/").to_lowercase();

        if should_exclude(&entry) {
            continue;
        }

        // Take first 5 fields, recalculate line hash
        let fields: Vec<&str> = entry.split(',').collect();
        if fields.len() < 5 {
            continue;
        }
        let first_five = fields[..5].join(",");
        let line_hash = MD5Sum::compute(&first_five);
        filtered.push(format!("{first_five},{line_hash}"));
    }

    log::info!("Filtered trunk: {} entries", filtered.len());
    write_manifest_crlf(&trunk_path, version_num, version_name, &filtered)?;

    Ok(())
}

/// Generate frontend.txt by including only trunk entries whose files belong to
/// pack archives matching the given pattern (e.g. "front" matches front1.pk,
/// ui1_front_1.pk, physics_front.pk, etc.)
fn generate_frontend(
    cache_dir: &Path,
    manifest_name: &str,
    pki_name: &str,
    version_num: u32,
    version_name: &str,
    pack_pattern: &str,
) -> color_eyre::Result<()> {
    let pki_path = cache_dir.join(pki_name);
    let trunk_path = cache_dir.join(manifest_name).with_extension("txt");
    let frontend_path = cache_dir.join("frontend.txt");

    log::info!("Generating {} (packs matching '{}')", frontend_path.display(), pack_pattern);

    let pki_data = fs::read(&pki_path)
        .wrap_err_with(|| format!("Failed to read PKI {}", pki_path.display()))?;
    let (_, pki) = parse_pki_file(&pki_data)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse PKI: {}", e))?;

    let front_indices: HashSet<u32> = pki
        .archives
        .iter()
        .enumerate()
        .filter(|(_, a)| a.path.to_lowercase().contains(pack_pattern))
        .map(|(i, _)| i as u32)
        .collect();

    log::info!(
        "Found {} frontend pack archives out of {}",
        front_indices.len(),
        pki.archives.len()
    );

    let front_crcs: HashSet<u32> = pki
        .files
        .iter()
        .filter(|(_, file_ref)| front_indices.contains(&file_ref.pack_file))
        .map(|(crc, _)| crc.to_raw())
        .collect();

    log::info!("Frontend packs contain {} files", front_crcs.len());

    let entries = read_manifest_entries(&trunk_path)?;
    let mut frontend_lines = Vec::new();

    for entry in &entries {
        if let Some(path) = entry.split(',').next() {
            let path_backslash = path.replace('/', "\\");
            let crc = calculate_crc(path_backslash.as_bytes()).to_raw();
            if front_crcs.contains(&crc) {
                frontend_lines.push(entry.clone());
            }
        }
    }

    log::info!("Frontend: {} of {} trunk entries", frontend_lines.len(), entries.len());
    write_manifest_crlf(&frontend_path, version_num, version_name, &frontend_lines)?;

    Ok(())
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

    let mut lines = Vec::new();

    for &file in files {
        let file_path = cache_dir.join(file);

        // Get raw hash to determine SD0 output path
        let raw_meta = md5::md5sum(&file_path)
            .wrap_err_with(|| format!("Failed to hash {}", file_path.display()))?;

        let compressed_path = cache_dir.join(hash_to_path(&raw_meta.hash));

        log::info!("Compressing {}", file_path.display());
        let conv = Converter {
            generate_segment_index: false,
            compression: Some(compression_level),
        };
        let pair = conv
            .convert_file(&file_path, &compressed_path)
            .wrap_err_with(|| format!("Failed to compress {}", file_path.display()))?;

        // Build manifest line with forward slashes
        let file_normalized = file.replace('\\', "/");
        let line_content = format!("{},{}", file_normalized, pair);
        let line_hash = MD5Sum::compute(&line_content);
        lines.push(format!("{line_content},{line_hash}"));
    }

    write_manifest_crlf(&output_path, version_num, version_name, &lines)?;
    Ok(())
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

    log::info!("[Finalize] Filtering trunk");
    filter_trunk(cache_dir, manifest_name, vnum, &vname)?;

    log::info!("[Finalize] Generating frontend");
    generate_frontend(
        cache_dir,
        manifest_name,
        &pki_name,
        vnum,
        &vname,
        &args.cmd.frontend_pack_pattern,
    )?;

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
