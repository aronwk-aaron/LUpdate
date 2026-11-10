//! Audit a finished cache the way a client would consume it.
//!
//! Nothing here trusts the build: every chain of references is followed from
//! `version.txt` down to the bytes inside each pack. Run this before anything
//! is published, and against the published directory afterwards.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Write as _,
    fs,
    io::{Cursor, Write as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

use argh::FromArgs;
use assembly_pack::{
    common::{FileMeta, FileMetaPair},
    crc::{calculate_crc, CRC},
    md5::{self, MD5Sum},
    pk::{file::MAGIC_SEP, reader::PackFile},
    pki::core::PackIndexFile,
};
use color_eyre::eyre::{eyre, Context};
use rayon::prelude::*;

use crate::{config::ProjectConfig, fsutil, ProjectArgs};

/// Problems shown per category; the count is always complete
const SHOW: usize = 25;

// Limits of the 1.10.64 client's resource manager. A pack breaking the validity
// rules is deleted from the player's disk at startup.
/// Longest manifest line the client reads
const MAX_LINE: usize = 0x800;
/// Most entries in a valid pack
const MAX_PACK_ENTRIES: usize = 49999;
/// File offsets are 32-bit and read with ftell
const MAX_PACK_SIZE: usize = 0x7FFF_FFFF;
/// Warn well before a pack reaches the limits above, while there's time to split it
const WARN_PACK_MB: usize = 1024;
const WARN_PACK_ENTRIES: usize = 40000;
/// Below this share of live data the client rewrites the pack at startup
const MIN_PACK_LIVE_PERCENT: u64 = 70;
/// Packs too small for that rewrite to matter: a pack of one empty file is
/// 5 live bytes in a 12 byte dictionary offset, and these do exist.
const COMPACTION_IRRELEVANT: u64 = 4096;
/// The only PKI version the client accepts
const PKI_VERSION: u32 = 3;

/// What to tell people about a pack's size, if anything
fn pack_limit_notice(pack: &str, size: usize, entries: usize, warn_mb: usize) -> Option<String> {
    const GB: f64 = (1u64 << 30) as f64;
    let gb = size as f64 / GB;
    if size > MAX_PACK_SIZE || entries > MAX_PACK_ENTRIES {
        Some(format!("OVER CLIENT LIMIT: {pack} is {gb:.2} GB with {entries} files (limits: 2 GB, {MAX_PACK_ENTRIES} files)"))
    } else if size > warn_mb * 1024 * 1024 || entries > WARN_PACK_ENTRIES {
        Some(format!("Getting close to the client limit: {pack} is {gb:.2} GB with {entries} files (limits: 2 GB, {MAX_PACK_ENTRIES} files)"))
    } else {
        None
    }
}

/// What to tell people about two paths sharing a CRC that were kept out of the pack index
fn collision_notice(crc: u32, a: &str, b: &str, pki_name: &str) -> String {
    format!("CRC collision: {a} and {b} share CRC {crc}; kept out of {pki_name}, they load loose")
}

/// The `(lower, upper)` links the client needs for `n` sorted entries. Lookups
/// walk the links on disk from index `n >> 1`, so a wrong tree that stays in
/// range makes files silently go missing.
fn search_tree(n: usize) -> Vec<(i32, i32)> {
    fn build(links: &mut [(i32, i32)], b: usize, e: usize) -> i32 {
        if b >= e {
            return -1;
        }
        let middle = (b + e) >> 1;
        links[middle] = (build(links, b, middle), build(links, middle + 1, e));
        middle as i32
    }
    let mut links = vec![(-1, -1); n];
    build(&mut links, 0, n);
    links
}

/// Check the on-disk search tree over `(crc, lower, upper)`
fn tree_problem(nodes: &[(u32, i32, i32)]) -> Option<String> {
    if let Some(i) = (1..nodes.len()).find(|&i| nodes[i - 1].0 >= nodes[i].0) {
        return Some(format!("not sorted by crc at entry {i}"));
    }
    let tree = search_tree(nodes.len());
    let bad = nodes.iter().zip(&tree).position(|(n, t)| (n.1, n.2) != *t)?;
    Some(format!(
        "wrong search tree at entry {bad}: has ({}, {}), needs {:?}",
        nodes[bad].1, nodes[bad].2, tree[bad]
    ))
}

/// Check the parts of a PKI that [`PackIndexFile`] doesn't keep
fn check_pki_structure(path: &Path, report: &Report) {
    let err = |message: String| report.error("pki", format!("{}: {message}", path.display()));
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) => return err(format!("{e}")),
    };
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
    };
    let parsed = (|| {
        let version = u32_at(0)?;
        let packs = u32_at(4)? as usize;
        let mut offset = 8;
        for _ in 0..packs {
            offset += 4 + u32_at(offset)? as usize;
        }
        let count = u32_at(offset)? as usize;
        offset += 4;
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            let at = offset + i * 20;
            nodes.push((u32_at(at)?, u32_at(at + 4)? as i32, u32_at(at + 8)? as i32));
        }
        (data.len() == offset + count * 20).then_some((version, nodes))
    })();
    let Some((version, nodes)) = parsed else {
        return err("truncated or has trailing data".into());
    };
    if version != PKI_VERSION {
        err(format!("version {version}, the client only accepts {PKI_VERSION}"));
    }
    if let Some(problem) = tree_problem(&nodes) {
        err(problem);
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "verify")]
/// audit a finished cache from version.txt down to the bytes in each pack
pub struct Args {
    /// directory to audit (default: the project's cache directory)
    #[argh(option)]
    dir: Option<PathBuf>,

    /// only check that each sd0 exists with the right size, without decoding
    #[argh(switch)]
    quick: bool,

    /// version.txt to start from (default: the one in the directory). Lets a
    /// deploy audit its files before publishing them by replacing version.txt.
    #[argh(option)]
    version_file: Option<PathBuf>,

    /// warn about packs larger than this many MB (default: 1024)
    #[argh(option, default = "WARN_PACK_MB")]
    warn_pack_mb: usize,
}

#[derive(Default)]
struct Report {
    errors: Mutex<BTreeMap<&'static str, Vec<String>>>,
    /// Things worth telling people about even when the build succeeds
    notices: Mutex<Vec<String>>,
}

impl Report {
    fn error(&self, category: &'static str, message: String) {
        self.errors.lock().unwrap().entry(category).or_default().push(message);
    }
}

struct Entry {
    path: String,
    meta: FileMetaPair,
}

struct ManifestFile {
    version: u32,
    entries: Vec<Entry>,
}

fn sd0_path(dir: &Path, hash: &MD5Sum) -> PathBuf {
    let hash = format!("{hash}");
    dir.join(&hash[..1]).join(&hash[1..2]).join(format!("{hash}.sd0"))
}

/// Parse a manifest strictly, reporting everything the patcher would reject
fn parse_manifest(path: &Path, report: &Report) -> Option<ManifestFile> {
    let name = path.display().to_string();
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            report.error("manifest", format!("{name}: {e}"));
            return None;
        }
    };
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let (head, version_line, files) = (lines.next(), lines.next(), lines.next());
    if head != Some("[version]") || files != Some("[files]") {
        report.error("manifest", format!("{name}: bad section headers"));
        return None;
    }
    let mut fields = version_line.unwrap_or_default().splitn(3, ',');
    let number = fields.next().unwrap_or_default();
    let hash = fields.next().unwrap_or_default();
    let version = number.parse().ok();
    if version.is_none() || format!("{}", MD5Sum::compute(number)) != hash {
        report.error("manifest", format!("{name}: bad version line {version_line:?}"));
        return None;
    }

    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines.filter(|l| !l.is_empty()) {
        if line.len() >= MAX_LINE {
            report.error("manifest", format!("{name}: line too long for the client: {line}"));
        }
        let parts: Vec<&str> = line.rsplitn(6, ',').collect();
        let parsed = (|| {
            let [line_hash, c_hash, c_size, r_hash, r_size, path] = parts[..] else {
                return None;
            };
            let hash = |s: &str| s.parse::<MD5Sum>().ok();
            let meta = FileMetaPair::new(
                FileMeta { size: r_size.parse().ok()?, hash: hash(r_hash)? },
                FileMeta { size: c_size.parse().ok()?, hash: hash(c_hash)? },
            );
            let content = line.rsplit_once(',')?.0;
            Some((path, meta, format!("{}", MD5Sum::compute(content)) == line_hash))
        })();
        let Some((path, meta, line_ok)) = parsed else {
            report.error("manifest", format!("{name}: malformed line {line}"));
            continue;
        };
        if !line_ok {
            report.error("manifest", format!("{name}: bad line checksum for {path}"));
        }
        if path.contains('\\') || path != path.to_lowercase() {
            report.error("manifest", format!("{name}: path not normalized: {path}"));
        }
        if !seen.insert(path.to_owned()) {
            report.error("manifest", format!("{name}: duplicate entry {path}"));
        }
        entries.push(Entry { path: path.to_owned(), meta });
    }
    Some(ManifestFile { version: version?, entries })
}

/// A manifest file listed by a parent manifest has to match it, both as the raw
/// file in the directory and as its sd0.
fn check_listed(dir: &Path, entry: &Entry, report: &Report) {
    let path = dir.join(&entry.path);
    match md5::md5sum(&path) {
        Ok(meta) if meta == entry.meta.raw => {}
        Ok(meta) => report.error(
            "chain",
            format!("{} is {} but its parent lists {}", entry.path, meta.hash, entry.meta.raw.hash),
        ),
        Err(e) => report.error("chain", format!("{}: {e}", path.display())),
    }
}

fn check_sd0(dir: &Path, path: &str, meta: &FileMetaPair, quick: bool, report: &Report) {
    let sd0 = sd0_path(dir, &meta.raw.hash);
    if quick {
        match fs::metadata(&sd0) {
            Ok(m) if m.len() == u64::from(meta.compressed.size) => {}
            Ok(m) => report.error(
                "sd0",
                format!("{path}: {} is {} bytes, expected {}", sd0.display(), m.len(), meta.compressed.size),
            ),
            Err(e) => report.error("sd0", format!("{path}: {}: {e}", sd0.display())),
        }
        return;
    }
    match fsutil::inspect_sd0(&sd0) {
        Ok(real) if real == *meta => {}
        Ok(real) if real.raw == meta.raw => report.error(
            "sd0",
            format!("{path}: compressed form is {} but the manifest lists {}", real.compressed, meta.compressed),
        ),
        Ok(real) => report.error(
            "sd0",
            format!("{path}: {} decodes to {} but the manifest lists {}", sd0.display(), real.raw, meta.raw),
        ),
        Err(e) => report.error("sd0", format!("{path}: {}: {e}", sd0.display())),
    }
}

fn check_pack(
    pack_index: usize,
    pack_path: &str,
    meta: &FileMetaPair,
    dir: &Path,
    pki: &PackIndexFile,
    by_crc: &HashMap<u32, &Entry>,
    report: &Report,
    warn_pack_mb: usize,
) -> usize {
    let err = |message: String| report.error("pack", format!("{pack_path}: {message}"));
    let mut data = Vec::with_capacity(meta.raw.size as usize);
    if let Err(e) = fsutil::decode_sd0(&sd0_path(dir, &meta.raw.hash), &mut data) {
        err(format!("can't decode: {e}"));
        return 0;
    }
    let mut pk = PackFile::open(Cursor::new(&data));
    let directory = (|| {
        pk.check_magic()?;
        let trailer = pk.get_header()?;
        let directory = pk.get_entry_list(trailer.file_list_base_addr)?;
        Ok::<_, std::io::Error>((trailer, directory))
    })();
    let (trailer, directory) = match directory {
        Ok(found) => found,
        Err(e) => {
            err(format!("bad structure: {e}"));
            return 0;
        }
    };

    if let Some(notice) = pack_limit_notice(pack_path, data.len(), directory.len(), warn_pack_mb) {
        log::warn!("{notice}");
        report.notices.lock().unwrap().push(notice);
    }
    if data.len() > MAX_PACK_SIZE {
        err(format!("{} bytes is over the client's 2 GB limit", data.len()));
    }
    if directory.is_empty() || directory.len() > MAX_PACK_ENTRIES {
        err(format!(
            "{} entries is outside the client's 1..={MAX_PACK_ENTRIES}: it would delete this pack",
            directory.len()
        ));
    }
    let nodes: Vec<_> = directory.iter().map(|e| (e.crc.to_raw(), e.left, e.right)).collect();
    if let Some(problem) = tree_problem(&nodes) {
        err(problem);
    }

    let dictionary = u64::from(trailer.file_list_base_addr);
    let mut live = 0u64;
    for entry in &directory {
        let crc = entry.crc.to_raw();
        let name = by_crc.get(&crc).map_or(format!("crc {crc}"), |e| e.path.clone());
        match pki.files.get(&entry.crc) {
            Some(file) if file.pack_file as usize == pack_index => {
                let is_compressed = file.category & 0xFF > 0;
                if (entry.is_compressed & 0xFF > 0) != is_compressed {
                    err(format!("{name}: compression flag differs from the pack index"));
                }
            }
            Some(file) => err(format!("{name}: pack index says it is in archive {}", file.pack_file)),
            None => err(format!("{name}: not in the pack index")),
        }
        match by_crc.get(&crc) {
            Some(listed) if listed.meta == entry.meta => {}
            Some(_) => err(format!("{name}: differs from the manifest")),
            None => err(format!("{name}: not in the manifest")),
        }

        let is_compressed = entry.is_compressed & 0xFF > 0;
        let expected = if is_compressed { entry.meta.compressed } else { entry.meta.raw };
        live += u64::from(expected.size) + MAGIC_SEP.len() as u64;
        if u64::from(entry.file_data_addr) >= dictionary.max(1) {
            err(format!("{name}: data offset is past the dictionary"));
        }
        let start = entry.file_data_addr as usize;
        let end = start + expected.size as usize;
        match data.get(start..end) {
            Some(bytes) if MD5Sum::compute(bytes) == expected.hash => {
                if data.get(end..end + MAGIC_SEP.len()) != Some(&MAGIC_SEP[..]) {
                    err(format!("{name}: missing separator after file data"));
                }
            }
            Some(_) => err(format!("{name}: stored bytes have the wrong md5")),
            None => err(format!("{name}: stored bytes are out of bounds")),
        }
    }
    if live > dictionary {
        err(format!("{live} bytes of files don't fit before the dictionary at {dictionary}"));
    } else if dictionary > COMPACTION_IRRELEVANT && live * 100 < dictionary * MIN_PACK_LIVE_PERCENT {
        err(format!("only {live} of {dictionary} bytes are live: the client would compact it"));
    }
    directory.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_tree_matches_the_client_layout() {
        // Five entries: the root is at 5 >> 1
        assert_eq!(search_tree(5), vec![(-1, -1), (0, -1), (1, 4), (-1, -1), (3, -1)]);
        assert_eq!(search_tree(0), vec![]);
        assert_eq!(search_tree(1), vec![(-1, -1)]);
    }

    #[test]
    fn pack_limit_notices() {
        const GB: usize = 1 << 30;
        assert_eq!(pack_limit_notice("a.pk", GB, 8520, WARN_PACK_MB), None);
        assert!(pack_limit_notice("a.pk", GB + 1, 10, WARN_PACK_MB).is_some());
        let warn = pack_limit_notice("a.pk", GB + GB * 3 / 5, 10, WARN_PACK_MB).unwrap();
        assert!(warn.starts_with("Getting close") && warn.contains("a.pk"), "{warn}");
        assert!(pack_limit_notice("a.pk", 10, 40001, WARN_PACK_MB).unwrap().starts_with("Getting close"));
        assert!(pack_limit_notice("a.pk", 2 * GB, 10, WARN_PACK_MB).unwrap().starts_with("OVER"));
        assert!(pack_limit_notice("a.pk", 10, 50000, WARN_PACK_MB).unwrap().starts_with("OVER"));
        assert_eq!(pack_limit_notice("a.pk", GB, 10, 2000), None);
    }

    #[test]
    fn collision_notices() {
        // The real pairs in the live caches
        for (a, b) in [
            (
                "client/res/brickprimitives/lod2/57563.g",
                "client/res/forkp/effects/celebration/celebrationsentinelsword/celebrationsentinelsword4.psb",
            ),
            (
                "client/res/forkp/effects/racing/rgf_tiki_lap_fire/rgf_tiki_lap_fire3.psb",
                "client/res/textures/ng_ninjago/ui/inventory/models/rew_ninjagomonastery_entranceleft.dds",
            ),
        ] {
            let crc = calculate_crc(a.as_bytes()).to_raw();
            assert_eq!(crc, calculate_crc(b.as_bytes()).to_raw(), "{a} {b}");
            let notice = collision_notice(crc, a, b, "primary.pki");
            assert_eq!(
                notice,
                format!("CRC collision: {a} and {b} share CRC {crc}; kept out of primary.pki, they load loose")
            );
        }
        let crc = calculate_crc(b"client/res/brickprimitives/lod2/57563.g").to_raw();
        assert_eq!(crc, 2708661638);
    }

    #[test]
    fn tree_checks() {
        let tree = search_tree(3);
        let good: Vec<_> = tree.iter().enumerate().map(|(i, t)| (i as u32, t.0, t.1)).collect();
        assert_eq!(tree_problem(&good), None);
        let mut unsorted = good.clone();
        unsorted.swap(0, 1);
        assert!(tree_problem(&unsorted).unwrap().contains("sorted"));
        let mut bad = good;
        bad[1].1 = -1;
        assert!(tree_problem(&bad).unwrap().contains("tree"));
    }
}

pub fn run(args: ProjectArgs<Args>) -> color_eyre::Result<()> {
    let paths = args.paths();
    let dir = args.cmd.dir.clone().unwrap_or_else(|| paths.cache_dir.clone());
    let version_file = args.cmd.version_file.clone().unwrap_or_else(|| dir.join("version.txt"));
    let notices = paths.cache_dir_parent.join(format!("{}.notices.txt", args.name));
    let options = AuditOptions { quick: args.cmd.quick, warn_pack_mb: args.cmd.warn_pack_mb };
    audit(args.project, &paths.prefix, &dir, &version_file, &options, &notices)
}

struct AuditOptions {
    quick: bool,
    warn_pack_mb: usize,
}

/// Audit the cache in `dir`, starting from `version_file`
fn audit(
    project: &ProjectConfig,
    prefix: &str,
    dir: &Path,
    version_file: &Path,
    options: &AuditOptions,
    notices_file: &Path,
) -> color_eyre::Result<()> {
    let quick = options.quick;
    let report = Report::default();
    let manifest_name = project.manifest.with_extension("txt");
    let manifest_name = manifest_name.to_string_lossy();
    let pki_name = project.pki.with_extension("pki");
    let pki_name = pki_name.to_string_lossy();

    log::info!("Verifying {} ({})", dir.display(), if quick { "quick" } else { "full" });

    // version.txt -> index.txt -> manifests and pack index
    let version = parse_manifest(version_file, &report);
    let index = parse_manifest(&dir.join("index.txt"), &report);
    let trunk = parse_manifest(&dir.join(&*manifest_name), &report);
    let frontend = parse_manifest(&dir.join("frontend.txt"), &report);
    let hotfix = parse_manifest(&dir.join("hotfix.txt"), &report);

    let mut numbers = BTreeSet::new();
    for m in [&version, &index, &trunk, &frontend, &hotfix].into_iter().flatten() {
        numbers.insert(m.version);
    }
    if numbers.len() > 1 {
        report.error("chain", format!("manifests disagree on the version number: {numbers:?}"));
    }

    let mut listed: Vec<(&Entry, &str)> = Vec::new();
    if let Some(version) = &version {
        if !version.entries.iter().any(|e| e.path == "index.txt") {
            report.error("chain", "version.txt does not list index.txt".into());
        }
        listed.extend(version.entries.iter().map(|e| (e, "version.txt")));
    }
    if let Some(index) = &index {
        for required in [&*manifest_name, "frontend.txt", &*pki_name] {
            if !index.entries.iter().any(|e| e.path == required) {
                report.error("chain", format!("index.txt does not list {required}"));
            }
        }
        listed.extend(index.entries.iter().map(|e| (e, "index.txt")));
    }
    for (entry, _) in &listed {
        check_listed(dir, entry, &report);
        check_sd0(dir, &entry.path, &entry.meta, quick, &report);
    }
    if let Some(hotfix) = &hotfix {
        for entry in &hotfix.entries {
            check_sd0(dir, &entry.path, &entry.meta, quick, &report);
        }
    }

    let trunk_entries = trunk.as_ref().map_or(&[][..], |t| &t.entries[..]);

    // Each distinct object once, decoded completely
    let mut objects: HashMap<[u8; 16], &Entry> = HashMap::new();
    for e in trunk_entries {
        let first = objects.entry(e.meta.raw.hash.0).or_insert(e);
        if first.meta != e.meta {
            report.error(
                "sd0",
                format!("{} and {} have the same content but different compressed metadata", first.path, e.path),
            );
        }
    }
    objects.par_iter().for_each(|(_, e)| check_sd0(dir, &e.path, &e.meta, quick, &report));

    // The objects on disk, for leftovers. Unreferenced objects are not errors:
    // keeping them is what lets clients on the previous version finish.
    let mut referenced: BTreeSet<String> = objects.keys().map(|h| format!("{}", MD5Sum(*h))).collect();
    referenced.extend(listed.iter().map(|(e, _)| format!("{}", e.meta.raw.hash)));
    let (mut unreferenced, mut leftovers) = (0usize, Vec::new());
    for a in fs::read_dir(dir).into_iter().flatten().flatten() {
        if !a.path().is_dir() {
            continue;
        }
        for b in fs::read_dir(a.path()).into_iter().flatten().flatten() {
            for file in fs::read_dir(b.path()).into_iter().flatten().flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                match name.strip_suffix(".sd0") {
                    Some(stem) if !name.starts_with('.') => {
                        unreferenced += usize::from(!referenced.contains(stem));
                    }
                    _ => leftovers.push(file.path()),
                }
            }
        }
    }
    for path in leftovers {
        report.error("sd0", format!("unexpected file {}", path.display()));
    }

    // Pack index <-> manifest <-> pack contents
    let mut by_crc: HashMap<u32, &Entry> = HashMap::new();
    let mut colliding: Vec<(u32, String, String)> = Vec::new();
    for e in trunk_entries {
        let crc = calculate_crc(e.path.as_bytes()).to_raw();
        if let Some(other) = by_crc.insert(crc, e) {
            colliding.push((crc, other.path.clone(), e.path.clone()));
        }
    }
    let mut packed = 0;
    let pki_path = dir.join(&*pki_name);
    check_pki_structure(&pki_path, &report);
    match PackIndexFile::from_file(&pki_path) {
        Err(e) => report.error("pack", format!("{}: {e}", pki_path.display())),
        Ok(pki) => {
            // Harmless while they load as loose files; in the index they can't both work
            for (crc, a, b) in &colliding {
                if pki.files.contains_key(&CRC::from_raw(*crc)) {
                    report.error("crc", format!("{a} and {b} have the same CRC {crc} and are in the pack index"));
                } else {
                    let notice = collision_notice(*crc, a, b, &pki_name);
                    log::warn!("{notice}");
                    report.notices.lock().unwrap().push(notice);
                }
            }
            for (crc, file) in &pki.files {
                let crc = crc.to_raw();
                if file.pack_file as usize >= pki.archives.len() {
                    report.error("pack", format!("crc {crc}: archive {} does not exist", file.pack_file));
                } else if !by_crc.contains_key(&crc) {
                    report.error(
                        "pack",
                        format!("crc {crc} (in {}) is in the pack index but not in the manifest", pki.archives[file.pack_file as usize].path),
                    );
                }
            }
            let packs: Vec<(usize, &str, Option<&Entry>)> = pki
                .archives
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let listed = a.path.replace('\\', "/").to_lowercase();
                    (i, a.path.as_str(), trunk_entries.iter().find(|e| e.path == listed))
                })
                .collect();
            packed = packs
                .par_iter()
                .map(|(i, path, entry)| match entry {
                    Some(entry) if !quick => check_pack(*i, path, &entry.meta, dir, &pki, &by_crc, &report, options.warn_pack_mb),
                    Some(_) => 0,
                    None => {
                        report.error("pack", format!("{path} is in the pack index but not in the manifest"));
                        0
                    }
                })
                .sum();
            if !quick && packed != pki.files.len() {
                report.error("pack", format!("packs hold {packed} files, the pack index lists {}", pki.files.len()));
            }
        }
    }

    // frontend.txt has to be a slice of trunk.txt that can start the game
    if let Some(frontend) = &frontend {
        let trunk_map: HashMap<&str, &FileMetaPair> =
            trunk_entries.iter().map(|e| (e.path.as_str(), &e.meta)).collect();
        for e in &frontend.entries {
            match trunk_map.get(e.path.as_str()) {
                Some(meta) if **meta == e.meta => {}
                Some(_) => report.error("frontend", format!("{} differs from trunk", e.path)),
                None => report.error("frontend", format!("{} is not in trunk", e.path)),
            }
        }
        let exe = format!("{}/legouniverse.exe", prefix.replace('\\', "/").to_lowercase());
        if !frontend.entries.iter().any(|e| e.path == exe) {
            report.error("frontend", format!("does not list {exe}"));
        }
    }

    // For the pipeline to pass on; empty when there's nothing to say
    let mut notices = report.notices.into_inner().unwrap();
    notices.sort();
    fsutil::atomic_write(notices_file, |w| {
        notices.iter().try_for_each(|notice| writeln!(w, "{notice}"))
    })
    .wrap_err("Failed to write the notices file")?;

    let errors = report.errors.into_inner().unwrap();
    let total: usize = errors.values().map(Vec::len).sum();
    log::info!(
        "{} trunk entries, {} distinct objects, {} files in packs, {} frontend entries, {} unreferenced objects, {} CRC collisions",
        trunk_entries.len(),
        objects.len(),
        packed,
        frontend.as_ref().map_or(0, |f| f.entries.len()),
        unreferenced,
        colliding.len()
    );
    if total == 0 {
        log::info!("Cache OK");
        return Ok(());
    }
    let mut summary = String::new();
    for (category, messages) in &errors {
        let _ = write!(summary, " {category}={}", messages.len());
        for message in messages.iter().take(SHOW) {
            log::error!("[{category}] {message}");
        }
        if messages.len() > SHOW {
            log::error!("[{category}] ... and {} more", messages.len() - SHOW);
        }
    }
    Err(eyre!("Cache verification failed with {total} problems:{summary}"))
}
