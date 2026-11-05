//! This tool is used to pre-package PK files given
//! a patcher dir with sd0 files, a trunk manifest file
//! and a package index.
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use argh::FromArgs;
use assembly_pack::{
    common::FileMetaPair,
    crc::{calculate_crc, CRC},
    md5::MD5Sum,
    pk::fs::{PKHandle, PKWriter},
    pki::core::PackIndexFile,
    txt::Manifest,
};
use color_eyre::eyre::{eyre, Context};
use globset::Glob;
use rayon::prelude::*;

use crate::{fsutil, ProjectArgs};

#[derive(FromArgs, PartialEq, Debug)]
/// pack files into PK archives
#[argh(subcommand, name = "pack")]
pub struct Args {
    #[argh(option, short = 'f', default = "String::from(\"**\")")]
    /// string that needs to be contained in the pack file name
    pub filter: String,
    /// rebuild packs even if their contents did not change
    #[argh(switch)]
    pub force: bool,
}

struct Writer<'a> {
    path: &'a Path,
}

impl<'a> PKWriter for Writer<'a> {
    fn write<W: std::io::Write>(&mut self, writer: &mut W) -> std::io::Result<()> {
        let file = File::open(self.path)?;
        let mut reader = BufReader::new(file);
        std::io::copy(&mut reader, writer)?;
        Ok(())
    }
}

fn win_join(base: &Path, path: &str) -> PathBuf {
    path.split('\\').fold(base.to_owned(), |mut l, r| {
        l.push(r);
        l
    })
}

/// One file to be put in a pack
struct Member {
    name: String,
    crc: CRC,
    meta: FileMetaPair,
    compressed: bool,
}

/// Identifies the exact contents of a pack. PK output is a pure function of
/// this, because members are always written in manifest order.
fn fingerprint(members: &[Member]) -> String {
    let mut text = String::with_capacity(members.len() * 96);
    for m in members {
        text.push_str(&format!("{},{},{}\n", m.crc.to_raw(), m.meta, m.compressed));
    }
    format!("{}", MD5Sum::compute(&text))
}

/// The state of a PK on disk
fn stamp(path: &Path) -> Option<(u64, u128)> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some((meta.len(), mtime.as_nanos()))
}

/// `pack path -> (fingerprint, size, mtime)` of the packs this project last built
type PackState = BTreeMap<String, (String, u64, u128)>;

fn read_state(path: &Path) -> PackState {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let mut f = line.rsplitn(4, ',');
            let mtime = f.next()?.parse().ok()?;
            let size = f.next()?.parse().ok()?;
            let fp = f.next()?.to_owned();
            Some((f.next()?.to_owned(), (fp, size, mtime)))
        })
        .collect()
}

fn build_pack(
    pk_path: &Path,
    tmp_path: &Path,
    members: &[Member],
    cache_dir: &Path,
    proj_dir: &Path,
    strip_prefix: &str,
) -> color_eyre::Result<()> {
    let _ = fs::remove_file(tmp_path);
    let mut pk = PKHandle::open(tmp_path)
        .wrap_err_with(|| format!("Failed to create {}", tmp_path.display()))?;

    for m in members {
        let source = if m.compressed {
            cache_dir.join(m.meta.to_path())
        } else {
            let relative = m
                .name
                .strip_prefix(strip_prefix)
                .ok_or_else(|| eyre!("{} does not start with {strip_prefix}", m.name))?;
            win_join(proj_dir, relative)
        };
        log::debug!("Packing '{}' from '{}'", m.name, source.display());
        let mut writer = Writer { path: &source };
        pk.put_file(m.crc, &mut writer, m.meta, m.compressed)
            .wrap_err_with(|| format!("Failed to pack '{}' from '{}'", m.name, source.display()))?;
    }
    pk.finish()
        .wrap_err_with(|| format!("Failed to finish {}", tmp_path.display()))?;
    drop(pk);

    if let Some(parent) = pk_path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("Failed to create {}", parent.display()))?;
    }
    fs::rename(tmp_path, pk_path)
        .wrap_err_with(|| format!("Failed to move {} into place", pk_path.display()))
}

/// Delete `.pk` files no longer in the PKI. They would otherwise stay in the
/// build directory and be served to every client from then on.
fn remove_stale_packs(dir: &Path, expected: &HashSet<PathBuf>) -> color_eyre::Result<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            remove_stale_packs(&path, expected)?;
        } else if path.extension().map_or(false, |e| e.eq_ignore_ascii_case("pk"))
            && !expected.contains(&path)
        {
            log::warn!("Removing stale pack {}", path.display());
            fs::remove_file(&path)
                .wrap_err_with(|| format!("Failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

pub fn run(args: ProjectArgs<Args>) -> color_eyre::Result<()> {
    let paths = args.paths();
    let output = &paths.cache_dir;

    let manifest_path = output.join(&args.project.manifest).with_extension("txt");
    log::info!("manifest: {}", manifest_path.display());
    let manifest = Manifest::from_file(&manifest_path)
        .wrap_err_with(|| format!("Failed to parse {}", manifest_path.display()))?;

    let pack_index_path = output.join(&args.project.pki).with_extension("pki");
    log::info!("pack index: {}", pack_index_path.display());
    let pack_index = PackIndexFile::from_file(&pack_index_path)
        .wrap_err_with(|| format!("Failed to load {}", pack_index_path.display()))?;
    log::info!("pack index has {} files", pack_index.files.len());

    let glob = Glob::new(&args.cmd.filter).context("failed to process filter glob")?;
    let matcher = glob.compile_matcher();

    let pack_paths = pack_index
        .archives
        .iter()
        .map(|e| {
            let relative = e.path.strip_prefix(&paths.strip_prefix).ok_or_else(|| {
                eyre!("Pack {} does not start with {}", e.path, paths.strip_prefix)
            })?;
            Ok(win_join(&paths.proj_dir, relative))
        })
        .collect::<color_eyre::Result<Vec<PathBuf>>>()?;

    // Assign the manifest's files to packs. The manifest is sorted, so this
    // order (and with it the PK) is deterministic.
    let mut groups: Vec<Vec<Member>> = pack_index.archives.iter().map(|_| Vec::new()).collect();
    let mut seen: HashMap<CRC, String> = HashMap::new();
    let mut errors = Vec::new();
    for (name, (meta, _)) in manifest.files {
        let name = name.replace('/', "\\");
        let crc = calculate_crc(name.as_bytes());
        let Some(lookup) = pack_index.files.get(&crc) else {
            continue;
        };
        if let Some(other) = seen.insert(crc, name.clone()) {
            // The client resolves files by CRC alone, so one of them can't work
            errors.push(format!("{name} and {other} have the same CRC {}", crc.to_raw()));
            continue;
        }
        groups[lookup.pack_file as usize].push(Member {
            name,
            crc,
            meta,
            compressed: lookup.category & 0xFF > 0,
        });
    }

    // A finalized manifest sorts by `/` paths and a fresh one by `\` paths, which
    // differ wherever `_` is involved. The bytes of a pack must not depend on that.
    for group in &mut groups {
        group.sort_by(|a, b| a.name.cmp(&b.name));
    }

    let missing = pack_index.files.keys().filter(|crc| !seen.contains_key(crc)).count();
    if missing > 0 {
        errors.push(format!(
            "{missing} files in the pack index are not in the manifest (run pki and cache on the same tree)"
        ));
    }
    for (i, group) in groups.iter().enumerate() {
        if group.is_empty() {
            errors.push(format!("Pack {} has no files", pack_index.archives[i].path));
        }
    }
    if !errors.is_empty() {
        for e in &errors {
            log::error!("{e}");
        }
        return Err(eyre!("{} inconsistencies between manifest and pack index", errors.len()));
    }

    let state_path = paths
        .cache_dir_parent
        .join(format!("{}.packstate.txt", args.name));
    let tmp_dir = paths.cache_dir_parent.join(format!(".{}.pack-tmp", args.name));
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).wrap_err("Failed to create pack temp dir")?;
    let state = read_state(&state_path);

    // Packs are independent, so build them concurrently. A pack whose contents
    // and file are unchanged keeps its mtime, and the following `cache` run then
    // doesn't need to hash it again.
    let results: Vec<color_eyre::Result<Option<(String, (String, u64, u128))>>> = groups
        .par_iter()
        .enumerate()
        .map(|(i, members)| {
            let name = &pack_index.archives[i].path;
            if !matcher.is_match(name) {
                return Ok(state.get(name).map(|s| (name.clone(), s.clone())));
            }
            let pk_path = &pack_paths[i];
            let fp = fingerprint(members);
            if !args.cmd.force {
                if let (Some((old_fp, size, mtime)), Some(now)) = (state.get(name), stamp(pk_path)) {
                    if *old_fp == fp && (*size, *mtime) == now {
                        log::debug!("Pack {name} is up to date");
                        return Ok(Some((name.clone(), (fp, now.0, now.1))));
                    }
                }
            }
            let tmp = tmp_dir.join(format!("{i}.pk"));
            build_pack(pk_path, &tmp, members, output, &paths.proj_dir, &paths.strip_prefix)?;
            let now = stamp(pk_path).ok_or_else(|| eyre!("{} vanished", pk_path.display()))?;
            log::info!("Built {name}: {} files, {} bytes", members.len(), now.0);
            Ok(Some((name.clone(), (fp, now.0, now.1))))
        })
        .collect();
    let _ = fs::remove_dir_all(&tmp_dir);

    let mut new_state = PackState::new();
    let mut failed = 0;
    for result in results {
        match result {
            Ok(Some((name, s))) => {
                new_state.insert(name, s);
            }
            Ok(None) => {}
            Err(e) => {
                log::error!("{e:?}");
                failed += 1;
            }
        }
    }
    if failed > 0 {
        return Err(eyre!("{failed} packs failed to build"));
    }

    if args.cmd.filter == "**" {
        let expected: HashSet<PathBuf> = pack_paths.iter().cloned().collect();
        remove_stale_packs(&paths.res_dir.join("pack"), &expected)?;
    }

    log::info!("{} packs up to date", new_state.len());
    fsutil::atomic_write(&state_path, |w| {
        for (name, (fp, size, mtime)) in &new_state {
            writeln!(w, "{name},{fp},{size},{mtime}")?;
        }
        Ok(())
    })
    .context("Failed to write pack state")?;

    Ok(())
}
