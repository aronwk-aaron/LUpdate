use argh::FromArgs;
use assembly_pack::{
    common::{
        fs::{scan_dir, FileInfo, FsVisitor},
        FileMetaPair,
    },
    md5::{self, MD5Sum},
    txt::{FileMeta, LineEnding, Manifest, VersionLine},
};
use color_eyre::eyre::{eyre, Context};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, Metadata},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::UNIX_EPOCH,
};

use crate::{config::ProjectConfig, fsutil, ProjectArgs};

use self::quickcheck::{scan_quickcheck, QuickCheck};

mod quickcheck;

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "cache")]
/// scans a file tree, generating sd0 compressed files and a manifest file
pub struct Args {
    /// version number
    #[argh(option, short = 'v', default = "1")]
    version: u32,

    /// version name
    #[argh(option, short = 'n')]
    name: Option<String>,

    /// don't ignore pk files
    #[argh(switch, short = 'i')]
    include_pk: bool,

    /// assume the filenames passed to -F / --files are already relative to `dir`
    ///
    /// i.e. don't strip the prefix (e.g. client\)
    #[argh(switch, short = 'r')]
    relative: bool,

    /// name of a file containing one path per line
    #[argh(option, short = 'F')]
    files: Option<PathBuf>,

    /// compression level 0-9 (default: 1, fastest; 9 = smallest but slowest)
    #[argh(option, short = 'c', default = "1")]
    compression: u32,

    /// number of parallel compression threads (default: all cores)
    #[argh(option, short = 'j')]
    jobs: Option<usize>,
}

fn hash_to_path(hash: &MD5Sum) -> String {
    const SEP: char = std::path::MAIN_SEPARATOR;
    let hash = format!("{:?}", hash);
    let mut chars = hash.chars();
    let c1 = chars.next().unwrap();
    let c2 = chars.next().unwrap();
    format!("{}{SEP}{}{SEP}{}.sd0", c1, c2, hash)
}

#[derive(Default, Debug)]
#[allow(dead_code)] // read through Debug
struct Stats {
    /// Files found by the scan
    total: usize,
    /// Files skipped by the include/exclude globs
    ignored: usize,
    /// Files whose md5 came from the quickcheck file (others were hashed)
    quickcheck: usize,
    /// Files whose sd0 the previous manifest already described
    unchanged: usize,
    /// Files whose sd0 was found in the cache and verified by decoding it
    cached_sd0: usize,
    /// Files needing a new sd0
    compress: usize,
    /// Distinct contents actually compressed (`compress` minus duplicates)
    compressed_unique: usize,
}

/// A file found by the scan, not yet hashed
struct ScanEntry {
    path: String,
    real: PathBuf,
    mtime: Option<f64>,
    size: Option<u64>,
}

fn mtime_of(meta: &Metadata) -> Option<f64> {
    let mtime = meta.modified().ok()?;
    Some(mtime.duration_since(UNIX_EPOCH).ok()?.as_secs_f64())
}

/// Everything that goes wrong during a scan; a file that can't be read must
/// fail the build, not silently vanish from the manifest.
#[derive(Default)]
struct Scan {
    include_glob: GlobSet,
    exclude_glob: GlobSet,
    entries: BTreeMap<String, ScanEntry>,
    errors: Vec<String>,
    ignored: usize,
}

impl Scan {
    fn add(&mut self, path: String, real: &Path, meta: Option<Metadata>) {
        if !self.include_glob.is_match(&path) || self.exclude_glob.is_match(&path) {
            self.ignored += 1;
            return;
        }
        let entry = ScanEntry {
            path: path.clone(),
            real: real.to_owned(),
            mtime: meta.as_ref().and_then(mtime_of),
            size: meta.as_ref().map(Metadata::len),
        };
        if let Some(old) = self.entries.insert(path.clone(), entry) {
            // Would otherwise be resolved by directory order
            self.errors.push(format!(
                "{path} exists twice with different case: {} and {}",
                old.real.display(),
                real.display()
            ));
        }
    }

    /// Scan the files named in a list (`-F`)
    fn scan_list<R: Read>(
        &mut self,
        list: R,
        proj_dir: &Path,
        strip_prefix: &str,
        prev: &mut BTreeMap<String, FileMetaPair>,
        quickcheck: &mut BTreeMap<String, QuickCheck>,
    ) -> color_eyre::Result<()> {
        use std::io::BufRead;
        for line in std::io::BufReader::new(list).lines() {
            let line = line?;
            let line = line.trim().replace('/', "\\");
            let Some(in_proj) = line.strip_prefix(strip_prefix) else {
                log::warn!("Missing prefix {}: {}", strip_prefix, line);
                continue;
            };
            let path = line.to_lowercase();
            let mut real = proj_dir.to_owned();
            real.extend(in_proj.split('\\'));
            match std::fs::metadata(&real) {
                Ok(meta) => self.add(path, &real, Some(meta)),
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    log::warn!("File {:?} not found!", line);
                    quickcheck.remove(&path);
                    if prev.remove(&path).is_some() {
                        log::info!("Removed {:?} from manifest", path);
                    }
                }
                Err(e) => self.errors.push(format!("{}: {e}", real.display())),
            }
        }
        Ok(())
    }
}

impl FsVisitor for Scan {
    fn visit_file<F: FileInfo>(&mut self, info: F) {
        // Normalize virtual paths to lowercase for case-insensitive consistency
        // (LU is a Windows game; all paths should be case-insensitive)
        match info.metadata() {
            Ok(meta) => self.add(info.path().to_lowercase(), info.real(), Some(meta)),
            Err(e) => self.errors.push(format!("{}: {e}", info.real().display())),
        }
    }

    fn failed_read_dir(&mut self, real: &Path, e: std::io::Error) {
        self.errors.push(format!("read_dir {}: {e}", real.display()));
    }

    fn failed_next_dir_entry(&mut self, real: &Path, e: std::io::Error) {
        self.errors.push(format!("read_dir {}: {e}", real.display()));
    }
}

/// How the sd0 for one distinct content was obtained
enum Resolved {
    Unchanged(FileMeta),
    Cached(FileMeta),
    Compressed(FileMeta),
}

impl Resolved {
    fn compressed(&self) -> FileMeta {
        match self {
            Self::Unchanged(m) | Self::Cached(m) | Self::Compressed(m) => *m,
        }
    }
}

/// Get a valid sd0 for one distinct content.
///
/// A file already at the output path is only reused after decoding it: this
/// path has no manifest vouching for it, and it may have been left by a crash
/// or by a version of this tool that wrote bad sd0 files.
fn resolve_sd0(
    raw: &FileMeta,
    input: &Path,
    output: &Path,
    known: Option<&FileMeta>,
    level: u32,
) -> Result<Resolved, String> {
    let outpath = output.join(hash_to_path(&raw.hash));
    let fail = |e: &dyn std::fmt::Display| format!("{}: {e}", input.display());

    match std::fs::metadata(&outpath) {
        Ok(on_disk) => {
            if let Some(known) = known.filter(|k| u64::from(k.size) == on_disk.len()) {
                return Ok(Resolved::Unchanged(*known));
            }
            match fsutil::inspect_sd0(&outpath) {
                Ok(pair) if pair.raw == *raw => return Ok(Resolved::Cached(pair.compressed)),
                Ok(pair) => log::warn!(
                    "Replacing bad {}: decodes to {} instead of {}",
                    outpath.display(),
                    pair.raw.hash,
                    raw.hash
                ),
                Err(e) => log::warn!("Replacing bad {}: {e}", outpath.display()),
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(fail(&e)),
    }

    let pair = fsutil::convert_atomic(level, input, &outpath).map_err(|e| fail(&e))?;
    if pair.raw != *raw {
        // Keeps a racing writer from publishing content the manifest doesn't describe
        return Err(fail(&"changed while the cache was being built"));
    }
    Ok(Resolved::Compressed(pair.compressed))
}

fn include_glob(project: &ProjectConfig) -> Result<GlobSet, globset::Error> {
    let mut builder = GlobSetBuilder::new();
    if project.include.is_empty() {
        builder.add(Glob::new("**")?);
    } else {
        for pattern in &project.include {
            builder.add(Glob::new(pattern)?);
        }
    }
    builder.build()
}

fn exclude_glob(project: &ProjectConfig) -> Result<GlobSet, globset::Error> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &project.exclude {
        builder.add(Glob::new(pattern)?);
    }
    builder.build()
}

/// Read the previous manifest, if there is one.
///
/// `finalize` rewrites the manifest with lowercase `/` paths while the scan
/// produces `\\` paths, so this has to normalize them or a finalized manifest
/// would never match anything.
fn load_prev(manifest: &Path) -> color_eyre::Result<BTreeMap<String, FileMetaPair>> {
    match std::fs::metadata(manifest) {
        Ok(m) if m.is_file() => {
            let mf = Manifest::from_file(manifest)
                .wrap_err_with(|| format!("Failed to parse {}", manifest.display()))?;
            log::info!(
                "Loaded previous manifest v{}: {} ({} files)",
                mf.version.version,
                mf.version.name,
                mf.files.len()
            );
            Ok(mf
                .files
                .into_iter()
                .map(|(k, (pair, _))| (k.replace('/', "\\"), pair))
                .collect())
        }
        _ => Ok(BTreeMap::new()),
    }
}

/// Log progress at most every 10%, keeping the build log readable
fn progress(what: &str, done: &AtomicUsize, total: usize) {
    let i = done.fetch_add(1, Ordering::Relaxed) + 1;
    if total >= 1000 && i % (total / 10) == 0 {
        log::info!("{what}: {i}/{total}");
    }
}

pub fn run(args: ProjectArgs<Args>) -> color_eyre::Result<()> {
    let compression_level = args.cmd.compression;
    if compression_level > 9 {
        return Err(eyre!("Compression level must be 0-9, got {}", compression_level));
    }

    if let Some(jobs) = args.cmd.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()
            .ok(); // ignore if already initialized
    }

    let paths = args.paths();
    let quickcheck_path = paths
        .cache_dir_parent
        .join(format!("{}.quickcheck.txt", args.name));
    let output = paths.cache_dir.clone();
    std::fs::create_dir_all(&output).wrap_err("Failed to create output dir")?;
    let leftovers = fsutil::remove_leftovers(&output).wrap_err("Failed to clean output dir")?;
    if leftovers > 0 {
        log::warn!("Removed {leftovers} temp files left by an interrupted run");
    }

    let mut quickcheck = match File::open(&quickcheck_path) {
        Ok(f) => scan_quickcheck(f),
        Err(_) => BTreeMap::new(),
    };

    let manifest_path = output.join(&args.project.manifest).with_extension("txt");
    let vnum = args.cmd.version;
    let vname = args.cmd.name.unwrap_or_else(|| vnum.to_string());
    let version = VersionLine::new(vnum, vname);
    let mut prev = load_prev(&manifest_path)?;

    log::info!(
        "Compression level: {}, threads: {}",
        compression_level,
        rayon::current_num_threads()
    );
    log::info!("Scanning {} as {}", paths.proj_dir.display(), paths.prefix);

    let mut scan = Scan {
        include_glob: include_glob(args.project)?,
        exclude_glob: exclude_glob(args.project)?,
        ..Scan::default()
    };
    let partial = args.cmd.files.is_some();
    if let Some(list) = &args.cmd.files {
        let strip = if args.cmd.relative { "" } else { paths.strip_prefix.as_str() };
        if list == Path::new("-") {
            scan.scan_list(std::io::stdin(), &paths.proj_dir, strip, &mut prev, &mut quickcheck)?;
        } else {
            let f = File::open(list)
                .wrap_err_with(|| format!("Failed to open files list: {}", list.display()))?;
            scan.scan_list(f, &paths.proj_dir, strip, &mut prev, &mut quickcheck)?;
        }
    } else {
        scan_dir(&mut scan, paths.prefix.clone(), &paths.proj_dir, true);
    }
    let Scan { entries, mut errors, ignored, .. } = scan;

    let mut stats = Stats {
        total: entries.len(),
        ignored,
        ..Stats::default()
    };

    // 1. Hash whatever the quickcheck can't vouch for
    let entries: Vec<ScanEntry> = entries.into_values().collect();
    let total = entries.len();
    let done = AtomicUsize::new(0);
    let hashed: Vec<(usize, Option<FileMeta>, bool)> = entries
        .par_iter()
        .enumerate()
        .map(|(i, e)| {
            progress("Hashed", &done, total);
            let qc = quickcheck.get(&e.path).filter(|qc| {
                e.mtime.is_some() && qc.mtime == e.mtime && e.size == Some(u64::from(qc.meta.size))
            });
            if let Some(qc) = qc {
                return (i, Some(qc.meta), true);
            }
            match md5::md5sum(&e.real) {
                Ok(meta) => (i, Some(meta), false),
                Err(err) => {
                    log::error!("Failed to hash {}: {err}", e.real.display());
                    (i, None, false)
                }
            }
        })
        .collect();

    // 2. One sd0 per distinct content: entries sharing content share an output
    // path, and a lot of game files are duplicates.
    let known: HashMap<[u8; 16], FileMeta> = prev
        .values()
        .map(|pair| (pair.raw.hash.0, pair.compressed))
        .collect();
    let mut metas: Vec<Option<FileMeta>> = vec![None; total];
    let mut unique: HashMap<[u8; 16], (FileMeta, usize)> = HashMap::new();
    for (i, meta, from_qc) in hashed {
        match meta {
            Some(meta) => {
                stats.quickcheck += usize::from(from_qc);
                metas[i] = Some(meta);
                unique.entry(meta.hash.0).or_insert((meta, i));
            }
            None => errors.push(format!("Failed to hash {}", entries[i].real.display())),
        }
    }

    let unique: Vec<(FileMeta, usize)> = unique.into_values().collect();
    log::info!("{} files, {} distinct contents", total, unique.len());
    let done = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    let resolved: HashMap<[u8; 16], Resolved> = unique
        .par_iter()
        .filter_map(|(raw, i)| {
            progress("Resolved sd0", &done, unique.len());
            let known = known.get(&raw.hash.0);
            match resolve_sd0(raw, &entries[*i].real, &output, known, compression_level) {
                Ok(r) => Some((raw.hash.0, r)),
                Err(e) => {
                    failures.lock().unwrap().push(e);
                    None
                }
            }
        })
        .collect();
    errors.extend(failures.into_inner().unwrap());

    // 3. Nothing is written unless every file is accounted for
    if !errors.is_empty() {
        errors.sort();
        for e in &errors {
            log::error!("{e}");
        }
        return Err(eyre!(
            "{} files could not be cached; keeping the previous manifest",
            errors.len()
        ));
    }

    let mut manifest = Manifest { version, files: BTreeMap::new() };
    let mut new_quickcheck = BTreeMap::new();
    for (entry, meta) in entries.iter().zip(metas) {
        let raw = meta.expect("errors were handled above");
        let result = &resolved[&raw.hash.0];
        match result {
            Resolved::Unchanged(_) => stats.unchanged += 1,
            Resolved::Cached(_) => stats.cached_sd0 += 1,
            Resolved::Compressed(_) => stats.compress += 1,
        }
        manifest.add_file(entry.path.clone(), FileMetaPair::new(raw, result.compressed()));
        let qc = QuickCheck { mtime: entry.mtime, meta: raw };
        new_quickcheck.insert(entry.path.clone(), qc);
        prev.remove(&entry.path);
    }
    stats.compressed_unique = resolved
        .values()
        .filter(|r| matches!(r, Resolved::Compressed(_)))
        .count();

    if partial {
        // A file list updates only those files
        for (path, pair) in std::mem::take(&mut prev) {
            manifest.add_file(path, pair);
        }
        for (path, qc) in quickcheck {
            new_quickcheck.entry(path).or_insert(qc);
        }
    } else {
        for path in prev.keys() {
            log::info!("File {path} was removed");
        }
    }

    log::info!("Writing manifest to {}", manifest_path.display());
    fsutil::atomic_write(&manifest_path, |w| manifest.write(w, LineEnding::Lf))
        .context("Failed to write manifest")?;
    fsutil::atomic_write(&quickcheck_path, |w| {
        new_quickcheck.iter().try_for_each(|(p, qc)| qc.write(p, w))
    })
    .context("Failed to write quickcheck file")?;

    log::info!("{:?}", stats);
    Ok(())
}
