use argh::FromArgs;
use assembly_pack::{
    pki::{self, gen::Config, writer::write_pki_file},
    txt::gen::{push_command, Command, DirSpec},
};
use color_eyre::eyre::Context;
use indexmap::IndexMap;
use serde::Deserialize;
use std::{
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader, BufWriter},
};

use crate::ProjectArgs;

#[derive(FromArgs, PartialEq, Debug)]
/// generate a PKI file from a directory tree
#[argh(subcommand, name = "pki")]
pub struct Args {}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PackConfig {
    #[serde(default)]
    compress: bool,
    #[serde(default)]
    dirs: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    exclude_files: Vec<String>,
    #[serde(default)]
    exclude_dirs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Cfg {
    pack: IndexMap<String, PackConfig>,
}

fn hidden_glob(filename: &str) -> Option<DirSpec> {
    if let Some((l, r)) = filename.rsplit_once('\\') {
        if r.contains('*') {
            return Some(DirSpec {
                directory: l.to_string(),
                recurse_subdirectories: false,
                filter_wildcard: r.to_string(),
            });
        }
    }
    None
}

/// Parse a dir spec string in the format `directory[=recursive[=filter]]`.
///
/// Examples:
/// - `mesh\\env` → directory=mesh\env, recursive=true, no filter
/// - `mesh\\env=0=re_*` → directory=mesh\env, recursive=false, filter=re_*
/// - `brickmodels\\pettaming=1` → directory=brickmodels\pettaming, recursive=true
fn parse_dir_spec(spec: &str) -> DirSpec {
    let parts: Vec<&str> = spec.splitn(3, '=').collect();
    let directory = parts[0].to_lowercase();
    let recurse = match parts.get(1) {
        Some(r) => *r != "0",
        None => true,
    };
    let filter = parts
        .get(2)
        .map(|f| f.to_lowercase())
        .unwrap_or_default();

    DirSpec {
        directory,
        recurse_subdirectories: recurse,
        filter_wildcard: filter,
    }
}

fn process_cfg(config: &mut Config, cfg: Cfg) {
    // NOTE: locale-specific files (paths containing `_loc\<locale>\`) are
    // routed into per-locale packs by assembly-pack's pki generator itself;
    // routing them here as well produced doubled names like
    // `pack\_loc\de_de\_loc\de_de\front2_3.pk`.
    for (k, v) in cfg.pack {
        let pack_name = format!("pack\\{}.pk", k).to_lowercase();

        let cmd = Command::Pack {
            filename: pack_name,
            force_compression: v.compress,
        };
        push_command(config, cmd);

        for dir in v.dirs {
            push_command(config, Command::AddDir(parse_dir_spec(&dir)));
        }

        for dir in v.exclude_dirs {
            push_command(config, Command::RemDir(parse_dir_spec(&dir)));
        }

        for filename in v.files {
            let filename = filename.to_lowercase();
            let cmd = if let Some(dir) = hidden_glob(&filename) {
                Command::AddDir(dir)
            } else {
                Command::AddFile { filename }
            };
            push_command(config, cmd);
        }

        for filename in v.exclude_files {
            let filename = filename.to_lowercase();
            let cmd = if let Some(dir) = hidden_glob(&filename) {
                Command::RemDir(dir)
            } else {
                Command::RemFile { filename }
            };
            push_command(config, cmd);
        }

        push_command(config, Command::EndPack);
    }
}

pub fn run(args: ProjectArgs<Args>) -> color_eyre::Result<()> {
    let paths = args.paths();
    log::debug!("{:#?}", paths);

    let cfg_path = paths.proj_dir.join(&args.project.config);

    let pki_name = &args.project.pki;
    let output = paths.cache_dir.join(pki_name).with_extension("pki");

    let mf_name = &args.project.manifest;
    let manifest = paths.cache_dir.join(mf_name).with_extension("txt");

    let mut config = pki::gen::Config {
        prefix: paths.res_prefix_path(),
        directory: paths.res_dir,
        output,
        manifest,
        pack_files: vec![],
    };

    log::info!("Loading generator config from {:?}", cfg_path.display());

    if cfg_path.extension() == Some(OsStr::new("toml")) {
        let cfg_text = std::fs::read_to_string(&cfg_path)?;
        let cfg: Cfg = toml::from_str(&cfg_text)?;
        process_cfg(&mut config, cfg);
    } else {
        let cfg_file = File::open(&cfg_path).wrap_err("Failed to load generator_config file")?;
        let cfg_reader = BufReader::new(cfg_file);
        for next_line in cfg_reader.lines() {
            let line = next_line.wrap_err("failed to read config line")?;
            if let Some(cmd) = assembly_pack::txt::gen::parse_line(&line) {
                push_command(&mut config, cmd);
            }
        }
    }

    let output = config.output.clone();
    let mut pki = config.run();

    // Prune archives that own zero files in the final CRC map. Duplicate
    // dir/file claims across packs are resolved first-wins, which can leave a
    // later pack empty; the original NetDevil pki never listed such packs,
    // and the vanilla patcher errors on any pki archive missing from the
    // manifest (it is never written to disk, so it never enters trunk.txt).
    let mut file_counts = vec![0u32; pki.archives.len()];
    for file_ref in pki.files.values() {
        file_counts[file_ref.pack_file as usize] += 1;
    }
    let mut remap = vec![0u32; pki.archives.len()];
    let mut kept = Vec::with_capacity(pki.archives.len());
    for (index, archive) in pki.archives.iter().enumerate() {
        if file_counts[index] > 0 {
            remap[index] = kept.len() as u32;
            kept.push(archive.clone());
        } else {
            log::warn!("Pruning empty pack {}", archive.path);
        }
    }
    for file_ref in pki.files.values_mut() {
        file_ref.pack_file = remap[file_ref.pack_file as usize];
    }
    pki.archives = kept;

    log::info!("number of archives: {}", pki.archives.len());
    log::info!("number of files: {}", pki.files.len());
    log::info!("Writing to {}", output.display());

    let file = File::create(&output).context("Failed to create output file")?;

    let mut writer = BufWriter::new(file);
    write_pki_file(&mut writer, &pki).context("Failed to write PKI file")?;

    Ok(())
}
