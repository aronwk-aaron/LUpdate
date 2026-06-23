use argh::FromArgs;
use assembly_pack::{
    pki::{self, gen::Config, writer::write_pki_file},
    txt::gen::{push_command, Command, DirSpec},
};
use color_eyre::eyre::Context;
use indexmap::IndexMap;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
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

/// Detect a locale directory pattern in a path (e.g. `_loc\en_gb`, `_loc\de_de`).
/// Returns the locale segment like `_loc\de_de` if found.
fn detect_locale(path: &str) -> Option<String> {
    let lower = path.to_lowercase();
    let idx = lower.find("_loc\\")?;
    let after = &lower[idx + 5..];
    let mut chars = after.chars();
    let c0 = chars.next().filter(|c| c.is_ascii_alphanumeric())?;
    let c1 = chars.next().filter(|c| c.is_ascii_alphanumeric())?;
    let c2 = chars.next().filter(|&c| c == '_')?;
    let c3 = chars.next().filter(|c| c.is_ascii_alphanumeric())?;
    let c4 = chars.next().filter(|c| c.is_ascii_alphanumeric())?;
    let locale: String = [c0, c1, c2, c3, c4].iter().collect();
    if !locale.is_empty() {
        Some(format!("_loc\\{}", locale))
    } else {
        None
    }
}

/// Remap a pack name to include a locale segment after the first component.
/// `pack\front2_3.pk` + `_loc\de_de` → `pack\_loc\de_de\front2_3.pk`
fn localize_pack_name(pack_name: &str, locale: &str) -> String {
    if let Some(idx) = pack_name.find('\\') {
        format!("{}\\{}\\{}", &pack_name[..idx], locale, &pack_name[idx + 1..])
    } else {
        format!("{}\\{}", locale, pack_name)
    }
}

fn process_cfg(config: &mut Config, cfg: Cfg) {
    // Collect locale-specific files to emit as separate packs at the end
    let mut locale_packs: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();

    for (k, v) in cfg.pack {
        let pack_name = format!("pack\\{}.pk", k).to_lowercase();

        let cmd = Command::Pack {
            filename: pack_name.clone(),
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
            if let Some(locale) = detect_locale(&filename) {
                // Route locale-specific files to their own pack
                let locale_pack = localize_pack_name(&pack_name, &locale);
                log::debug!("Routing {} to locale pack {}", filename, locale_pack);
                locale_packs
                    .entry(locale_pack)
                    .or_insert_with(|| (v.compress, Vec::new()))
                    .1
                    .push(filename);
            } else {
                let cmd = if let Some(dir) = hidden_glob(&filename) {
                    Command::AddDir(dir)
                } else {
                    Command::AddFile { filename }
                };
                push_command(config, cmd);
            }
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

    // Emit locale-specific packs
    for (locale_pack_name, (compress, files)) in locale_packs {
        if files.is_empty() {
            continue;
        }
        log::info!(
            "Generating locale pack {} with {} files",
            locale_pack_name,
            files.len()
        );
        push_command(
            config,
            Command::Pack {
                filename: locale_pack_name,
                force_compression: compress,
            },
        );
        for filename in files {
            push_command(config, Command::AddFile { filename });
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
    let pki = config.run();

    log::info!("number of archives: {}", pki.archives.len());
    log::info!("number of files: {}", pki.files.len());
    log::info!("Writing to {}", output.display());

    let file = File::create(&output).context("Failed to create output file")?;

    let mut writer = BufWriter::new(file);
    write_pki_file(&mut writer, &pki).context("Failed to write PKI file")?;

    Ok(())
}
