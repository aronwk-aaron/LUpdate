//! Crash-safe file output.
//!
//! The cache is content addressed and reused between builds, so a partially
//! written file at its final path would be trusted forever. Everything that
//! ends up in the cache is written to a temp file and renamed into place.
use std::{
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use assembly_pack::{
    common::{FileMeta, FileMetaPair},
    md5::io::IOSum,
    sd0::{fs::Converter, MAGIC},
};
use flate2::{Decompress, FlushDecompress, Status};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp path in the same directory (so that the rename is atomic).
/// The name is hidden and contains `.tmp` so deploy can exclude leftovers.
pub fn temp_path(dest: &Path) -> PathBuf {
    let name = dest.file_name().unwrap_or_default().to_string_lossy();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    dest.with_file_name(format!(".{name}.tmp{}_{n}", std::process::id()))
}

/// Remove temp files a killed process left among the sd0 objects (`x/y/.*.tmp*`)
pub fn remove_leftovers(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for a in fs::read_dir(dir)?.flatten().filter(|e| e.path().is_dir()) {
        for b in fs::read_dir(a.path())?.flatten().filter(|e| e.path().is_dir()) {
            for file in fs::read_dir(b.path())?.flatten() {
                let name = file.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.') && name.contains(".tmp") {
                    fs::remove_file(file.path())?;
                    removed += 1;
                }
            }
        }
    }
    Ok(removed)
}

/// Move a finished temp file over `dest`, removing the temp file on failure.
fn commit(tmp: &Path, dest: &Path) -> io::Result<()> {
    fs::rename(tmp, dest).map_err(|e| {
        let _ = fs::remove_file(tmp);
        e
    })
}

/// Create `dest` by writing through `f`; `dest` only changes if all of it worked.
pub fn atomic_write<T>(
    dest: &Path,
    f: impl FnOnce(&mut BufWriter<File>) -> io::Result<T>,
) -> io::Result<T> {
    let tmp = temp_path(dest);
    let result = (|| {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut w = BufWriter::new(File::create(&tmp)?);
        let value = f(&mut w)?;
        w.flush()?;
        Ok(value)
    })();
    match result {
        Ok(value) => {
            commit(&tmp, dest)?;
            Ok(value)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Compress `input` to the sd0 file at `dest`, atomically.
pub fn convert_atomic(level: u32, input: &Path, dest: &Path) -> io::Result<FileMetaPair> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = temp_path(dest);
    let conv = Converter {
        generate_segment_index: false,
        compression: Some(level),
    };
    match conv.convert_file(input, &tmp) {
        Ok(pair) => {
            commit(&tmp, dest)?;
            Ok(pair)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The most raw data one sd0 chunk may hold: the client decompresses each chunk
/// into a buffer of this size and rejects the file if it doesn't fit.
const MAX_CHUNK_RAW: usize = 0x40000;

fn corrupt(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Fully decode an sd0 file, passing the raw bytes to `sink`, and return the
/// real metadata of both its raw and compressed forms.
///
/// As strict as the client: each chunk has to be one complete zlib stream of
/// at most [`MAX_CHUNK_RAW`] bytes.
pub fn decode_sd0<W: Write>(path: &Path, sink: &mut W) -> io::Result<FileMetaPair> {
    let mut input = IOSum::new(BufReader::with_capacity(1 << 16, File::open(path)?));
    let mut output = IOSum::new(sink);

    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(corrupt(format!("bad sd0 magic {magic:?}")));
    }

    let mut chunk = Vec::new();
    let mut raw = vec![0u8; MAX_CHUNK_RAW];
    loop {
        let mut len = [0u8; 4];
        let got = input.read(&mut len[..1])?;
        if got == 0 {
            break;
        }
        input.read_exact(&mut len[1..])?;
        let len = u32::from_le_bytes(len) as usize;
        if len == 0 {
            continue;
        }

        chunk.resize(len, 0);
        input.read_exact(&mut chunk)?;

        let mut z = Decompress::new(true);
        let status = z
            .decompress(&chunk, &mut raw, FlushDecompress::Finish)
            .map_err(|e| corrupt(format!("bad zlib data: {e}")))?;
        if status != Status::StreamEnd {
            return Err(corrupt(format!(
                "chunk is truncated or decodes to more than {MAX_CHUNK_RAW} bytes"
            )));
        }
        if z.total_in() as usize != len {
            return Err(corrupt(format!("{} stray bytes in chunk", len - z.total_in() as usize)));
        }
        output.write_all(&raw[..z.total_out() as usize])?;
    }

    Ok(FileMetaPair {
        raw: FileMeta {
            size: output.byte_count() as u32,
            hash: output.digest(),
        },
        compressed: FileMeta {
            size: input.byte_count() as u32,
            hash: input.digest(),
        },
    })
}

/// [`decode_sd0`], discarding the data.
pub fn inspect_sd0(path: &Path) -> io::Result<FileMetaPair> {
    decode_sd0(path, &mut io::sink())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lupdate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sd0_roundtrip_detects_truncation() {
        let d = tmpdir("sd0");
        let input = d.join("in");
        // Spans several chunks and is poorly compressible
        let data: Vec<u8> = (0..700_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        fs::write(&input, &data).unwrap();

        let out = d.join("a/b/out.sd0");
        let pair = convert_atomic(1, &input, &out).unwrap();
        assert_eq!(inspect_sd0(&out).unwrap(), pair);
        assert_eq!(pair.raw.size as usize, data.len());

        // What an interrupted write used to leave behind
        let bytes = fs::read(&out).unwrap();
        fs::write(&out, &bytes[..bytes.len() / 2]).unwrap();
        let broken = inspect_sd0(&out);
        assert!(broken.map_or(true, |p| p.raw != pair.raw));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_atomic_write_keeps_old_content() {
        let d = tmpdir("atomic");
        let f = d.join("trunk.txt");
        fs::write(&f, "old").unwrap();
        let r: io::Result<()> = atomic_write(&f, |w| {
            w.write_all(b"partial")?;
            Err(io::Error::new(io::ErrorKind::Other, "boom"))
        });
        assert!(r.is_err());
        assert_eq!(fs::read_to_string(&f).unwrap(), "old");
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1, "temp file left behind");
        fs::remove_dir_all(&d).unwrap();
    }

    fn write_sd0(path: &Path, chunks: &[Vec<u8>]) {
        let mut out = MAGIC.to_vec();
        for chunk in chunks {
            out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        fs::write(path, out).unwrap();
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    #[test]
    fn sd0_chunk_rules_match_the_client() {
        let d = tmpdir("chunks");
        let f = d.join("x.sd0");

        // Empty file and zero-length chunks are valid
        write_sd0(&f, &[]);
        assert_eq!(inspect_sd0(&f).unwrap().raw.size, 0);
        write_sd0(&f, &[Vec::new(), zlib(b"hello")]);
        assert_eq!(inspect_sd0(&f).unwrap().raw.size, 5);

        // A full chunk is valid, one byte more would overflow the client's buffer
        write_sd0(&f, &[zlib(&vec![7u8; MAX_CHUNK_RAW])]);
        assert_eq!(inspect_sd0(&f).unwrap().raw.size as usize, MAX_CHUNK_RAW);
        write_sd0(&f, &[zlib(&vec![7u8; MAX_CHUNK_RAW + 1])]);
        assert!(inspect_sd0(&f).is_err());

        // Truncated zlib stream inside an intact chunk frame (the July bug)
        let mut cut = zlib(&(0..5000u32).map(|i| (i * 7919 >> 3) as u8).collect::<Vec<_>>());
        cut.truncate(cut.len() - 10);
        write_sd0(&f, &[cut]);
        assert!(inspect_sd0(&f).is_err());

        fs::write(&f, b"notsd0").unwrap();
        assert!(inspect_sd0(&f).is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
