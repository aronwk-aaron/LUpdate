use std::{
    collections::BTreeMap,
    io::{self, BufRead, BufReader, Write},
};

use assembly_pack::{md5::MD5Sum, txt::FileMeta};

#[derive(Clone)]
pub(super) struct QuickCheck {
    pub mtime: Option<f64>,
    pub meta: FileMeta,
}

impl QuickCheck {
    pub fn write<W: Write>(&self, path: &str, out: &mut W) -> io::Result<()> {
        out.write_all(path.as_bytes())?;
        out.write_all(b",")?;
        if let Some(mtime) = self.mtime {
            write!(out, "{}", mtime)?;
        }
        writeln!(out, ",{},{}", self.meta.size, self.meta.hash)
    }
}

fn parse_line(line: &str) -> Option<(String, QuickCheck)> {
    // From the right: a file name may contain commas
    let mut fields = line.trim_end().rsplitn(4, ',');
    let hash: MD5Sum = fields.next()?.parse().ok()?;
    let size: u32 = fields.next()?.parse().ok()?;
    let mtime: f64 = fields.next()?.parse().ok()?;
    let path = fields.next()?.to_owned();
    let meta = FileMeta { size, hash };
    let mtime = Some(mtime);
    Some((path, QuickCheck { mtime, meta }))
}

/// Read the quickcheck file. It is only an optimization, so anything malformed
/// (e.g. a crash left it truncated) only means that file gets hashed again.
pub(super) fn scan_quickcheck<R: io::Read>(reader: R) -> BTreeMap<String, QuickCheck> {
    let mut quickcheck = BTreeMap::new();
    let mut skipped = 0usize;
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else { break };
        match parse_line(&line) {
            Some((path, qc)) => {
                quickcheck.insert(path, qc);
            }
            None => skipped += 1,
        }
    }
    if skipped > 0 {
        log::warn!("Ignored {skipped} malformed quickcheck lines");
    }
    quickcheck
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn survives_garbage_and_commas() {
        let hash = "9778d5d219c5080b9a6a17bef029331c";
        let text = format!(
            "client\\a,b.txt,1.5,3,{hash}\nclient\\trunc,1.5\n,,,\nclient\\no_mtime,,3,{hash}\nclient\\c.txt,2,4,{hash}\n"
        );
        let qc = scan_quickcheck(text.as_bytes());
        assert_eq!(qc.len(), 2);
        assert_eq!(qc["client\\a,b.txt"].meta.size, 3);
        assert_eq!(qc["client\\c.txt"].mtime, Some(2.0));
    }
}
