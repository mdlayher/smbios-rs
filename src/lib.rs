//! Provides detection and access to System Management BIOS (SMBIOS) and
//! Desktop Management Interface (DMI) data and structures.

extern crate bytes;

use bytes::Buf;
use std::error;
use std::fmt;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::path;
use std::result;

/// Specifies the different classes of errors which may occur.
#[derive(Debug)]
pub enum Error {
    /// Indicates an error occurred while performing file I/O.
    Io(io::Error),

    /// Indicates an error produced by this library.
    Internal(ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Internal(ref err) => write!(f, "internal SMBIOS error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::Internal(ref err) => Some(err),
        }
    }
}

/// Specifies certain internal error conditions which may occur when dealing
/// with SMBIOS data.
#[derive(Debug)]
pub enum ErrorKind {
    /// No SMBIOS entry point was detected.
    EntryPointNotFound,

    /// An SMBIOS entry point was detected, but it could not be successfully
    /// parsed.
    InvalidEntryPoint,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ErrorKind::EntryPointNotFound => write!(f, "entry point not found"),
            ErrorKind::InvalidEntryPoint => write!(f, "invalid entry point"),
        }
    }
}

impl error::Error for ErrorKind {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

/// A Result type specialized use with for an Error.
pub type Result<T> = result::Result<T, Error>;

/// Provides access to common information for SMBIOS entry points, including the
/// SMBIOS version in use and the location and size of the SMBIOS table in
/// system memory.
pub trait EntryPoint {
    /// Provides the address of the SMBIOS table in system memory and its size
    /// in bytes.
    fn table(&self) -> (usize, usize);

    /// Provides the major, minor, and revision numbers for SMBIOS on this
    /// system.
    fn version(&self) -> (usize, usize, usize);
}

/// Decodes an SMBIOS data stream from an input Read trait object.
pub struct Decoder<T: Read> {
    stream: io::BufReader<T>,
}

impl<T: Read> Decoder<T> {
    /// Creates a new Decoder by accepting an input stream with the Read trait.
    pub fn new(stream: T) -> Self {
        Decoder {
            stream: io::BufReader::new(stream),
        }
    }

    /// Decodes a vector of SMBIOS structures from the Decoder's stream.
    pub fn decode(&mut self) -> Result<Vec<Structure>> {
        let mut structures = Vec::new();

        // Header always occupies 4 bytes.
        let mut header_buf = [0; 4];
        loop {
            self.stream.read_exact(&mut header_buf).map_err(Error::Io)?;
            let header = parse_header(header_buf);

            // Formatted section is indicated length minus size of the header.
            let mut formatted = vec![0; header.length as usize - 4];
            self.stream.read_exact(&mut formatted).map_err(Error::Io)?;

            let strings = self.parse_strings()?;

            let header_type = header.header_type;

            structures.push(Structure {
                header,
                formatted,
                strings,
            });

            // Indicates end-of-structures in SMBIOS table.
            if header_type == 127 {
                return Ok(structures);
            }
        }
    }

    fn parse_strings(&mut self) -> Result<Vec<String>> {
        let mut strings = Vec::new();

        // It is possible for no strings to be presented; if so, two null bytes
        // will occur immediately and we return an empty vector.
        let mut prefix_buf = [0; 2];
        self.stream.read_exact(&mut prefix_buf).map_err(Error::Io)?;

        if prefix_buf == [0, 0] {
            return Ok(strings);
        }

        // Otherwise, keep looping and reading strings until we encounter two null bytes,
        // indicating end of strings.
        let mut upper = 2;
        loop {
            let string = self.parse_string(&mut prefix_buf[0..upper])?;
            strings.push(string);

            // From now on, we'll only use 1 byte of the prefix buffer.
            upper = 1;
            self.stream
                .read_exact(&mut prefix_buf[0..upper])
                .map_err(Error::Io)?;

            // If we read a second null byte after parsing a string, end of
            // strings section.
            if prefix_buf[0] == 0 {
                return Ok(strings);
            }
        }
    }

    fn parse_string(&mut self, prefix: &mut [u8]) -> Result<String> {
        // Each string is terminated with a null byte.
        let mut buf = Vec::new();
        self.stream.read_until(0, &mut buf).map_err(Error::Io)?;

        // Remove the null byte from the string so it isn't parsed later.
        let i = buf.len() - 1;
        buf.remove(i);

        // Take the prefix buffer and append the string's bytes to get the
        // completed string.
        let mut string_vec = prefix.to_vec();
        string_vec.append(&mut buf);

        Ok(String::from_utf8_lossy(&string_vec).to_string())
    }
}

// Predetermined locations where SMBIOS information can be found.
const DEV_MEM: &str = "/dev/mem";
const LINUX_SYSFS_DMI: &str = "/sys/firmware/dmi/tables/DMI";
const LINUX_SYSFS_ENTRY_POINT: &str = "/sys/firmware/dmi/tables/smbios_entry_point";

/// Detects the entry point and location of an SMBIOS stream on this system,
/// returning the entry point found and all available SMBIOS structures.
// TODO(mdlayher): is this signature idiomatic?  Should this function just
// decode the stream instead?
pub fn stream() -> Result<(EntryPointType, Vec<Structure>)> {
    // Try the standard Linux sysfs location.
    // TODO(mdlayher): figure out cross-platform support.
    if !path::Path::new(LINUX_SYSFS_ENTRY_POINT).exists() {
        // Fall back to UNIX /dev/mem if possible.
        if !path::Path::new(DEV_MEM).exists() {
            // Nothing to do.
            return Err(Error::Internal(ErrorKind::EntryPointNotFound));
        }

        return dev_mem_stream();
    }

    let entry_point = fs::File::open(LINUX_SYSFS_ENTRY_POINT).map_err(Error::Io)?;
    let dmi = fs::File::open(LINUX_SYSFS_DMI).map_err(Error::Io)?;

    let structures = Decoder::new(dmi).decode()?;

    Ok((parse_entry_point(entry_point)?, structures))
}

fn dev_mem_stream() -> Result<(EntryPointType, Vec<Structure>)> {
    let mut mem = fs::File::open(DEV_MEM).map_err(Error::Io)?;

    // Begin searching for the entry point at the location specified in the
    // SMBIOS specification.
    mem.seek(io::SeekFrom::Start(START_ADDRESS))
        .map_err(Error::Io)?;

    let address = find_entry_point(&mem)?;

    // Seek to where the entry point is.
    mem.seek(io::SeekFrom::Start(address)).map_err(Error::Io)?;

    // Discover the SMBIOS table location.
    let entry_point = parse_entry_point(&mem)?;

    let (table_address, table_size) = match &entry_point {
        EntryPointType::Bits32(ep) => ep.table(),
        EntryPointType::Bits64(ep) => ep.table(),
        _ => {
            return Err(Error::Internal(ErrorKind::InvalidEntryPoint));
        }
    };

    // Seek to the start of the SMBIOS stream and decode it.
    mem.seek(io::SeekFrom::Start(table_address as u64))
        .map_err(Error::Io)?;

    let structures = Decoder::new(mem.take(table_size as u64)).decode()?;

    Ok((entry_point, structures))
}

const START_ADDRESS: u64 = 0x000f_0000;
const PARAGRAPH_SIZE: u64 = 16;

fn find_entry_point<T: Read>(mut mem: T) -> Result<u64> {
    let mut buf = [0; PARAGRAPH_SIZE as usize];

    let start = START_ADDRESS;
    let end = 0x000f_ffff;

    let mut addr = start;
    loop {
        if addr >= end {
            break;
        }

        mem.read_exact(&mut buf).map_err(Error::Io)?;

        if let [b'_', b'S', b'M'] = buf[0..3] {
            return Ok(addr);
        }

        addr += PARAGRAPH_SIZE;
    }

    Err(Error::Internal(ErrorKind::EntryPointNotFound))
}

/// Indicates the type of data contained within an SMBIOS structure.
#[derive(Debug, PartialEq)]
pub struct Header {
    pub header_type: u8,
    pub length: u8,
    pub handle: u16,
}

fn parse_header(buf: [u8; 4]) -> Header {
    let mut cursor = io::Cursor::new(buf);
    Header {
        header_type: cursor.get_u8(),
        length: cursor.get_u8(),
        handle: cursor.get_u16_le(),
    }
}

/// Contains a single SMBIOS structure which can be interpreted using the SMBIOS
/// specification.
#[derive(Debug, PartialEq)]
pub struct Structure {
    pub header: Header,
    pub formatted: Vec<u8>,
    pub strings: Vec<String>,
}

fn parse_entry_point<T: Read>(mut stream: T) -> Result<EntryPointType> {
    // The entry point should be smaller than 64 bytes.
    let mut buf = [0; 64];
    let n = stream.read(&mut buf).map_err(Error::Io)?;

    Ok(match buf[0..5] {
        // 32-bit entry point.
        [b'_', b'S', b'M', b'_', _] => EntryPointType::Bits32(parse_32bit(&buf[0..n])?),
        // 64-bit entry point.
        [b'_', b'S', b'M', b'3', b'_'] => EntryPointType::Bits64(parse_64bit(&buf[0..n])?),
        _ => EntryPointType::Unknown,
    })
}

/// Possible entry point types and their contained structures.
#[derive(Debug)]
pub enum EntryPointType {
    /// An unknown entry point.  Returned when no valid entry point is
    /// recognized by this library.
    Unknown,

    /// A 32-bit entry point.
    Bits32(Bits32),

    /// A 64-bit entry point.
    Bits64(Bits64),
}

impl EntryPoint for Bits32 {
    fn table(&self) -> (usize, usize) {
        (
            self.structure_table_address as usize,
            self.structure_table_length as usize,
        )
    }

    fn version(&self) -> (usize, usize, usize) {
        (self.major as usize, self.minor as usize, 0)
    }
}

/// Contains the information found in a 32-bit SMBIOS entry point.
#[derive(Debug, PartialEq)]
pub struct Bits32 {
    pub checksum: u8,
    pub length: u8,
    pub major: u8,
    pub minor: u8,
    pub max_structure_size: u16,
    pub entry_point_revision: u8,
    pub formatted_area: [u8; 5],
    pub intermediate_checksum: u8,
    pub structure_table_length: u16,
    pub structure_table_address: u32,
    pub number_structures: u16,
    pub bcd_revision: u8,
}

fn parse_32bit(buf: &[u8]) -> Result<Bits32> {
    // Could potentially contain more data if we're reading from /dev/mem.
    if buf.len() < 31 {
        return Err(Error::Internal(ErrorKind::InvalidEntryPoint));
    }

    let mut cursor = io::Cursor::new(buf);

    // Skip the anchor string.
    cursor.set_position(4);

    let checksum = cursor.get_u8();
    let length = cursor.get_u8();
    let major = cursor.get_u8();
    let minor = cursor.get_u8();
    let max_structure_size = cursor.get_u16_le();
    let entry_point_revision = cursor.get_u8();

    let mut formatted_area = [0; 5];
    cursor.read_exact(&mut formatted_area).map_err(Error::Io)?;

    // Skip the intermediate anchor string.
    cursor.set_position(21);

    let intermediate_checksum = cursor.get_u8();
    let structure_table_length = cursor.get_u16_le();
    let structure_table_address = cursor.get_u32_le();
    let number_structures = cursor.get_u16_le();
    let bcd_revision = cursor.get_u8();

    Ok(Bits32 {
        checksum,
        length,
        major,
        minor,
        max_structure_size,
        entry_point_revision,
        formatted_area,
        intermediate_checksum,
        structure_table_length,
        structure_table_address,
        number_structures,
        bcd_revision,
    })
}

impl EntryPoint for Bits64 {
    fn table(&self) -> (usize, usize) {
        (
            self.structure_table_address as usize,
            self.structure_table_max_size as usize,
        )
    }

    fn version(&self) -> (usize, usize, usize) {
        (
            self.major as usize,
            self.minor as usize,
            self.revision as usize,
        )
    }
}

/// Contains the information found in a 64-bit SMBIOS entry point.
#[derive(Debug, PartialEq)]
pub struct Bits64 {
    pub checksum: u8,
    pub length: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
    pub entry_point_revision: u8,
    pub reserved: u8,
    pub structure_table_max_size: u32,
    pub structure_table_address: u64,
}

fn parse_64bit(buf: &[u8]) -> Result<Bits64> {
    // Could potentially contain more data if we're reading from /dev/mem.
    if buf.len() < 24 {
        return Err(Error::Internal(ErrorKind::InvalidEntryPoint));
    }

    let mut cursor = io::Cursor::new(buf);

    // Skip the anchor string.
    cursor.set_position(5);

    Ok(Bits64 {
        checksum: cursor.get_u8(),
        length: cursor.get_u8(),
        major: cursor.get_u8(),
        minor: cursor.get_u8(),
        revision: cursor.get_u8(),
        entry_point_revision: cursor.get_u8(),
        reserved: cursor.get_u8(),
        structure_table_max_size: cursor.get_u32_le(),
        structure_table_address: cursor.get_u64_le(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_point_32bit_ok() {
        #[rustfmt::skip]
        let cursor = io::Cursor::new(vec![
            b'_', b'S', b'M', b'_',
            0xa4,
            0x1f,
            0x2,
            0x8,
            0xd4,
            0x1, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0,
            b'_', b'D', b'M', b'I', b'_',
            0x95,
            0x5f, 0xf,
            0x0, 0x90, 0xf0, 0x7a,
            0x43, 0x0,
            0x28,
        ]);

        let entry_point = parse_entry_point(cursor).expect("expected valid 32-bit entry point");

        match entry_point {
            EntryPointType::Bits32(got) => {
                let want = Bits32 {
                    checksum: 164,
                    length: 31,
                    major: 2,
                    minor: 8,
                    max_structure_size: 468,
                    entry_point_revision: 0,
                    formatted_area: [0, 0, 0, 0, 0],
                    intermediate_checksum: 149,
                    structure_table_length: 3935,
                    structure_table_address: 2_062_585_856,
                    number_structures: 67,
                    bcd_revision: 40,
                };

                assert_eq!(want, got);
                assert_eq!((2, 8, 0), got.version());
                assert_eq!((2_062_585_856, 3935), got.table());
            }
            _ => panic!("invalid entry point type"),
        }
    }

    #[test]
    fn entry_point_32bit_bad() {
        let cursor = io::Cursor::new(vec![b'_', b'S', b'M', b'_', 0xff]);

        let _ = parse_entry_point(cursor).expect_err("expected invalid 32-bit entry point");
    }

    #[test]
    fn entry_point_64bit_ok() {
        let cursor = io::Cursor::new(vec![
            b'_', b'S', b'M', b'3', b'_', 0x86, 0x18, 0x3, 0x0, 0x0, 0x1, 0x0, 0x53, 0x9, 0x0, 0x0,
            0xb0, 0xb3, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]);

        let entry_point = parse_entry_point(cursor).expect("expected valid 64-bit entry point");

        match entry_point {
            EntryPointType::Bits64(got) => {
                let want = Bits64 {
                    checksum: 134,
                    length: 24,
                    major: 3,
                    minor: 0,
                    revision: 0,
                    entry_point_revision: 1,
                    reserved: 0,
                    structure_table_max_size: 2387,
                    structure_table_address: 963_504,
                };

                assert_eq!(want, got);
                assert_eq!((3, 0, 0), got.version());
                assert_eq!((963_504, 2387), got.table());
            }
            _ => panic!("invalid entry point type"),
        }
    }

    #[test]
    fn entry_point_64bit_bad() {
        let cursor = io::Cursor::new(vec![b'_', b'S', b'M', b'3', b'_', 0xff]);

        let _ = parse_entry_point(cursor).expect_err("expected invalid 64-bit entry point");
    }

    #[test]
    fn decode_structure_header_only_ok() {
        let got = unwrap_structure(&[127, 0x04, 0x01, 0x00, 0x00, 0x00]);

        let want = Structure {
            header: Header {
                header_type: 127,
                length: 4,
                handle: 1,
            },
            formatted: vec![],
            strings: vec![],
        };

        assert_eq!(want, got);
    }

    #[test]
    fn decode_structure_no_strings_ok() {
        let got = unwrap_structure(&[127, 0x06, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00]);

        let want = Structure {
            header: Header {
                header_type: 127,
                length: 6,
                handle: 1,
            },
            formatted: vec![1, 2],
            strings: vec![],
        };

        assert_eq!(want, got);
    }

    #[test]
    fn decode_structure_all_ok() {
        let got = unwrap_structure(&[
            127, 0x06, 0x01, 0x00, 0x01, 0x02, b'a', b'b', b'c', b'd', 0x00, b'1', b'2', b'3',
            b'4', 0x00, 0x00,
        ]);

        let want = Structure {
            header: Header {
                header_type: 127,
                length: 6,
                handle: 1,
            },
            formatted: vec![1, 2],
            strings: vec!["abcd".to_string(), "1234".to_string()],
        };

        assert_eq!(want, got);
    }

    #[test]
    fn decode_structure_multiple_ok() {
        // Thanks, reddit user coder543!
        // https://old.reddit.com/r/rust/comments/9jhbtw/rustfmts_handling_of_long_vec_literals/e6rh1uo/
        #[rustfmt::skip]
        let got = unwrap_structures(&[
            0x00, 0x05, 0x01, 0x00,
            0xff,
            0x00,
            0x00,

            0x01, 0x0c, 0x02, 0x00,
            0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
            b'd', b'e', b'a', b'd', b'b', b'e', b'e', b'f', 0x00,
            0x00,

            127, 0x06, 0x03, 0x00,
            0x01, 0x02,
            b'a', b'b', b'c', b'd', 0x00,
            b'1', b'2', b'3', b'4', 0x00,
            0x00,
        ]);

        let want = vec![
            Structure {
                header: Header {
                    header_type: 0,
                    length: 5,
                    handle: 1,
                },
                formatted: vec![255],
                strings: vec![],
            },
            Structure {
                header: Header {
                    header_type: 1,
                    length: 12,
                    handle: 2,
                },
                formatted: vec![222, 173, 190, 239, 222, 173, 190, 239],
                strings: vec!["deadbeef".to_string()],
            },
            Structure {
                header: Header {
                    header_type: 127,
                    length: 6,
                    handle: 3,
                },
                formatted: vec![1, 2],
                strings: vec!["abcd".to_string(), "1234".to_string()],
            },
        ];

        assert_eq!(want, got);
    }

    #[test]
    fn find_entry_point_not_found() {
        // Paragraphs are 16 bytes each.
        let mem = io::Cursor::new(&[0xff; 32]);

        find_entry_point(mem).expect_err("expected entry point not found error");
    }

    #[test]
    fn find_entry_point_ok() {
        #[rustfmt::skip]
        let mem = io::Cursor::new(&[
            // Paragraphs are 16 bytes each.
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // Entry point in second paragraph.
            b'_', b'S', b'M', 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);

        let address = find_entry_point(mem).expect("expected valid entry point address");

        // Table address is one paragraph after start address.
        assert_eq!(address, START_ADDRESS + PARAGRAPH_SIZE);
    }

    fn unwrap_structure(buf: &[u8]) -> Structure {
        let mut structures = unwrap_structures(buf);
        if structures.len() != 1 {
            panic!("only expected one structure");
        }

        structures.pop().unwrap()
    }

    fn unwrap_structures(buf: &[u8]) -> Vec<Structure> {
        let cursor = io::Cursor::new(buf);

        let mut decoder = Decoder::new(cursor);

        decoder.decode().unwrap()
    }
}
