extern crate byteorder;
extern crate smbios;

use byteorder::{ByteOrder, LE};
use smbios::{EntryPoint, EntryPointType};

fn main() -> Result<(), Box<std::error::Error>> {
    let (entry_point, structures) = smbios::stream()?;

    match entry_point {
        EntryPointType::Bits32(ep) => show_entry_point(&ep),
        EntryPointType::Bits64(ep) => show_entry_point(&ep),
        _ => {
            println!("unknown SMBIOS entry point type, continuing anyway");
        }
    }

    for structure in structures {
        // Only look for DIMM information for this example.
        if structure.header.header_type != 17 {
            continue;
        }

        let mut dimm_size = LE::read_u16(&structure.formatted[8..10]) as usize;

        if dimm_size == 0x7fff {
            dimm_size = LE::read_u32(&structure.formatted[24..28]) as usize;
        }

        let unit = if structure.formatted[9] & 0x80 == 0 {
            "MB"
        } else {
            "KB"
        };

        println!("DIMM: {} {}", dimm_size, unit);
    }

    Ok(())
}

fn show_entry_point<T: EntryPoint>(entry_point: &T) {
    let (major, minor, rev) = entry_point.version();
    println!("SMBIOS: {}.{}.{}", major, minor, rev);

    let (address, size) = entry_point.table();
    println!("  table: {} bytes, address: {:#010x}", size, address);
}
