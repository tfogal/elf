use std::default::Default;

#[deriving(Copy, FromPrimitive, PartialEq, Show)]
pub enum FileType {
	None = 0x0,
	Relocatable = 0x1,
	Executable = 0x2,
	Dynamic = 0x3,
	Core = 0x4,
	LoOS = 0xFE00,
	HiOS = 0xFEFF,
	LoProc = 0xFF00,
	HiProc = 0xFFFF,
}
impl Default for FileType { fn default() -> FileType { FileType::None } }

#[deriving(Copy, PartialEq)]
pub enum SpecialSectionIndex {
	Undefined = 0x0,
	LoProc = 0xFF00,
	HiProc = 0xFF1F,
	LoOS = 0xff20,
	HiOS = 0xff3f,
	Absolute = 0xfff1,
	Common = 0xfff2,
}
impl Default for SpecialSectionIndex {
	fn default() -> SpecialSectionIndex { SpecialSectionIndex::Undefined }
}

#[deriving(Copy, PartialEq)]
pub enum SectionType {
	Null = 0,
	Program = 1,
	SymTable = 2,
	StrTable = 3,
	RelA = 4,
	Hash = 5,
	Dynamic = 6,
	Note = 7,
	NoBits = 8,
	Rel = 9,
	SharedLibrary = 10,
	DynSymTable = 11,
	LoOS = 0x60000000,
	HiOS = 0x6FFFFFFF,
	LoProc = 0x70000000,
	HiProc = 0x7FFFFFFF,
}

pub struct Hdr {
	pub ident : [char, ..16],
	pub file_type : FileType,
	pub machine : u16,
	pub version : u32,
	pub entry : u64, // really a uintptr... :-/
	pub phdr_offset : u64,
	pub shdr_offset : u64,
	pub flags: u32,
	pub ehdr_size : u16,
	pub phdr_size : u16,
	pub n_phdr : u16,
	pub shdr_size : u16,
	pub n_shdr : u16,
	pub idx_strtable : u16,
}
impl Default for Hdr {
	fn default() -> Hdr {
		Hdr {
			ident: ['\0', ..16],
			file_type: Default::default(),
			machine: Default::default(),
			version: Default::default(),
			entry: 0x0,
			phdr_offset: Default::default(),
			shdr_offset: Default::default(),
			flags: Default::default(),
			ehdr_size: Default::default(),
			phdr_size: Default::default(),
			n_phdr: 0,
			shdr_size: 0,
			n_shdr: 0,
			idx_strtable: 0
		}
	}
}
impl Copy for Hdr {}

pub struct SectionHeader {
	pub name: u32,
	pub shtype: u32,
	pub flags: u64,
	pub addr: u64, // actually a uintptr... what type should we use for that?
	pub offset: u64,
	pub size: u64,
	pub link: u32,
	pub info: u32,
	pub align: u64,
	pub entsize: u64,
}
impl Default for SectionHeader {
	fn default() -> SectionHeader {
		SectionHeader {
			name: 0, shtype: 0, flags:0, addr: 0, offset: 0, size: 0, link: 0,
			info: 0, align: 0, entsize: 0,
		}
	}
}
impl Copy for SectionHeader {}

// reads the elf header for the given file.
pub fn ehdr(filename : &str) -> Option<Hdr> {
	use std::io::File;
	use std::mem;

	let path = Path::new(filename);
	let mut file = match File::open(&path) {
		Err(err) =>	panic!("could not open {}: {}", path.display(), err.desc),
		Ok(file) => file,
	};
	let bs = match file.read_exact(mem::size_of::<Hdr>()) {
		Err(err) => panic!("could not read bytes: {}", err.desc),
		Ok(b) => b,
	};
	let bytes = bs.as_slice();

	if bytes[0] != 0x7f || bytes[1] != 0x45 || bytes[2] != 0x4c ||
	   bytes[3] != 0x46 {
		println!("{} is not an ELF file!", filename);
		println!("b: {:x} {:x} {:x} {:x}", bytes[0], bytes[1], bytes[2], bytes[3]);
		return None;
	}

	let mut hdr: Hdr = Default::default();
	for i in range(0u, 16u) {
		hdr.ident[i] = bytes[i] as char;
	}

	let ftype = bytes[16] as u16 | bytes[17] as u16 << 8u;
	hdr.file_type = FromPrimitive::from_u16(ftype).unwrap();

	hdr.entry = u64_from_le_bytes(bytes, 24, 8);
	hdr.phdr_offset = u64_from_le_bytes(bytes, 32, 8);
	hdr.shdr_offset = u64_from_le_bytes(bytes, 40, 8);
	hdr.flags = bytes[48] as u32 <<  0u | bytes[49] as u32 <<  8u |
	            bytes[50] as u32 << 16u | bytes[51] as u32 << 24u;
	hdr.ehdr_size = u16_from_le(bytes, 52);
	hdr.phdr_size = u16_from_le(bytes, 54);
	hdr.n_phdr = u16_from_le(bytes, 56);
	hdr.shdr_size = u16_from_le(bytes, 58);
	hdr.n_shdr = u16_from_le(bytes, 60);
	hdr.idx_strtable = u16_from_le(bytes, 62);

	return Some(hdr);
}

pub fn shdr(filename: &str, sidx: uint) -> Option<SectionHeader> {
	let x: SectionHeader = Default::default();
	println!("blah: {}, {}", filename, sidx);
	return Some(x);
}

fn u16_from_le(data: &[u8], offset : uint) -> u16 {
	return data[offset] as u16 << 0u | data[offset+1] as u16 << 8u;
}

/// Extracts an 8-bit to 64-bit unsigned big-endian value from the given byte
/// buffer and returns it as a 64-bit value.
///
/// Arguments:
/// * `data`: The buffer in which to extract the value.
/// * `start`: The offset at which to extract the value.
/// * `size`: The size of the value in bytes to extract. This must be 8 or
/// less, or task panic occurs. If this is less than 8, then only
/// that many bytes are parsed. For example, if `size` is 4, then a
/// 32-bit value is parsed.
fn u64_from_le_bytes(data: &[u8], start: uint, size: uint) -> u64 {
	use std::num::Int;
	use std::ptr::{copy_nonoverlapping_memory};

	assert!(size <= 8u);
	if data.len() - start < size {
		panic!("index out of bounds");
	}
	let mut buf = [0u8, ..8];
	unsafe {
		let ptr = data.as_ptr().offset(start as int);
		let out = buf.as_mut_ptr();
		copy_nonoverlapping_memory(out.offset((8 - size) as int), ptr, size);
		(*(out as *const u64)).to_le()
	}
}

