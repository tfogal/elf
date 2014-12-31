use std::default::Default;
use std::error::FromError;
use std::io::IoError;

#[deriving(Copy, FromPrimitive, PartialEq, Show)]
pub enum FileType {
	None = 0,
	Relocatable = 1,
	Executable = 2,
	Dynamic = 3,
	Core = 4,
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

pub struct Hdr {
	pub ident : [char, ..16],
	pub file_type : FileType,
	pub machine : u16,
	pub version : u32,
	pub entry : uint,
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

#[deriving(Copy, FromPrimitive, PartialEq, Show)]
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
	InitializeArray = 0xe, // extension, not in ELF spec
	FinalizeArray = 0xf, // extension, not in ELF spec
	LoOS = 0x60000000,
	GnuHash = 0x6FFFFFF6, // extension, not in ELF spec.
	HiOS = 0x6FFFFFFF,
	LoProc = 0x70000000,
	GnuVersionNeed = 0x6ffffffe, // extension, not in ELF spec.
	HiProc = 0x7FFFFFFF,
}
impl Default for SectionType {
	fn default() -> SectionType { SectionType::Null }
}

#[deriving(Show)]
pub struct SectionHeader {
	pub name: u32,
	pub shtype: SectionType,
	pub flags: u64,
	pub addr: uint,
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
			name: 0, shtype: SectionType::Null, flags:0, addr: 0, offset: 0, size: 0,
			link: 0, info: 0, align: 0, entsize: 0,
		}
	}
}
impl Copy for SectionHeader {}

#[deriving(Show)]
pub enum Error {
	Io(IoError),
	Index,
	Magic,
	TomMadeThisUp,
}
impl FromError<IoError> for Error {
	fn from_error(err: IoError) -> Error {
		Error::Io(err)
	}
}

// reads the elf header for the given file.
pub fn ehdr(filename : &str) -> Result<Hdr, Error> {
	use std::io::File;
	use std::mem;

	let path = Path::new(filename);
	let mut file = try!(File::open(&path));
	let bs = match file.read_exact(mem::size_of::<Hdr>()) {
		Err(err) => panic!("could not read bytes: {}", err.desc),
		Ok(b) => b,
	};
	let bytes = bs.as_slice();

	if bytes[0] != 0x7f || bytes[1] != 0x45 || bytes[2] != 0x4c ||
	   bytes[3] != 0x46 {
		println!("{} is not an ELF file!", filename);
		println!("b: {:x} {:x} {:x} {:x}", bytes[0], bytes[1], bytes[2], bytes[3]);
		return Err(Error::Magic);
	}

	let mut hdr: Hdr = Default::default();
	for i in range(0u, 16u) {
		hdr.ident[i] = bytes[i] as char;
	}

	let ftype = bytes[16] as u16 | bytes[17] as u16 << 8u;
	hdr.file_type = FromPrimitive::from_u16(ftype).unwrap();

	// make sure that using the u64 as a uint is appropriate.
	assert!(mem::size_of::<uint>() >= mem::size_of::<u64>());
	hdr.entry = u64_from_le(bytes, 24) as uint;
	hdr.phdr_offset = u64_from_le(bytes, 32);
	hdr.shdr_offset = u64_from_le(bytes, 40);
	hdr.flags = bytes[48] as u32 <<  0u | bytes[49] as u32 <<  8u |
	            bytes[50] as u32 << 16u | bytes[51] as u32 << 24u;
	hdr.ehdr_size = u16_from_le(bytes, 52);
	hdr.phdr_size = u16_from_le(bytes, 54);
	hdr.n_phdr = u16_from_le(bytes, 56);
	hdr.shdr_size = u16_from_le(bytes, 58);
	hdr.n_shdr = u16_from_le(bytes, 60);
	hdr.idx_strtable = u16_from_le(bytes, 62);

	return Ok(hdr);
}

pub fn shdr(filename: &str, sidx: uint) -> Result<SectionHeader, Error> {
	use std::io::{File, SeekSet};
	use std::mem;

	let ehdr = try!(ehdr(filename));
	if (sidx as u64) >= (ehdr.n_shdr as u64) {
		return Err(Error::Index);
	}
	assert!((sidx as u64) < (ehdr.n_shdr as u64));

	let path = Path::new(filename);
	let mut file = try!(File::open(&path));

	let shstart: u64 = ehdr.shdr_offset as u64;
	let shsz: u64 = ehdr.shdr_size as u64;
	try!(file.seek((shstart + (sidx as u64)*shsz) as i64, SeekSet));

	let bs = match file.read_exact(shsz as uint) {
		Err(_) => return Err(Error::TomMadeThisUp),
		Ok(b) => b,
	};
	let bytes = bs.as_slice();

	let mut hdr: SectionHeader = Default::default();
	hdr.name = u32_from_le(bytes, 0);
	let stype = u32_from_le(bytes, 4);
	hdr.shtype = match FromPrimitive::from_u32(stype) {
		None => {println!("stype? {:x}", stype); return Err(Error::TomMadeThisUp)},
		Some(ty) => ty,
	};
	hdr.flags = u64_from_le(bytes, 8);
	// make sure that using the u64 as a uint is appropriate.
	assert!(mem::size_of::<uint>() >= mem::size_of::<u64>());
	hdr.addr = u64_from_le(bytes, 16) as uint;
	hdr.offset = u64_from_le(bytes, 24);
	hdr.size = u64_from_le(bytes, 32);
	hdr.link = u32_from_le(bytes, 40);
	hdr.info = u32_from_le(bytes, 44);
	hdr.align = u64_from_le(bytes, 48);
	hdr.entsize = u64_from_le(bytes, 56);
	return Ok(hdr);
}

fn u16_from_le(data: &[u8], offset: uint) -> u16 {
	return data[offset] as u16 << 0u | data[offset+1] as u16 << 8u;
}

fn u32_from_le(data: &[u8], offset: uint) -> u32 {
	return data[offset+0] as u32 <<  0u |
	       data[offset+1] as u32 <<  8u |
	       data[offset+2] as u32 << 16u |
	       data[offset+3] as u32 << 24u;
}

/// Extracts an 8-bit to 64-bit unsigned big-endian value from the given byte
/// buffer and returns it as a 64-bit value.
///
/// Arguments:
/// * `data`: The buffer in which to extract the value.
/// * `start`: The offset at which to extract the value.
fn u64_from_le(data: &[u8], start: uint) -> u64 {
	use std::num::Int;
	use std::ptr::{copy_nonoverlapping_memory};

	let size = 8u;
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
