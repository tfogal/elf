extern crate elf;

#[test]
fn testexectype() {
	let bintrue = elf::ehdr("/bin/true").unwrap();
	assert_eq!(bintrue.file_type, elf::FileType::Executable);

	let libc = elf::ehdr("/lib/x86_64-linux-gnu/libc.so.6").unwrap();
	assert_eq!(libc.file_type, elf::FileType::Dynamic);

	printinfo("/lib/x86_64-linux-gnu/libc.so.6");
	printinfo("/bin/true");
}

#[allow(dead_code)] // stupid f'ing rust doesn't consider test code as "used".
fn printinfo(fname: &str) {
	let program = match elf::ehdr(fname) {
		None => return,
		Some(ehdr) => ehdr,
	};
	println!("{}, {}", fname, program.file_type);
	println!("\t{:-30} 0x{:x}", "entry:", program.entry);
	println!("\t{:-30} {}", "program header offset:", program.phdr_offset);
	println!("\t{:-30} {}", "section header offset:", program.shdr_offset);
	println!("\t{:-30} 0x{:x}", "flags:", program.flags);
	println!("\t{:-30} {}", "size of this header:", program.ehdr_size);
	println!("\t{:-30} {}", "size of prog headers:", program.phdr_size);
	println!("\t{:-30} {}", "number of Pheaders:", program.n_phdr);
	println!("\t{:-30} {}", "size of sec headers:", program.shdr_size);
	println!("\t{:-30} {}", "number of sec headers:", program.n_shdr);
	println!("\t{:-30} {}", "sec header strtable:", program.idx_strtable);
}