//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Writes the committed EWF fixtures via libewf write
//!

// rustc --edition 2021 -L <dir-with-libewf.so> -l ewf generate.rs -o generate && ./generate

use std::ffi::{c_void, CString};
use std::os::raw::{c_char, c_int};
type Handle = *mut c_void;
type Err = *mut c_void;
unsafe extern "C" {
    fn libewf_handle_initialize(h: *mut Handle, e: *mut Err) -> c_int;
    fn libewf_handle_free(h: *mut Handle, e: *mut Err) -> c_int;
    fn libewf_handle_open(h: Handle, n: *const *mut c_char, c: c_int, f: c_int, e: *mut Err) -> c_int;
    fn libewf_handle_close(h: Handle, e: *mut Err) -> c_int;
    fn libewf_handle_set_media_size(h: Handle, s: u64, e: *mut Err) -> c_int;
    fn libewf_handle_set_maximum_segment_size(h: Handle, s: u64, e: *mut Err) -> c_int;
    fn libewf_handle_write_buffer(h: Handle, b: *const c_void, s: usize, e: *mut Err) -> isize;
    fn libewf_handle_write_finalize(h: Handle, e: *mut Err) -> isize;
}
fn pattern(n: usize) -> Vec<u8> { (0..n).map(|i| ((i * 31 + 7) % 251) as u8).collect() }
unsafe fn create(base: &str, size: usize, segment: u64) {
    let data = pattern(size);
    let mut h: Handle = std::ptr::null_mut();
    let mut e: Err = std::ptr::null_mut();
    libewf_handle_initialize(&mut h, &mut e);
    let name = CString::new(base).unwrap();
    let names = [name.as_ptr() as *mut c_char];
    assert_eq!(libewf_handle_open(h, names.as_ptr(), 1, 0x02, &mut e), 1);
    assert_eq!(libewf_handle_set_media_size(h, size as u64, &mut e), 1);
    if segment > 0 { libewf_handle_set_maximum_segment_size(h, segment, &mut e); }
    assert_eq!(libewf_handle_write_buffer(h, data.as_ptr() as *const c_void, data.len(), &mut e) as usize, data.len());
    assert!(libewf_handle_write_finalize(h, &mut e) >= 0);
    libewf_handle_close(h, &mut e);
    libewf_handle_free(&mut h, &mut e);
    println!("wrote {base} ({size} bytes)");
}
fn main() { unsafe {
    create("single", 8192, 0);
    create("multi", 65536, 8192);
}}
