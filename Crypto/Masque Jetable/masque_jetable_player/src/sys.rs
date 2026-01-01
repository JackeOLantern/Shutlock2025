//! System boilerplate (x86_64 specific)

use sc::syscall;

#[no_mangle]
unsafe fn entry() -> ! {
    // Necessary to align stack
    use core::arch::asm;
    let mut ret: usize;
    asm!("push rax; call {main}", main=sym crate::main, out("rax") ret);
    exit(ret);
}

#[panic_handler]
unsafe fn _panic(_: &core::panic::PanicInfo) -> ! {
    write(b"INTERNAL ERROR\n");
    exit(1);
}

unsafe fn exit(code: usize) -> ! {
    use core::arch::asm;
    syscall!(EXIT_GROUP, code);
    asm!("", options(noreturn))
}

pub unsafe fn getrandom(buf: &mut [u8]) {
    const GRND_NONBLOCK: u32 = 1;
    syscall!(GETRANDOM, buf.as_mut_ptr(), buf.len(), GRND_NONBLOCK);
}

pub unsafe fn getc() -> Option<u8> {
    let mut buf = [0u8];
    let ret = syscall!(READ, 0, buf.as_mut_ptr(), buf.len());
    if ret != 1 {
        return None;
    }
    Some(buf[0])
}

pub unsafe fn write(buf: &[u8]) {
    syscall!(WRITE, 1, buf.as_ptr(), buf.len());
}

#[no_mangle]
unsafe fn memset(ptr: *mut u8, c: u8, size: usize) {
    for i in 0..size {
        *ptr.add(i) = c
    }
}

#[no_mangle]
unsafe fn memcpy(dst: *mut u8, src: *const u8, size: usize) {
    for i in 0..size {
        *dst.add(i) = *src.add(i)
    }
}
