#![no_std]
#![no_main]

mod maps;
mod xdp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
