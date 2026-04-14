#![no_std]
#![no_main]

mod icmp;
mod maps;
mod tc;
mod token_bucket;
mod xdp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
