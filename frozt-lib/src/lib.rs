pub mod bytes;
pub mod handle;

mod address;
mod codec;
mod errors;
mod keygen;
mod keyshare;
mod reshare;
mod sign;

#[no_mangle]
pub extern "C" fn tss_buffer_free(buf: Option<&mut bytes::tss_buffer>) {
    bytes::tss_buffer_free(buf);
}
