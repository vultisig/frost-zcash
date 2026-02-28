pub mod bytes;
pub mod handle;

mod codec;
mod errors;
mod key_import;
mod keygen;
mod keyshare;
mod reshare;
mod sign;

#[no_mangle]
pub extern "C" fn tss_buffer_free(buf: Option<&mut bytes::tss_buffer>) {
    bytes::tss_buffer_free(buf);
}

#[no_mangle]
pub extern "C" fn frozt_handle_free(h: handle::Handle) -> errors::lib_error {
    errors::with_error_handler(|| {
        handle::Handle::free(h)?;
        Ok(())
    })
}
