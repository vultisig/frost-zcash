pub mod bytes;
pub mod handle;

mod codec;
pub mod errors;
mod key_import;
mod keygen;
pub mod sapling;
mod keyshare;
mod reshare;
mod sign;
pub mod tree;
pub mod tx;
mod zeroize_util;

pub use zeroize_util::{zeroize_scalar, zeroize_scalar_vec};

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn tss_buffer_free(buf: Option<&mut bytes::tss_buffer>) {
    bytes::tss_buffer_free(buf);
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frozt_handle_free(h: handle::Handle) -> errors::lib_error {
    errors::with_error_handler(|| {
        handle::Handle::free(h)?;
        Ok(())
    })
}
