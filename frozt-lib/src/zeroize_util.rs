use reddsa::frost::redjubjub::JubjubBlake2b512;

type Scalar = frost_core::Scalar<JubjubBlake2b512>;

/// Zeroes the in-memory representation of a jubjub scalar.
/// jubjub::Fr doesn't implement Zeroize, so we use volatile writes directly.
pub fn zeroize_scalar(s: &mut Scalar) {
    unsafe {
        let ptr = s as *mut Scalar as *mut u8;
        let len = std::mem::size_of::<Scalar>();
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
}

/// Zeroes all scalars in a Vec, then drops the Vec.
pub fn zeroize_scalar_vec(v: &mut Vec<Scalar>) {
    for s in v.iter_mut() {
        zeroize_scalar(s);
    }
}
