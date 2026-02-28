use std::ops::Deref;

#[derive(Debug)]
pub enum Error {
    NullPtr,
    InvalidSize,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct go_slice {
    ptr: *const u8,
    len: usize,
    cap: usize,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct tss_buffer {
    ptr: *const u8,
    len: usize,
}

impl Deref for go_slice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl go_slice {
    /// SAFETY: Caller must ensure ptr is valid for len bytes and pinned
    /// for the lifetime of any slice returned by as_slice().
    pub fn as_slice(&self) -> &[u8] {
        if self.is_empty() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0
    }
}

impl tss_buffer {
    pub fn empty() -> Self {
        tss_buffer {
            ptr: std::ptr::null(),
            len: 0,
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = vec.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *const u8;
        tss_buffer { ptr, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.is_empty() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0
    }

    pub fn into_vec(self) -> Vec<u8> {
        if self.is_empty() {
            return vec![];
        }
        unsafe {
            let slice = std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len);
            Box::from_raw(slice as *mut [u8]).into_vec()
        }
    }
}

unsafe impl Send for tss_buffer {}

impl Deref for tss_buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl From<Vec<u8>> for tss_buffer {
    fn from(vec: Vec<u8>) -> Self {
        Self::from_vec(vec)
    }
}

impl From<&[u8]> for tss_buffer {
    fn from(slice: &[u8]) -> tss_buffer {
        Vec::from(slice).into()
    }
}

impl From<&[u8]> for go_slice {
    fn from(slice: &[u8]) -> go_slice {
        go_slice {
            ptr: slice.as_ptr(),
            len: slice.len(),
            cap: slice.len(),
        }
    }
}

pub fn tss_buffer_free(buf: Option<&mut tss_buffer>) {
    if let Some(buf) = buf {
        if !buf.is_empty() {
            let ptr = std::mem::replace(&mut buf.ptr, std::ptr::null());
            let len = std::mem::replace(&mut buf.len, 0);
            unsafe {
                let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len);
                let _ = Box::from_raw(slice as *mut [u8]);
            }
        }
    }
}
