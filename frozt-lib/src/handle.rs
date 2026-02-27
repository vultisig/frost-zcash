use std::{
    any::Any,
    collections::HashMap,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicI32, Ordering},
        Mutex,
    },
};

use lazy_static::lazy_static;

#[derive(Debug)]
pub enum Error {
    NullHandle,
    NotFound,
    InUse,
    InvalidType,
}

lazy_static! {
    static ref LAST: AtomicI32 = AtomicI32::new(1);
    static ref HMAP: Mutex<HashMap<i32, Option<Box<dyn Any + Send + 'static>>>> =
        Mutex::new(HashMap::new());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Handle(i32);

#[derive(Debug)]
pub struct HandleGuard<T: Send + 'static> {
    ptr: Option<Box<T>>,
    handle: i32,
}

impl<T: Send + 'static> HandleGuard<T> {
    pub fn into_inner(self) -> T {
        let mut this = ManuallyDrop::new(self);
        HMAP.lock().unwrap().remove(&this.handle);
        let obj = this.ptr.take().unwrap();
        *obj
    }
}

impl<T: Send + 'static> Deref for HandleGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.ptr.as_ref().unwrap()
    }
}

impl<T: Send + 'static> DerefMut for HandleGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ptr.as_mut().unwrap()
    }
}

fn put(handle: i32, obj: Box<dyn Any + Send + 'static>) {
    let mut map = HMAP.lock().unwrap();
    map.insert(handle, Some(obj));
}

impl<T: Send + 'static> Drop for HandleGuard<T> {
    fn drop(&mut self) {
        put(self.handle, self.ptr.take().unwrap());
    }
}

impl Handle {
    pub fn null() -> Self {
        Handle(0)
    }

    pub fn allocate<T: Send + 'static>(obj: T) -> Handle {
        let obj: Box<dyn Any + Send> = Box::new(obj);
        let mut map = HMAP.lock().unwrap();
        let handle = loop {
            let last = LAST.fetch_add(2, Ordering::Relaxed);
            if !map.contains_key(&last) {
                break last;
            }
        };
        map.insert(handle, Some(obj));
        Handle(handle)
    }

    pub fn get<T: Send + 'static>(&self) -> Result<HandleGuard<T>, Error> {
        if self.0 == 0 {
            return Err(Error::NullHandle);
        }
        let mut map = HMAP.lock().unwrap();
        let ent = map.get_mut(&self.0).ok_or(Error::NotFound)?;
        let obj = ent.take().ok_or(Error::InUse)?;
        match obj.downcast::<T>() {
            Ok(obj) => Ok(HandleGuard {
                ptr: Some(obj),
                handle: self.0,
            }),
            Err(obj) => {
                *ent = Some(obj);
                Err(Error::InvalidType)
            }
        }
    }

    pub fn take<T>(self) -> Result<T, Error>
    where
        T: Any,
    {
        if self.0 == 0 {
            return Err(Error::NullHandle);
        }
        let mut map = HMAP.lock().unwrap();
        let ent = map.get_mut(&self.0).ok_or(Error::NotFound)?;
        let obj = ent.take().ok_or(Error::InUse)?;
        match obj.downcast::<T>() {
            Ok(obj) => {
                map.remove(&self.0);
                Ok(*obj)
            }
            Err(obj) => {
                *ent = Some(obj);
                Err(Error::InvalidType)
            }
        }
    }

    pub fn free(handle: Handle) -> Result<(), Error> {
        let mut map = HMAP.lock().unwrap();
        map.remove(&handle.0).ok_or(Error::NotFound)?;
        Ok(())
    }
}
