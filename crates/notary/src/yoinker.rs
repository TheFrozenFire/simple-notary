use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::pin::Pin;
use futures::io::{AsyncRead, AsyncWrite};

pub struct IoBoinker<T>(Weak<Mutex<T>>);

impl<T: AsyncRead + Unpin> AsyncRead for IoBoinker<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8]) -> Poll<Result<usize, std::io::Error>>
    { 
        let arc = self.0.upgrade()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "IoYoinker was dropped"
            ))?;
        
        let mut guard = arc.lock().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Mutex was poisoned"
        ))?;
        
        let pinned = Pin::new(&mut *guard);
        pinned.poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IoBoinker<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, std::io::Error>> {
        let arc = self.0.upgrade()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "IoYoinker was dropped"
            ))?;
        
        let mut guard = arc.lock().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Mutex was poisoned"
        ))?;
        
        let pinned = Pin::new(&mut *guard);
        pinned.poll_write(cx, buf)
    }
    
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), std::io::Error>> {
        let arc = self.0.upgrade()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "IoYoinker was dropped"
            ))?;
        
        let mut guard = arc.lock().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Mutex was poisoned"
        ))?;
        
        let pinned = Pin::new(&mut *guard);
        pinned.poll_flush(cx)
    }
    
    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let arc = self.0.upgrade()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "IoYoinker was dropped"
            ))?;
        
        let mut guard = arc.lock().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::Other,
            "Mutex was poisoned"
        ))?;
        
        let pinned = Pin::new(&mut *guard);
        pinned.poll_close(cx)
    }
}

pub struct IoYoinker<T>(Arc<Mutex<T>>);

impl<T> IoYoinker<T> {
    pub fn new_yoinker(value: T) -> (Self, IoBoinker<T>) {
        let value = Arc::new(Mutex::new(value));
        let value_weak = Arc::downgrade(&value);
        (Self(value), IoBoinker(value_weak))
    }

    pub fn yoink(self) -> T 
    where
        T: std::fmt::Debug,
    {
        Arc::try_unwrap(self.0).unwrap().into_inner().unwrap()
    }
}