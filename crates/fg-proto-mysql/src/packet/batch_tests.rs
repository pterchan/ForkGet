use super::*;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::Notify;

pub(crate) struct RecordingWriter {
    pub(crate) bytes: Vec<u8>,
    pub(crate) flush_ends: Vec<usize>,
    pub(crate) flush_notify: Option<Arc<Notify>>,
    chunk_limit: usize,
    pending_next: bool,
    alternate_pending: bool,
    fail_after: Option<usize>,
    pause_after: Option<usize>,
    fail_flush: bool,
}

impl Default for RecordingWriter {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            flush_ends: Vec::new(),
            flush_notify: None,
            chunk_limit: usize::MAX,
            pending_next: false,
            alternate_pending: false,
            fail_after: None,
            pause_after: None,
            fail_flush: false,
        }
    }
}

impl RecordingWriter {
    pub(crate) fn notifying(notification: Arc<Notify>) -> Self {
        Self {
            flush_notify: Some(notification),
            ..Self::default()
        }
    }
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self
            .fail_after
            .is_some_and(|limit| self.bytes.len() >= limit)
        {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self
            .pause_after
            .is_some_and(|limit| self.bytes.len() >= limit)
        {
            return Poll::Pending;
        }
        if self.pending_next {
            self.pending_next = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let remaining = self
            .fail_after
            .or(self.pause_after)
            .map_or(usize::MAX, |limit| limit.saturating_sub(self.bytes.len()));
        let length = bytes.len().min(self.chunk_limit).min(remaining);
        self.bytes.extend_from_slice(&bytes[..length]);
        self.pending_next = self.alternate_pending;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.fail_flush {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let length = self.bytes.len();
        self.flush_ends.push(length);
        if let Some(notify) = &self.flush_notify {
            notify.notify_one();
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn metadata_capacity_boundaries_preserve_bytes_and_sequence() -> io::Result<()> {
    for sizes in [
        vec![0, 7],
        vec![METADATA_BATCH_LIMIT - 4],
        vec![METADATA_BATCH_LIMIT - 5, 0],
        vec![METADATA_BATCH_LIMIT - 3],
    ] {
        let mut batch = MetadataBatch::new();
        let mut writer = RecordingWriter::default();
        let mut expected = RecordingWriter::default();
        let (mut sequence, mut expected_sequence) = (u8::MAX, u8::MAX);
        for size in sizes {
            let message = vec![0x45; size];
            batch.write(&mut writer, &mut sequence, &message).await?;
            write(&mut expected, &mut expected_sequence, &message).await?;
            assert!(batch.framed.len() <= METADATA_BATCH_LIMIT);
            assert_eq!(batch.framed.capacity(), METADATA_BATCH_LIMIT);
        }
        batch.flush(&mut writer).await?;
        assert_eq!(writer.bytes, expected.bytes);
        assert_eq!(sequence, expected_sequence);
    }
    Ok(())
}

#[tokio::test]
async fn full_capacity_flushes_and_reuses_the_allocation() -> io::Result<()> {
    let mut batch = MetadataBatch::new();
    let allocation = batch.framed.as_ptr();
    let mut writer = RecordingWriter::default();
    let mut sequence = 0;
    for _ in 0..2 {
        batch
            .write(
                &mut writer,
                &mut sequence,
                &vec![0; METADATA_BATCH_LIMIT - 4],
            )
            .await?;
        assert!(batch.framed.is_empty());
        assert_eq!(batch.framed.as_ptr(), allocation);
    }
    assert_eq!(
        writer.flush_ends,
        [METADATA_BATCH_LIMIT, METADATA_BATCH_LIMIT * 2]
    );
    batch.flush(&mut writer).await?;
    assert_eq!(writer.flush_ends.len(), 2);
    Ok(())
}

#[tokio::test]
async fn large_metadata_drains_then_uses_fragment_framing() -> io::Result<()> {
    let mut batch = MetadataBatch::new();
    let mut writer = RecordingWriter::default();
    let mut sequence = u8::MAX - 1;
    batch.write(&mut writer, &mut sequence, b"header").await?;
    batch
        .write(&mut writer, &mut sequence, &vec![0x45; FRAGMENT])
        .await?;
    assert_eq!(writer.flush_ends, [10, FRAGMENT + 18]);
    let mut wire = writer.bytes.as_slice();
    let mut received = u8::MAX - 1;
    assert_eq!(
        read(&mut wire, &mut received, MESSAGE_LIMIT).await?,
        b"header"
    );
    assert_eq!(
        read(&mut wire, &mut received, MESSAGE_LIMIT).await?,
        vec![0x45; FRAGMENT]
    );
    assert!(wire.is_empty());
    assert_eq!((sequence, received), (1, 1));
    assert!(batch.framed.is_empty());
    Ok(())
}

#[tokio::test]
async fn metadata_handles_short_writes_and_pending_backpressure() -> io::Result<()> {
    let mut batch = MetadataBatch::new();
    let mut writer = RecordingWriter {
        chunk_limit: 3,
        alternate_pending: true,
        ..Default::default()
    };
    let mut sequence = 1;
    batch.write(&mut writer, &mut sequence, b"first").await?;
    batch.write(&mut writer, &mut sequence, b"second").await?;
    assert!(writer.bytes.is_empty());
    batch.flush(&mut writer).await?;
    assert_eq!(writer.bytes, b"\x05\0\0\x01first\x06\0\0\x02second");
    assert_eq!(writer.flush_ends, [19]);
    Ok(())
}

#[tokio::test]
async fn failed_or_cancelled_metadata_never_flushes_on_drop() -> io::Result<()> {
    for cancel in [false, true] {
        let mut batch = MetadataBatch::new();
        let mut writer = RecordingWriter {
            fail_after: (!cancel).then_some(5),
            pause_after: cancel.then_some(5),
            ..Default::default()
        };
        batch.write(&mut writer, &mut 1, b"metadata").await?;
        if cancel {
            let mut flushing = Box::pin(batch.flush(&mut writer));
            let state = std::future::poll_fn(|cx| Poll::Ready(flushing.as_mut().poll(cx))).await;
            assert!(state.is_pending());
            drop(flushing);
        } else {
            assert_eq!(
                batch
                    .flush(&mut writer)
                    .await
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::BrokenPipe)
            );
        }
        drop(batch);
        assert_eq!(writer.bytes, b"\x08\0\0\x01m");
        assert!(writer.flush_ends.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn flush_failure_is_reported_without_replaying_delivered_bytes() -> io::Result<()> {
    let mut batch = MetadataBatch::new();
    let mut writer = RecordingWriter {
        fail_flush: true,
        ..Default::default()
    };
    batch.write(&mut writer, &mut 1, b"metadata").await?;
    assert_eq!(
        batch
            .flush(&mut writer)
            .await
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    assert!(batch.framed.is_empty());
    assert_eq!(writer.bytes, b"\x08\0\0\x01metadata");
    Ok(())
}
