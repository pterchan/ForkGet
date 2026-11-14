//! MySQL classic packet framing and length-encoded fields.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const FRAGMENT: usize = 0xff_ff_ff;
pub(crate) const MESSAGE_LIMIT: usize = 32 * 1024 * 1024;
pub(crate) const HANDSHAKE_LIMIT: usize = 64 * 1024;
// Keep common header/body pairs in one TLS write without copying large rows.
const COALESCE_LIMIT: usize = 16 * 1024;
pub(crate) const METADATA_BATCH_LIMIT: usize = 16 * 1024;

/// Only result metadata may wait for a protocol-defined group boundary.
pub(crate) struct MetadataBatch {
    framed: Vec<u8>,
}

impl MetadataBatch {
    pub(crate) fn new() -> Self {
        Self {
            framed: Vec::with_capacity(METADATA_BATCH_LIMIT),
        }
    }

    pub(crate) async fn write(
        &mut self,
        stream: &mut (impl AsyncWrite + Unpin),
        sequence: &mut u8,
        message: &[u8],
    ) -> io::Result<()> {
        if message.len() > METADATA_BATCH_LIMIT - 4 {
            self.flush(stream).await?;
            return write(stream, sequence, message).await;
        }
        let length = message.len() + 4;
        if length > METADATA_BATCH_LIMIT - self.framed.len() {
            self.flush(stream).await?;
        }
        self.framed
            .extend_from_slice(&(message.len() as u32).to_le_bytes()[..3]);
        self.framed.push(*sequence);
        self.framed.extend_from_slice(message);
        *sequence = sequence.wrapping_add(1);
        if self.framed.len() == METADATA_BATCH_LIMIT {
            self.flush(stream).await?;
        }
        Ok(())
    }

    pub(crate) async fn flush(&mut self, stream: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        if !self.framed.is_empty() {
            // As with packet::write, cancellation or I/O failure ends the
            // session; partially delivered packets must never be replayed.
            stream.write_all(&self.framed).await?;
            self.framed.clear();
            stream.flush().await?;
        }
        Ok(())
    }
}

pub(crate) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid MySQL protocol message")
}

pub(crate) async fn read(
    stream: &mut (impl AsyncRead + Unpin),
    sequence: &mut u8,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        let length = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
        if header[3] != *sequence || length > limit.saturating_sub(message.len()) {
            return Err(invalid());
        }
        *sequence = sequence.wrapping_add(1);
        let start = message.len();
        message.resize(start + length, 0);
        stream.read_exact(&mut message[start..]).await?;
        if length != FRAGMENT {
            return Ok(message);
        }
    }
}

pub(crate) async fn write(
    stream: &mut (impl AsyncWrite + Unpin),
    sequence: &mut u8,
    mut message: &[u8],
) -> io::Result<()> {
    loop {
        let length = message.len().min(FRAGMENT);
        let [low, middle, high, _] = (length as u32).to_le_bytes();
        let header = [low, middle, high, *sequence];
        if length == 0 {
            stream.write_all(&header).await?;
        } else if length + header.len() <= COALESCE_LIMIT {
            let mut framed = Vec::with_capacity(header.len() + length);
            framed.extend_from_slice(&header);
            framed.extend_from_slice(&message[..length]);
            stream.write_all(&framed).await?;
        } else {
            stream.write_all(&header).await?;
            stream.write_all(&message[..length]).await?;
        }
        *sequence = sequence.wrapping_add(1);
        if length != FRAGMENT {
            return stream.flush().await;
        }
        message = &message[length..];
    }
}

pub(crate) struct Fields<'a>(pub(crate) &'a [u8]);

impl<'a> Fields<'a> {
    pub(crate) fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(count).ok_or_else(invalid)?;
        self.0 = tail;
        Ok(head)
    }

    pub(crate) fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> io::Result<u16> {
        self.fixed().map(u16::from_le_bytes)
    }

    pub(crate) fn u32(&mut self) -> io::Result<u32> {
        self.fixed().map(u32::from_le_bytes)
    }

    fn fixed<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| invalid())
    }

    pub(crate) fn cstring(&mut self) -> io::Result<&'a [u8]> {
        let end = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(invalid)?;
        let value = self.take(end)?;
        self.take(1)?;
        Ok(value)
    }

    pub(crate) fn lenenc(&mut self) -> io::Result<usize> {
        usize::try_from(self.lenenc_u64()?).map_err(|_| invalid())
    }

    pub(crate) fn lenenc_u64(&mut self) -> io::Result<u64> {
        let number = match self.byte()? {
            value @ 0..=0xfa => u64::from(value),
            0xfc => u64::from(self.u16()?),
            0xfd => {
                let [low, middle, high] = self.fixed()?;
                u64::from(u32::from_le_bytes([low, middle, high, 0]))
            }
            0xfe => u64::from_le_bytes(self.fixed()?),
            _ => return Err(invalid()),
        };
        Ok(number)
    }

    pub(crate) fn lenbytes(&mut self) -> io::Result<&'a [u8]> {
        let length = self.lenenc()?;
        self.take(length)
    }
}

pub(crate) fn put_lenbytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = value.len();
    if length <= 0xfa {
        output.push(length as u8);
    } else if let Ok(length) = u16::try_from(length) {
        output.push(0xfc);
        output.extend(length.to_le_bytes());
    } else if length <= FRAGMENT {
        output.push(0xfd);
        output.extend_from_slice(&(length as u32).to_le_bytes()[..3]);
    } else {
        output.push(0xfe);
        output.extend((length as u64).to_le_bytes());
    }
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preserves_wire_bytes_with_backpressure_at_small_write_boundary() -> io::Result<()> {
        for size in [0, 7, COALESCE_LIMIT - 4, COALESCE_LIMIT - 3] {
            let (mut sender, mut receiver) = tokio::io::duplex(3);
            let input = vec![0x45; size];
            let mut sequence = u8::MAX;
            let expected_length = size + 4;
            let sending = async {
                write(&mut sender, &mut sequence, &input).await?;
                sender.shutdown().await
            };
            let receiving = async {
                let mut bytes = Vec::new();
                receiver.read_to_end(&mut bytes).await?;
                Ok::<_, io::Error>(bytes)
            };
            let (sent, received) = tokio::join!(sending, receiving);
            sent?;
            let bytes = received?;
            assert_eq!(bytes.len(), expected_length);
            assert_eq!(&bytes[..3], &(size as u32).to_le_bytes()[..3]);
            assert_eq!(bytes[3], u8::MAX);
            assert_eq!(&bytes[4..], input);
            assert_eq!(sequence, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn exact_fragment_requires_a_terminator_and_wraps_sequence() -> io::Result<()> {
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        let input = vec![0x45; FRAGMENT];
        let mut sent = u8::MAX;
        let mut received = u8::MAX;
        let (write_result, read_result) = tokio::join!(
            write(&mut sender, &mut sent, &input),
            read(&mut receiver, &mut received, MESSAGE_LIMIT),
        );
        write_result?;
        assert_eq!(read_result?, input);
        assert_eq!((sent, received), (1, 1));
        Ok(())
    }

    #[tokio::test]
    async fn wrong_sequence_and_excess_size_fail_before_reading_body() -> io::Result<()> {
        for header in [[1, 0, 0, 1], [9, 0, 0, 0]] {
            let mut stream = header.as_slice();
            let error = read(&mut stream, &mut 0, 8).await.err();
            assert_eq!(
                error.map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "packet/batch_tests.rs"]
pub(crate) mod batch_tests;
