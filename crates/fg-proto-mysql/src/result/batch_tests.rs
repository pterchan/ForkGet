use super::*;
use crate::packet::batch_tests::RecordingWriter;
use fg_rewrite::ColumnOrigin;
use std::{sync::Arc, time::Duration};
use tokio::{io::DuplexStream, sync::Notify};

const END: &[u8] = &[EOF, 0, 0, 2, 0];

fn column(label: &str) -> Vec<u8> {
    let mut message = Vec::new();
    for field in [
        "def",
        "physical_schema",
        "physical_table",
        "physical_table",
        label,
        label,
    ] {
        put_lenbytes(&mut message, field.as_bytes());
    }
    message.extend_from_slice(&[12, 63, 0, 8, 0, 0, 0, 0x08, 0, 0, 0, 0, 0]);
    message
}

fn logical(label: &str) -> OutputColumn {
    OutputColumn {
        name: Some(label.into()),
        origin: Some(ColumnOrigin {
            logical_schema: "app".into(),
            logical_table: "orders".into(),
            logical_column: label.into(),
            table_alias: Some("o".into()),
        }),
    }
}

fn relay<'a>(
    backend: &'a mut DuplexStream,
    frontend: &'a mut RecordingWriter,
    metadata: &'a mut MetadataBatch,
) -> Relay<'a, RecordingWriter, DuplexStream> {
    Relay {
        backend,
        frontend,
        metadata,
        back_sequence: 1,
        front_sequence: 1,
        is_branch: true,
        is_writable: false,
        has_found_rows: false,
    }
}

async fn send(
    stream: &mut DuplexStream,
    sequence: &mut u8,
    messages: &[Vec<u8>],
) -> io::Result<()> {
    for message in messages {
        packet::write(stream, sequence, message).await?;
    }
    Ok(())
}

async fn frames(bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut input = bytes;
    let mut sequence = 1;
    let mut messages = Vec::new();
    while !input.is_empty() {
        messages.push(packet::read(&mut input, &mut sequence, MESSAGE_LIMIT).await?);
    }
    Ok(messages)
}

#[tokio::test]
async fn three_column_point_result_has_three_flushes_and_logical_metadata() -> io::Result<()> {
    let (mut backend, mut server) = tokio::io::duplex(32);
    let mut frontend = RecordingWriter::default();
    let mut batch = MetadataBatch::new();
    let output = [logical("id"), logical("quantity"), logical("version")];
    let native = [column("id"), column("quantity"), column("version")];
    let row = b"\x011\x012\x013".to_vec();
    let messages = vec![
        vec![3],
        native[0].clone(),
        native[1].clone(),
        native[2].clone(),
        END.to_vec(),
        row.clone(),
        END.to_vec(),
    ];
    let mut sequence = 1;
    let mut result = relay(&mut backend, &mut frontend, &mut batch);
    let (sent, relayed) = tokio::join!(
        send(&mut server, &mut sequence, &messages),
        result.query(Some(&output))
    );
    sent?;
    relayed?;
    assert_eq!(frontend.flush_ends.len(), 3);
    let actual = frames(&frontend.bytes).await?;
    assert_eq!(actual.len(), 7);
    assert_eq!(&actual[5..], &[row, END.to_vec()]);
    for (index, native) in native.iter().enumerate() {
        assert_eq!(
            actual[index + 1],
            logical_column(native, true, Some(&output[index]))?
        );
    }
    let metadata_bytes: usize = actual[..5].iter().map(|message| message.len() + 4).sum();
    assert_eq!(frontend.flush_ends[0], metadata_bytes);
    assert!(
        !frontend
            .bytes
            .windows(b"physical_".len())
            .any(|part| part == b"physical_")
    );
    Ok(())
}

#[tokio::test]
async fn metadata_and_each_row_flush_before_waiting_for_more_backend_data() -> io::Result<()> {
    let (mut backend, mut server) = tokio::io::duplex(16);
    let notification = Arc::new(Notify::new());
    let mut frontend = RecordingWriter::notifying(notification.clone());
    let mut batch = MetadataBatch::new();
    let sending = async {
        let mut sequence = 1;
        send(
            &mut server,
            &mut sequence,
            &[vec![1], column("id"), END.to_vec()],
        )
        .await?;
        notification.notified().await;
        send(&mut server, &mut sequence, &[b"\x011".to_vec()]).await?;
        notification.notified().await;
        send(&mut server, &mut sequence, &[END.to_vec()]).await
    };
    timeout(Duration::from_secs(2), async {
        let mut result = relay(&mut backend, &mut frontend, &mut batch);
        let (sent, relayed) = tokio::join!(sending, result.query(None));
        sent?;
        relayed
    })
    .await??;
    assert_eq!(frontend.flush_ends.len(), 3);
    Ok(())
}

#[tokio::test]
async fn prepare_flushes_parameter_and_column_groups_including_empty_groups() -> io::Result<()> {
    for (parameters, columns, flushes) in [(0u16, 0u16, 1), (2, 0, 1), (0, 2, 1), (2, 2, 2)] {
        let mut first = vec![OK];
        first.extend_from_slice(&42u32.to_le_bytes());
        first.extend_from_slice(&columns.to_le_bytes());
        first.extend_from_slice(&parameters.to_le_bytes());
        first.extend_from_slice(&[0, 0, 0]);
        let mut messages = vec![first];
        for count in [parameters, columns] {
            for _ in 0..count {
                messages.push(column("id"));
            }
            if count > 0 {
                messages.push(END.to_vec());
            }
        }
        let (mut backend, mut server) = tokio::io::duplex(32);
        let mut frontend = RecordingWriter::default();
        let mut batch = MetadataBatch::new();
        let mut sequence = 1;
        let mut result = relay(&mut backend, &mut frontend, &mut batch);
        let (sent, prepared) = tokio::join!(
            send(&mut server, &mut sequence, &messages),
            result.prepare(None)
        );
        sent?;
        assert_eq!(prepared?, Some(42));
        assert_eq!(
            frontend.flush_ends.len(),
            flushes,
            "parameters={parameters}, columns={columns}"
        );
        let actual = frames(&frontend.bytes).await?;
        assert_eq!(actual[0], messages[0]);
        for (index, message) in messages.iter().enumerate().skip(1) {
            assert_eq!(
                actual[index],
                if message.as_slice() == END {
                    message.clone()
                } else {
                    logical_column(message, true, None)?
                }
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn prepare_parameter_group_flushes_before_the_backend_sends_columns() -> io::Result<()> {
    let (mut backend, mut server) = tokio::io::duplex(16);
    let notification = Arc::new(Notify::new());
    let mut frontend = RecordingWriter::notifying(notification.clone());
    let mut batch = MetadataBatch::new();
    let sending = async {
        let mut sequence = 1;
        send(
            &mut server,
            &mut sequence,
            &[
                vec![OK, 42, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0],
                column("parameter"),
                END.to_vec(),
            ],
        )
        .await?;
        notification.notified().await;
        send(&mut server, &mut sequence, &[column("id"), END.to_vec()]).await
    };
    timeout(Duration::from_secs(2), async {
        let mut result = relay(&mut backend, &mut frontend, &mut batch);
        let (sent, prepared) = tokio::join!(sending, result.prepare(None));
        sent?;
        assert_eq!(prepared?, Some(42));
        Ok::<_, io::Error>(())
    })
    .await??;
    assert_eq!(frontend.flush_ends.len(), 2);
    Ok(())
}

#[tokio::test]
async fn native_error_during_metadata_drains_before_the_mapped_error() -> io::Result<()> {
    for before_end in [false, true] {
        let (mut backend, mut server) = tokio::io::duplex(32);
        let mut frontend = RecordingWriter::default();
        let mut batch = MetadataBatch::new();
        let messages = vec![
            vec![if before_end { 1 } else { 2 }],
            column("id"),
            b"\xff\x15\x04#HY000private backend message".to_vec(),
        ];
        let mut sequence = 1;
        let mut result = relay(&mut backend, &mut frontend, &mut batch);
        let (sent, relayed) = tokio::join!(
            send(&mut server, &mut sequence, &messages),
            result.query(None)
        );
        sent?;
        assert_eq!(
            relayed.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
        assert_eq!(frontend.flush_ends.len(), 2);
        let actual = frames(&frontend.bytes).await?;
        assert_eq!(actual.len(), 3);
        assert_eq!(actual[2][0], ERR);
        assert!(
            !frontend
                .bytes
                .windows(b"private".len())
                .any(|part| part == b"private")
        );
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_ok_error_and_final_eof_never_wait_in_the_metadata_buffer() -> io::Result<()> {
    for message in [
        vec![OK, 0, 0, 2, 0, 0, 0],
        b"\xff\x15\x04#HY000private".to_vec(),
    ] {
        let (mut backend, mut server) = tokio::io::duplex(32);
        let mut frontend = RecordingWriter::default();
        let mut batch = MetadataBatch::new();
        let mut sequence = 1;
        let messages = [message];
        let mut result = relay(&mut backend, &mut frontend, &mut batch);
        let (sent, relayed) = tokio::join!(
            send(&mut server, &mut sequence, &messages),
            result.query(None)
        );
        sent?;
        relayed?;
        assert_eq!(frontend.flush_ends.len(), 1);
    }
    let (mut backend, _server) = tokio::io::duplex(1);
    let mut frontend = RecordingWriter::default();
    let mut batch = MetadataBatch::new();
    let mut result = relay(&mut backend, &mut frontend, &mut batch);
    result.write_metadata(&[1]).await?;
    result.eof(END).await?;
    result.write_metadata(&[2]).await?;
    result.error(WireError::Backend).await?;
    assert_eq!(frontend.flush_ends.len(), 4);
    let actual = frames(&frontend.bytes).await?;
    assert_eq!(&actual[..3], &[vec![1], END.to_vec(), vec![2]]);
    assert_eq!(actual[3][0], ERR);
    Ok(())
}
