//! Run the standalone MongoDB passthrough fixture for driver compatibility checks.
//! The example credentials below are local test values.
//!
//! ```sh
//! FG_MONGO_BACKEND=127.0.0.1:27027 FG_MONGO_LISTEN=127.0.0.1:28017 \
//! FG_MONGO_USER=alice FG_MONGO_PASSWORD=spike-alice-pw \
//! cargo run -p fg-proto-mongo --example spike_proxy
//! ```

use std::net::SocketAddr;

use fg_proto_mongo::{Account, SpikeConfig};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listen: SocketAddr = std::env::var("FG_MONGO_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:28017".into())
        .parse()
        .map_err(|error| std::io::Error::other(format!("FG_MONGO_LISTEN: {error}")))?;
    let backend: SocketAddr = std::env::var("FG_MONGO_BACKEND")
        .unwrap_or_else(|_| "127.0.0.1:27027".into())
        .parse()
        .map_err(|error| std::io::Error::other(format!("FG_MONGO_BACKEND: {error}")))?;
    let account = Account {
        user: std::env::var("FG_MONGO_USER").unwrap_or_else(|_| "alice".into()),
        password: std::env::var("FG_MONGO_PASSWORD").unwrap_or_else(|_| "spike-alice-pw".into()),
    };
    let config = SpikeConfig {
        listen,
        backend,
        backend_auth_db: std::env::var("FG_MONGO_AUTH_DB").unwrap_or_else(|_| "admin".into()),
        accounts: vec![account],
    };
    println!("mongo spike listening on {}", config.listen);
    fg_proto_mongo::serve(config).await
}
