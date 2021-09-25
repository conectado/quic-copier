use std::fs::File;
use std::io::prelude::*;

use connection_manager::ConnectionManager;
const HTTP_REQ_STREAM_ID: u64 = 4;

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    env_logger::init();

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 1 {
        println!("Usage: {} URL", cmd);
        println!("\nSee tools/apps/ for more complete implementations.");
        // Lol no
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Argument Error",
        ));
    }

    let url = url::Url::parse(&args.next().unwrap()).expect("Incorrect arguments");

    let connection_manager = ConnectionManager::connect(url)
        .await
        .expect("Couldn't connect to url");

    let mut f = File::open("medium_chungus")?;

    let mut file_buf = Vec::new();
    f.read_to_end(&mut file_buf)?;

    connection_manager
        .send(file_buf.clone(), HTTP_REQ_STREAM_ID)
        .await
        .expect("Couldn't send file");

    Ok(())
}
