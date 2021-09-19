use connection_manager::server_manager::ConnectionManager;
#[tokio::main]
async fn main() {
    env_logger::init();

    let manager = ConnectionManager::listen()
        .await
        .expect("Couldn't open listening loop");

    log::info!("Press ctrl-C to stop listening");
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            manager.shutdown().expect("Couldn't send shutdown message");
        }
        Err(err) => {
            log::error!("Error waiting for signal {}", err);
        }
    }
}
