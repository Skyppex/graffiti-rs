mod cli;
mod csp;
mod id;
mod log;
mod net;
mod path_utils;
mod ppp;
mod rpc;
mod session;
mod state;

use std::{error::Error, process};

use clap::Parser;
use cli::{Cli, Commands};
use id::next_client_id;
use session::{
    editor::{EditorInbound, EditorOutbound},
    Role, Session, SessionEvent, SessionHandle,
};
use state::State;
use tokio::{
    io::{self, AsyncWriteExt, BufReader},
    sync::mpsc,
};
use tracing::info;

type DynError = Box<dyn Error + Send + Sync>;
type DynResult<T> = Result<T, DynError>;

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    log::init(
        cli.log_file.clone(),
        cli.log_to_stderr,
        cli.log_level,
        cli.log_filter.clone(),
    );

    info!("Starting graffiti-rs");

    let is_host = matches!(cli.command, Commands::Host { .. });

    let (editor_sender, mut session_receiver) = mpsc::channel::<EditorOutbound>(8);

    let cwd = std::env::current_dir()?;

    info!("Current working directory: {:?}", cwd);

    let state = State::new(cwd, cli.graffitiignore);

    let role = if is_host { Role::Host } else { Role::Client };
    let (session, session_handle) = Session::new(role, state.clone(), editor_sender.clone());
    let session_task = tokio::spawn(session.run());

    let network_task = match cli.command {
        Commands::Host { authorized_keys } => {
            info!("Starting host mode");

            let my_client_id = next_client_id();
            info!("my client id is {}", my_client_id);
            state.lock().await.set_client_id(my_client_id);

            let identity = net::identity::Identity::generate()?;

            tokio::spawn(net::run_host(
                session_handle.clone(),
                identity,
                authorized_keys,
            ))
        }
        Commands::Connect { sha, client_key } => {
            info!("Starting client mode");
            tokio::spawn(net::run_client(sha, session_handle.clone(), client_key))
        }
    };

    // the outbound half of the editor endpoint: encodes what the session
    // emits and writes it to the editor over stdout
    let editor_writer_task = tokio::spawn(async move {
        let mut editor_writer = io::stdout();
        while let Some(message) = session_receiver.recv().await {
            match csp::encode(message) {
                Ok(data) => {
                    if editor_writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Err(e) => info!("Failed to encode editor message: {}", e),
            }
        }
        info!("Editor writer task exited");
    });

    let editor_reader_task = tokio::spawn(run_editor(session_handle));

    // the session loop is the program: when it ends, we're done
    let shutting_down = session_task.await.unwrap_or(false);

    editor_reader_task.abort();
    network_task.abort();

    // every other editor_sender clone is gone once the session has returned,
    // so this closes the channel and lets the editor writer drain and exit
    drop(editor_sender);
    editor_writer_task.await?;

    if !shutting_down {
        info!("Exiting without shutdown message");
        process::exit(1);
    } else {
        info!("Exiting");
        process::exit(0);
    }
}

/// The editor endpoint: reads CSP messages from stdin and forwards them,
/// decoded, into the session's inbox.
async fn run_editor(session: SessionHandle) {
    let mut editor_reader = BufReader::new(io::stdin());

    info!("Entering editor message loop");

    loop {
        let decoded = match rpc::decode(&mut editor_reader).await {
            Ok(decoded) => decoded,
            Err(e) => {
                info!("Editor input closed: {}", e);
                let _ = session.send(SessionEvent::EditorClosed).await;
                break;
            }
        };

        info!("Handling editor method: {}", decoded.method);
        info!("Content: {:?}", String::from_utf8(decoded.content.clone()));

        match csp::decode(&decoded) {
            Ok(message) => {
                let is_exit = matches!(message, EditorInbound::Exit);

                if session
                    .send(SessionEvent::FromEditor(message))
                    .await
                    .is_err()
                {
                    break;
                }

                if is_exit {
                    break;
                }
            }
            Err(e) => info!("Failed to decode editor message: {}", e),
        }
    }
}
