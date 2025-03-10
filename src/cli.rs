use crate::config::{parse, MercuryConfig};
use crate::service::Service;

use ansi_term::Colour::Green;
use clap::{crate_version, App, Arg, ArgMatches, SubCommand};
use fs_extra::dir::{self, CopyOptions};
use jsonrpc_core_client::transports::http;
use log::{error, info, LevelFilter};
use log4rs::append::{console::ConsoleAppender, file::FileAppender};
use log4rs::config::{Appender, Root};
use log4rs::{encode::pattern::PatternEncoder, Config};

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, str::FromStr};

const CONSOLE: &str = "console";

pub struct Cli<'a> {
    pub matches: ArgMatches<'a>,
    pub config: MercuryConfig,
}

impl<'a> Cli<'a> {
    pub fn init() -> Self {
        let matches = App::new("mercury")
            .version(crate_version!())
            .arg(
                Arg::with_name("config_path")
                    .short("c")
                    .long("config")
                    .help("Mercury config path")
                    .required(true)
                    .takes_value(true),
            )
            .subcommand(SubCommand::with_name("run").about("run the mercury process"))
            .subcommand(
                SubCommand::with_name("reset")
                    .about("reset with a height of db checkpoint")
                    .arg(
                        Arg::with_name("height")
                            .short("h")
                            .long("height")
                            .help("find the latest snapshot below this height")
                            .required(true)
                            .takes_value(true),
                    ),
            )
            .get_matches();

        let mut config: MercuryConfig =
            parse(matches.value_of("config_path").expect("missing config")).unwrap();

        config.check();

        Cli { matches, config }
    }

    pub async fn start(&self) {
        match self.matches.subcommand() {
            ("run", None) => self.run().await,

            ("reset", Some(sub_cmd)) => self.reset(
                sub_cmd
                    .value_of("height")
                    .expect("missing reset height")
                    .parse::<u64>()
                    .expect("parse reset height"),
            ),

            _ => self.run().await,
        }
    }

    async fn run(&self) {
        self.print_logo();
        self.log_init(false);

        let service = Service::new(
            self.config.store_path.as_str(),
            self.config.listen_uri.as_str(),
            Duration::from_secs(2),
            self.config.rpc_thread_num,
            self.config.network_type.as_str(),
            self.config.to_json_extensions_config().into(),
            self.config.snapshot_interval,
            self.config.snapshot_path.as_str(),
            self.config.cellbase_maturity,
            self.config.cheque_since,
        );

        let rpc_server = service.start();

        info!("Running!");

        let client = http::connect(&self.config.ckb_uri)
            .await
            .unwrap_or_else(|_| panic!("Failed to connect to {:?}", self.config.ckb_uri));

        service.poll(client).await;

        rpc_server.close();

        info!("Closing!");
    }

    fn reset(&self, height: u64) {
        self.log_init(true);

        if height < self.config.snapshot_interval {
            info!("The height is too low");
            return;
        }

        let latest_snapshot_height =
            (height / self.config.snapshot_interval) * self.config.snapshot_interval;

        let mut snapshot_path = Path::new(&self.config.snapshot_path).to_path_buf();
        snapshot_path.push(latest_snapshot_height.to_string());

        let mut db_path = Path::new(&self.config.store_path).to_path_buf();
        db_path.pop();

        if fs::read_dir(&snapshot_path).is_ok() {
            self.replace_with_snapshot(&snapshot_path, &mut db_path, latest_snapshot_height);
            snapshot_path.pop();
            self.clean_outdated_snapshots(&snapshot_path, latest_snapshot_height);

            info!("The DB has reset to height {} state", height);
        } else {
            error!("Invalid given height");
        }
    }

    fn clean_outdated_snapshots(&self, path: &Path, from: u64) {
        for dir in dir::get_dir_content(path)
            .unwrap()
            .directories
            .iter()
            .skip(1)
        {
            let p = PathBuf::from(dir);
            let folder = p.iter().last().unwrap().to_str().unwrap();

            if parse_folder_name(folder) > from {
                dir::remove(p).expect("remove outdated snapshot");
            }
        }
    }

    fn replace_with_snapshot(
        &self,
        snapshot_path: &Path,
        db_path: &mut PathBuf,
        snapshot_height: u64,
    ) {
        dir::remove(&self.config.store_path).expect("remove db");
        dir::copy(snapshot_path, &db_path, &CopyOptions::new()).expect("copy snapshot");
        db_path.push(snapshot_height.to_string());
        fs::rename(db_path, &self.config.store_path).expect("rename");
    }

    fn log_init(&self, coerce_console: bool) {
        let mut root_builder = Root::builder();
        let log_path = if coerce_console {
            CONSOLE
        } else {
            self.config.log_path.as_str()
        };

        if log_path == CONSOLE {
            root_builder = root_builder.appender("console");
        } else {
            root_builder = root_builder.appender("file")
        }

        let root = root_builder.build(LevelFilter::from_str(&self.config.log_level).unwrap());
        let encoder = Box::new(PatternEncoder::new("[{d} {h({l})} {t}] {m}{n}"));

        let config = if log_path == CONSOLE {
            let console_appender = ConsoleAppender::builder().encoder(encoder).build();
            Config::builder()
                .appender(Appender::builder().build("console", Box::new(console_appender)))
                .build(root)
        } else {
            let file_appender = FileAppender::builder()
                .encoder(encoder)
                .build(log_path)
                .expect("build file logger");
            Config::builder()
                .appender(Appender::builder().build("file", Box::new(file_appender)))
                .build(root)
        };

        log4rs::init_config(config.expect("build log config")).unwrap();
    }

    fn print_logo(&self) {
        println!(
            "{}",
            format!(
                r#"
  _   _   ______   _____   __      __ {}   _____
 | \ | | |  ____| |  __ \  \ \    / / {}  / ____|
 |  \| | | |__    | |__) |  \ \  / /  {} | (___
 | . ` | |  __|   |  _  /    \ \/ /   {}  \___ \
 | |\  | | |____  | | \ \     \  /    {}  ____) |
 |_| \_| |______| |_|  \_\     \/     {} |_____/
"#,
                Green.bold().paint(r#"  ____  "#),
                Green.bold().paint(r#" / __ \ "#),
                Green.bold().paint(r#"| |  | |"#),
                Green.bold().paint(r#"| |  | |"#),
                Green.bold().paint(r#"| |__| |"#),
                Green.bold().paint(r#" \____/ "#),
            )
        );
    }

    #[cfg(test)]
    fn run_reset(config: MercuryConfig, height: u64) {
        let cli = Cli {
            matches: Default::default(),
            config,
        };

        cli.reset(height);
    }
}

fn parse_folder_name(name: &str) -> u64 {
    if name.ends_with(".tmp") {
        let len = name.len();
        let (tmp, _) = name.split_at(len - 4);
        tmp.parse::<u64>().unwrap()
    } else {
        name.parse::<u64>().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use std::io::Write;

    fn random_bytes(size: usize) -> Vec<u8> {
        (0..1024 * 1024 * size).map(|_| random::<u8>()).collect()
    }

    #[test]
    fn test_reset() {
        fs::create_dir("./free-space/test-db").unwrap();
        let mut db_file = fs::File::create("./free-space/test-db/a.txt").unwrap();
        let data_a = random_bytes(1);
        db_file.write_all(&data_a).unwrap();

        fs::create_dir_all("./free-space/test-snap/10").unwrap();
        fs::create_dir("./free-space/test-snap/20").unwrap();
        let mut snap_file = fs::File::create("./free-space/test-snap/10/b.txt").unwrap();
        let data_b = random_bytes(2);
        snap_file.write_all(&data_b).unwrap();

        let config = MercuryConfig {
            store_path: "./free-space/test-db".to_string(),
            snapshot_path: "./free-space/test-snap".to_string(),
            log_level: "info".to_string(),
            snapshot_interval: 10,
            ..Default::default()
        };

        Cli::run_reset(config, 10);

        for entry in fs::read_dir("./free-space/test-db").unwrap() {
            let entry = entry.unwrap();
            assert_eq!(entry.file_name().to_str().unwrap(), "b.txt");
            let raw = fs::read("./free-space/test-db/b.txt").unwrap();
            assert_eq!(raw, data_b);
        }

        dir::remove("./free-space/test-db").unwrap();
        dir::remove("./free-space/test-snap").unwrap();
    }
}
