// Malinstrack: Malicious installation tracker

#![feature(fs_try_exists)]

use std::{
    env, fs,
    path::{self, Path, PathBuf},
    process::Command,
};

use clap::{Parser, Subcommand};
use colored::Colorize;
use spinners::{Spinner, Spinners};

#[derive(Clone, Subcommand)]
enum Actions {
    /// setup malinstrack program
    Setup,
    /// track program
    Track {
        /// unique identifier to link different scripts/apps to a single report
        identifier: String,
        /// path of script/app to track
        path: path::PathBuf,
    },
    /// view report
    ViewReport { identifier: String },
}

#[derive(Parser)]
#[command(author = "feniljain", version = "0.0.1", about, long_about = None)]
struct Args {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    action: Actions,
}

fn main() -> anyhow::Result<()> {
    // CLI Options:
    // - Setup: Provide setup command of this project
    //     - Make a file to report different apps passed to track cmd
    //     - Check build deps and build a shared library locally
    // - Track: Take in a path and track all files accessed/created/deleted by it
    //     - LD_PRELOAD our shared library and run the path
    // - View Report: Get comprehensive report for given target
    //     - Make a TUI/GUI to select what all to delete and make a generic uninstaller
    //     - Also create a generic KB which *suggests* what files you should ideally not delete or
    //     should definitely delete
    //     - Can show report in nice table: https://github.com/zhiburt/tabled

    // Shared Library:
    // - Make functions to override syscalls
    // - They see what file is accessed/modified and append it to our file
    // - Parse app/script's linked libs and add them to our file too
    // - We run a de-duplication job after exec of given binary completes

    let args = Args::parse();

    // [] TODO: Set debug mode
    // [] TODO: Insert a check/cmd option to check deps:
    // - sqlite3
    // - gcc/clang

    #[allow(deprecated)]
    let home_dir_path = std::env::home_dir().expect("Expected home dir path");
    let reports_dir_path = Path::join(&home_dir_path, Path::new(".malinstrack/reports/"));
    let lib_dir_path = Path::join(&home_dir_path, Path::new(".malinstrack/lib/"));
    let new_build_so_path = Path::join(&lib_dir_path, Path::new("libmalinstrack.so"));

    match args.action {
        Actions::Setup => {
            println!("Starting setup");

            check_deps()?;

            let mut dir_creation_sp = Spinner::new(
                Spinners::Dots9,
                "creating dirs for handling everything related to malinstrack\n".into(),
            );

            fs::create_dir_all(reports_dir_path)?;
            fs::create_dir_all(lib_dir_path.clone())?;
            dir_creation_sp.stop();
            println!("finished creating dirs ✅");
            println!();

            println!("=============================================");
            println!("finding gcc by asking for it's version, output:");
            create_shared_object(new_build_so_path)?;
            println!("=============================================");
            println!();

            println!("setup completed :)");
            println!("let's track those malicious actors down!");
        }
        Actions::Track {
            path: bin_path,
            identifier,
        } => {
            let bin_path_str = bin_path
                .to_str()
                .expect("could not print path, what did you pass bruhh");

            if identifier == "" {
                println!("{}", "invalid identifier: {identifier}".red());
                return Ok(());
            }

            let tracking_dir_str = format!(".malinstrack/reports/{identifier}");

            let tracking_dir_path = Path::join(&home_dir_path, Path::new(&tracking_dir_str));
            let db_name = format!("{identifier}.db");
            let tracking_db_path = Path::join(&tracking_dir_path, Path::new(&db_name));

            println!("tracking_db_path: {tracking_db_path:?}");

            let connection: sqlite::Connection;

            if let Ok(false) = fs::try_exists(&tracking_dir_str) {
                fs::create_dir_all(tracking_dir_path)?;

                // Making different sqlite DB for each program, so that results can
                // be easily transported anywhere, more convenience to user
                connection =
                    sqlite::open(tracking_db_path.clone()).expect("could not create or open DB");

                let table_create_cmd =
                    format!("CREATE TABLE IF NOT EXISTS {identifier}(path TEXT, unique(path))");
                connection
                    .execute(table_create_cmd)
                    .expect("could not run create table if not exists cmd");
            }

            env::set_var(
                "LD_PRELOAD",
                new_build_so_path
                    .to_str()
                    .expect("could not convert lib dir path to str"),
            );

            env::set_var(
                "MALINSTRACK_DB_PATH",
                tracking_db_path
                    .to_str()
                    .expect("could not convert db path to str"),
            );

            println!(
                "Starting to track identifier: {identifier} at path: {}",
                bin_path_str
            );
            println!("=============================================");

            // Don't care if this program succeeds or fails, that's program specific stuff
            // let bin_path_str = format!("./{bin_path_str}");
            let _ = Command::new(bin_path_str).status();
        }
        Actions::ViewReport { identifier } => {
            println!("Generating report for identifier: {identifier}");
        }
    }

    Ok(())
}

fn check_deps() -> anyhow::Result<()> {
    Command::new("gcc")
        .args(["--version"])
        .status()
        .expect("could not find gcc compiler");

    Command::new("sqlite3")
        .args(["--version"])
        .status()
        .expect("could not find sqlite3");

    Ok(())
}

fn create_shared_object(new_build_so_path: PathBuf) -> anyhow::Result<()> {
    // - [X] Get sample shared lib working with old examples
    // - TODO: [] Get it working with rust-installer.sh

    let curr_working_dir = env::current_dir()?;
    let so_project_dir = Path::join(&curr_working_dir, Path::new("libmalinstrack/"));
    env::set_current_dir(so_project_dir.clone())?;

    // Build shared object
    Command::new("cargo")
        .args(["build", "--release"])
        .status()
        .expect("could not build libmalinstrack");

    let built_so_path = Path::join(
        &so_project_dir,
        Path::new("target/release/libmalinstrack.so"),
    );

    // Place it in central dir
    fs::copy(built_so_path, new_build_so_path)
        .expect("could not move libmalinstrack.so to central dir");

    // TODO: [] Program a small check to see if it's working
    // TODO: [] Add proper error handling in this function

    Ok(())
}
