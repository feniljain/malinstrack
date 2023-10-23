// Malinstrack: Malicious installation tracker

#![feature(fs_try_exists)]

use std::{
    env, fs,
    path::{Path, PathBuf},
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
        /// cmd to track
        cmd_str: String,
    },
    /// view report
    ViewReport { identifier: String },
}

#[derive(Parser)]
#[command(author = "feniljain", version = "0.0.1", about, long_about = None)]
struct Args {
    // /// Turn debugging information on
    // #[arg(short, long, action = clap::ArgAction::Count)]
    // debug: u8,
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

    let args = Args::parse();

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
            cmd_str,
            identifier,
        } => {
            if identifier == "" {
                println!("{}", "invalid identifier: {identifier}".red());
                return Ok(());
            }

            let mut cmd_splits = cmd_str.split_whitespace();
            let root_cmd = cmd_splits.next().expect("could not separate root_cmd");

            let tracking_dir_str = format!(".malinstrack/reports/{identifier}");

            let tracking_dir_path = Path::join(&home_dir_path, Path::new(&tracking_dir_str));
            let db_name = format!("{identifier}.db");
            let tracking_db_path = Path::join(&tracking_dir_path, Path::new(&db_name));

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

                add_linked_shared_libs_to_db(connection, identifier.as_str(), root_cmd.to_string());
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
                "Starting to track identifier: {identifier} cmd: {}",
                cmd_str
            );
            println!("=============================================");

            // Don't care if this program succeeds or fails, that's program specific stuff

            let mut cmd = Command::new(root_cmd);
            cmd_splits.for_each(|ele| {
                cmd.arg(ele);
            });
            let _ = cmd.status();
        }
        Actions::ViewReport { identifier } => {
            // TODO: Include `ldd` output too
            println!("Listing accessed paths for {identifier}");

            let tracking_dir_str = format!(".malinstrack/reports/{identifier}");

            let tracking_dir_path = Path::join(&home_dir_path, Path::new(&tracking_dir_str));
            let db_name = format!("{identifier}.db");
            let tracking_db_path = Path::join(&tracking_dir_path, Path::new(&db_name));

            let connection =
                sqlite::open(tracking_db_path.clone()).expect("could not create or open DB");

            let table_create_cmd = format!("SELECT * FROM {identifier}");
            connection
                .iterate(table_create_cmd, |row| {
                    let path = row[0].1.expect("expected row to be present");
                    println!("{}", path);
                    return true;
                })
                .expect("could not fetch accessed paths");
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

    Ok(())
}

fn add_linked_shared_libs_to_db(
    connection: sqlite::Connection,
    table_name: &str,
    root_cmd: String,
) {
    let mut qualified_path = root_cmd.clone();

    // detect fully qualified or unqualified path
    if !root_cmd.starts_with("./") && !root_cmd.starts_with("../") && !root_cmd.starts_with("/") {
        let which_cmd_stdout = Command::new("which")
            .args([root_cmd])
            .output()
            .expect("could not run which command")
            .stdout;

        let which_cmd_stdout_str = String::from_utf8(which_cmd_stdout)
            .expect("could not convert which cmd output to string");

        qualified_path = which_cmd_stdout_str
            .split("\n")
            .next()
            .expect("could not find any qualified paths, invalid command")
            .to_string();
    }

    let ldd_cmd_stdout = Command::new("ldd")
        .args([qualified_path])
        .output()
        .expect("could not run ldd command")
        .stdout;

    let ldd_cmd_stdout_str =
        String::from_utf8(ldd_cmd_stdout).expect("could not convert ldd cmd output to string");

    ldd_cmd_stdout_str.split("\n").for_each(|path| {
        let trimmed_path = trim_ldd_row_to_only_path(path);
        if is_needed_shared_lib_path(trimmed_path) {
            let table_create_cmd = format!("INSERT INTO {table_name} VALUES({trimmed_path:?})");
            connection
                .execute(table_create_cmd)
                .expect("could not run add one of the ldd given paths to db");
        }
    });
}

fn is_needed_shared_lib_path(path: &str) -> bool {
    return !(path.starts_with("linux-vdso.so") || path.starts_with("libc.so") || path == "");
}

fn trim_ldd_row_to_only_path(path: &str) -> &str {
    let mut row_segments = path.split("=>");

    // for cases like: linux-vdso.so.1
    // directly consider first given path
    //
    // for everything else consider second full path
    let mut row_segment = row_segments
        .next()
        .expect("could not get first part of row");

    if let Some(ele) = row_segments.next() {
        row_segment = ele;
    }

    row_segment
        .split("(")
        .next()
        .expect("could not split to get exact path")
        .trim()
}
