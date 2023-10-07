// Malinstrack: Malicious installation tracker

use std::{
    fs,
    path::{self, Path},
    process::Command,
};

use clap::{Parser, Subcommand};
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

    // TODO: Set debug mode

    match args.action {
        Actions::Setup => {
            println!("Starting setup");

            let mut dir_creation_sp = Spinner::new(
                Spinners::Dots9,
                "creating dirs for handling everything related to malinstrack\n".into(),
            );

            #[allow(deprecated)]
            let home_dir_path = std::env::home_dir().expect("Expected home dir path");
            let reports_dir_path = Path::join(&home_dir_path, Path::new(".malinstrack/reports/"));
            fs::create_dir_all(reports_dir_path)?;
            dir_creation_sp.stop();
            println!("finished creating dirs ✅");
            println!();

            println!("=============================================");
            println!("finding gcc by asking for it's version, output:");
            // TODO: Create shared object
            check_build_deps()?;
            println!("=============================================");
            println!();

            println!("setup completed :)");
            println!("let's track those malicious actors down!");
        }
        Actions::Track { path, identifier } => {
            // fs::write("~/.malinstrack/reports/iden", "")?;
            println!(
                "Starting to track identifier: {identifier} at path: {}",
                path.to_str()
                    .expect("could not print path, what did you pass bruhh")
            );
        }
        Actions::ViewReport { identifier } => {
            println!("Generating report for identifier: {identifier}");
        }
    }

    Ok(())
}

fn check_build_deps() -> anyhow::Result<()> {
    Command::new("gcc")
        .args(["--version"])
        .status()
        .expect("could not find gcc compiler");

    Ok(())
}

fn create_shared_object() -> anyhow::Result<()> {
    // - [] Get sample shared lib working with old examples
    // - [] Get it working with rust-installer.sh
    Ok(())
}
