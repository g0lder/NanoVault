#![allow(unused_macros)]
#![allow(dead_code)]
mod cff;
mod exploit;
mod img1;
mod mse;
mod payload;

// use crate::exploit::create_cff;
// use crate::payload::exploit_config::{ExploitConfigN6G, ExploitConfigN7G};
use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use isahc::ReadResponseExt;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process::Command;
use tracing::{info, Level};
use zip::ZipArchive;
use std::fs::File;
use std::io::{Write, BufWriter, Seek};
use walkdir::WalkDir;
use zip::write::FileOptions;

#[derive(Debug, ValueEnum, Copy, Clone)]
pub enum Device {
    Nano6,
    Nano7Refresh,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Which device to build a payload for
    #[arg(short, long)]
    device: Device,
}

fn zip_dir<T>(src_dir: &str, target: T) -> zip::result::ZipResult<()>
where
    T: Write + Seek,
{
    #![allow(deprecated)]
    let mut zip_writer = zip::ZipWriter::new(target);
    let options = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o755);

    let walkdir = WalkDir::new(src_dir);
    let mut buffer = Vec::new();

    for entry in walkdir.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(src_dir)).unwrap();

        if path.is_file() {
            println!("Adding file {:?} as {:?}", path, name);
            zip_writer.start_file_from_path(name, options)?;
            let mut f = File::open(path)?;
            f.read_to_end(&mut buffer)?;
            zip_writer.write_all(&buffer)?;
            buffer.clear();
        } else if !name.as_os_str().is_empty() {
            println!("Adding directory {:?}", name);
            zip_writer.add_directory_from_path(name, options)?;
        }
    }
    zip_writer.finish()?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let args = Args::parse();

    /* 
    // Generate exploit font
    info!("Building CFF exploit");
    let bytes = match args.device {
        Device::Nano6 => create_cff::<ExploitConfigN6G>()?,
        Device::Nano7Refresh => create_cff::<ExploitConfigN7G>()?,
    };

    std::fs::write("./in-cff.bin", bytes)?;

    info!("Converting font to OTF");
    Command::new("python3")
        .arg("./helpers/cff_to_otf.py")
        .status()
        .unwrap();

    std::fs::remove_file("./in-cff.bin")?;
    let otf_bytes = std::fs::read("./out-otf.bin")?;
    std::fs::remove_file("./out-otf.bin")?;
    */

    info!("Unpacking MSE");
    let mut mse = if let Device::Nano6 = args.device {
        if !Path::new("./Firmware-36B10147.MSE").try_exists()? {
            let ipsw_file = File::open("myTheme.ipsw")?;
            let mut zip = ZipArchive::new(ipsw_file)?;
            let mut mse = zip.by_name("Firmware.MSE")?;
            let mut out = Vec::new();
            mse.read_to_end(&mut out)?;
            std::fs::write("./Firmware-36B10147.MSE", &out)?;
        }

        mse::unpack("./Firmware-36B10147.MSE", &args.device)
    } else {
        if !Path::new("./Firmware-39A10023.MSE").try_exists()? {
            let ipsw_file = File::open("myTheme.ipsw")?;
            let mut zip = ZipArchive::new(ipsw_file)?;
            let mut mse = zip.by_name("Firmware.MSE")?;
            let mut out = Vec::new();
            mse.read_to_end(&mut out)?;
            std::fs::write("./Firmware-39A10023.MSE", &out)?;
        }

        mse::unpack("./Firmware-39A10023.MSE", &args.device)
    };

    let rsrc = mse
        .sections
        .iter_mut()
        .find(|s| &s.name == b"crsr")
        .ok_or(anyhow!("Failed to find rsrc section in MSE"))?;
    {
        info!("Unpacking RSRC Img1");
        let mut img1 = img1::img1_parse(&rsrc.body, &args.device);
        {
            info!("Patching FATFS");
            std::fs::write("rsrc.bin", &img1.body)?;
            // std::fs::write("in-otf.bin", otf_bytes)?;

            Command::new("python3")
                .arg("./helpers/fat_patch.py")
                .status()?;

            let rsrc_data = std::fs::read("./rsrc.bin")?;
            std::fs::remove_file("./rsrc.bin")?;
            // std::fs::remove_file("./in-otf.bin")?;
            img1.body = rsrc_data;
        }
        info!("Repacking RSRC Img1");
        rsrc.body.clear();
        img1.write(&mut rsrc.body);
    }

    info!("Repacking MSE");
    let mut mse_out = Vec::new();
    mse.write(&mut mse_out);

    // Disk swap
    info!("Doing disk swap");

    if let Device::Nano6 = args.device {
        mse_out[0x5004..][..4].copy_from_slice(b"soso");
        mse_out[0x5144..][..4].copy_from_slice(b"ksid");
        std::fs::write("./iPod_1.2_36B10147/Firmware.MSE", &mse_out)?;
        let src_dir = "./iPod_1.2_36B10147";
        let zip_file_path = "./iPod_1.2_36B10147_repack.ipsw";
    
        let file = File::create(zip_file_path)?;
        let writer = BufWriter::new(file);
    
        match zip_dir(src_dir, writer) {
            Ok(_) => println!("Successfully zipped the directory!"),
            Err(e) => println!("Error zipping the directory: {:?}", e),
        }
    } else {
        mse_out[0x5004..][..4].copy_from_slice(b"soso");
        mse_out[0x5194..][..4].copy_from_slice(b"ksid");
        std::fs::write("./iPod_1.1.2_39A10023_2012/Firmware.MSE", &mse_out)?;
        let src_dir = "./iPod_1.1.2_39A10023_2012";
        let zip_file_path = "./iPod_1.1.2_39A10023_2012_repack.ipsw";
    
        let file = File::create(zip_file_path)?;
        let writer = BufWriter::new(file);
    
        match zip_dir(src_dir, writer) {
            Ok(_) => println!("Successfully zipped the directory!"),
            Err(e) => println!("Error zipping the directory: {:?}", e),
        }

        std::fs::write("./iPod_1.1.2_39A10023_2015/Firmware.MSE", &mse_out)?;
        let src_dir15 = "./iPod_1.1.2_39A10023_2015";
        let zip_file_path15 = "./iPod_1.1.2_39A10023_2015_repack.ipsw";
    
        let file15 = File::create(zip_file_path15)?;
        let writer15 = BufWriter::new(file15);
    
        match zip_dir(src_dir15, writer15) {
            Ok(_) => println!("Successfully zipped the directory!"),
            Err(e) => println!("Error zipping the directory: {:?}", e),
        }
    }

    Ok(())
}
