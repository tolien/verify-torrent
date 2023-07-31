extern crate clap;
extern crate sha1;
use clap::{Arg, Command};

use sha1::{Digest, Sha1};
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::Error;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::str;

#[tokio::main]
async fn main() {
    let matches = Command::new("torrent-verify")
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .help("File to read")
                .required(true),
        )
        .arg(
            Arg::new("blocksize")
                .long("blocksize")
                .short('b')
                .help("Block size to read")
                .required(true),
        )
        .get_matches();

    if let Some(file_to_read) = matches.get_one::<String>("file") {
        let mut file = File::open(file_to_read).unwrap_or_else(|_| {
            panic!("Couldn't open file");
        });

        println!("{}", format!("Loading file {:?}", file));
    }
}

async fn read_file(file: &File, piece_size: u64) {
    let mut piece_hashes = Vec::new();

    let mut num_pieces: usize = ((buffer.len() as u64 + file.size) / piece_size)
        .try_into()
        .unwrap();

    let mut file_size = 0;
    if let Ok(metadata) = fs::metadata(&file.path) {
        file_size = metadata.len();
    };
    let mut total_bytes_read = 0;

    debug!("file: {:?}, size {}", &file.path, file.size);
    trace!("has {} pieces", num_pieces);
    trace!("entering read_file with buffer size {} bytes", buffer.len());
    if file_size == file.size as u64 {
        let mut start_file = File::open(&file.path).unwrap();
        let mut futures = Vec::new();
        let mut file_invalid = false;
        let mut i = 0;
        while !file_invalid && i < num_pieces {
            //println!("Piece {} of file", i);
            let mut to_read = piece_size;
            let mut read_bytes = Vec::new();
            // if there aren't enough bytes left in the file
            if file_size < to_read + total_bytes_read {
                //println!("Was going to read {} bytes but there are {} bytes remaining of the file", to_read, file_size - total_bytes_read);
                to_read = file_size - total_bytes_read;
            }
            //println!("Have read {} bytes already, need to read {} bytes to complete the piece", read_bytes.len(), to_read);

            let mut read_buffer =
                read_bytes_from_file(&mut start_file, to_read.try_into().unwrap()).unwrap();
            let bytes_read = read_buffer.len();
            total_bytes_read += bytes_read as u64;
            assert_eq!(bytes_read as u64, to_read);
            assert!((read_bytes.len() + bytes_read) as u64 <= piece_size);
            if (read_bytes.len() + bytes_read) as u64 == piece_size {
                read_bytes.append(&mut read_buffer);
                let digest_future = async move { hash_bytes(&read_bytes).await };
            }
            i += 1;
        }
    }
}

fn read_bytes_from_file(file: &mut File, bytes_to_read: usize) -> Result<Vec<u8>, Error> {
    let mut read_buffer = vec![0; bytes_to_read];
    let read_result = file.read(&mut read_buffer);
    if read_result.is_ok() {
        Ok(read_buffer)
    } else {
        Err(read_result.err().unwrap())
    }
}

async fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha1::digest(bytes))
}
