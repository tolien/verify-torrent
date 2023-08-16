extern crate clap;
extern crate sha1;

use clap::{Arg, Command};

use sha1::{Digest, Sha1};
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::io::Error;

use std::sync::mpsc;
use std::thread;

fn main() {
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

    let mut file;
    if let Some(file_to_read) = matches.get_one::<String>("file") {
        file = File::open(file_to_read).unwrap_or_else(|_| {
            panic!("Couldn't open file");
        });

        println!("{}", format!("Loading file {:?}", file));

        if let Some(piece_size_str) = matches.get_one::<String>("blocksize") {
            let block_size = piece_size_str.parse().unwrap_or_else(|_| {
                panic!("Block size was invalid");
            });

            read_file(&mut file, block_size);
        }
    }
}

fn read_file(file: &mut File, piece_size: u64) {
    let mut piece_hashes: Vec<String> = Vec::new();

    let mut file_size = 0;
    if let Ok(metadata) = file.metadata() {
        file_size = metadata.len();
    };
    let num_pieces: usize = ((file_size) / piece_size).try_into().unwrap();
    let mut total_bytes_read = 0;

    println!("file has size {}", file_size);
    println!("has {} pieces", num_pieces);
    println!("entering read_file");
    let mut i = 0;

    while i < num_pieces {
        let (tx, rx) = mpsc::channel();
        //println!("Piece {} of file", i);
        let mut to_read = piece_size;
        let mut read_bytes = Vec::new();
        // if there aren't enough bytes left in the file
        if file_size < to_read + total_bytes_read {
            //println!("Was going to read {} bytes but there are {} bytes remaining of the file", to_read, file_size - total_bytes_read);
            to_read = file_size - total_bytes_read;
        }
        //println!("Have read {} bytes already, need to read {} bytes to complete the piece", read_bytes.len(), to_read);

        let mut read_buffer = read_bytes_from_file(file, to_read.try_into().unwrap()).unwrap();
        let bytes_read = read_buffer.len();
        total_bytes_read += bytes_read as u64;
        assert_eq!(bytes_read as u64, to_read);
        assert!((read_bytes.len() + bytes_read) as u64 <= piece_size);
        if (read_bytes.len() + bytes_read) as u64 == piece_size {
            read_bytes.append(&mut read_buffer);

            thread::spawn(move || {
                let val = hash_bytes(&read_buffer);
                tx.send(val).unwrap();
            });

            let received = rx.recv().unwrap();
            piece_hashes.push(received);
        }
        i += 1;
    }
    println!(
        "Leaving read_file with {} piece hashes read",
        piece_hashes.len()
    );
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

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha1::digest(bytes))
}
