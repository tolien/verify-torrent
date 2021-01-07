extern crate serde;
extern crate serde_bencode;
extern crate sha1;
#[macro_use]
extern crate serde_derive;
extern crate clap;
extern crate serde_bytes;
use clap::{App, Arg};
use serde_bencode::de;
use serde_bytes::ByteBuf;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Node(String, u64);

#[derive(Debug, Deserialize)]
struct TorrentFile {
    path: Vec<String>,
    #[serde(rename = "length")]
    size: i64,
    #[serde(default)]
    md5sum: Option<String>,
}
impl Eq for TorrentFile {}
impl PartialEq for TorrentFile {
    fn eq(&self, other: &Self) -> bool {
        let self_path = self.path.join("/");
        let other_path = other.path.join("/");
        self.size == other.size && self_path == other_path
    }
}
impl Clone for TorrentFile {
    fn clone(&self) -> Self {
        let mut md5sum = None;
        if self.md5sum.is_some() {
            let md5sum_str = self.md5sum.as_ref();
            md5sum = Some(String::from(md5sum_str.unwrap()));
        }
        Self {
            path: self.path.to_owned(),
            size: self.size,
            md5sum,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Info {
    name: String,
    pieces: ByteBuf,
    #[serde(rename = "piece length")]
    piece_length: u64,
    #[serde(default)]
    md5sum: Option<String>,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    files: Option<Vec<TorrentFile>>,
    #[serde(default)]
    private: Option<u8>,
    #[serde(default)]
    path: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "root hash")]
    root_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Torrent {
    info: Info,
    #[serde(default)]
    announce: Option<String>,
    #[serde(default)]
    nodes: Option<Vec<Node>>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    httpseeds: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "announce-list")]
    announce_list: Option<Vec<Vec<String>>>,
    #[serde(default)]
    #[serde(rename = "creation date")]
    creation_date: Option<u64>,
    #[serde(rename = "comment")]
    comment: Option<String>,
    #[serde(default)]
    #[serde(rename = "created by")]
    created_by: Option<String>,
}

#[tokio::main]
async fn main() {
    let matches = App::new("torrent-verify")
        .arg(
            Arg::with_name("file")
                .short("-f")
                .help("Path to the torrent file to verify")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    if let Some(torrent_file) = matches.value_of("file") {
        let mut file = File::open(torrent_file).unwrap_or_else(|_| {
            panic!("Couldn't open torrent");
        });
        println!("{}", format!("Checking torrent {:?}", torrent_file));
        let mut buffer = Vec::new();
        match file.read_to_end(&mut buffer) {
            Ok(_) => match de::from_bytes::<Torrent>(&buffer) {
                Ok(t) => verify_torrent(&t).await,
                Err(e) => println!("ERROR: {:?}", e),
            },
            Err(e) => println!("ERROR: {:?}", e),
        }
    }
}

async fn verify_torrent(torrent: &Torrent) {
    let file_list = get_file_list(torrent);
    let piece_size = get_piece_size(torrent);
    let piece_hashes = get_piece_hashes(torrent);

    println!(
        "{} files, pieces size {} bytes, {} pieces",
        file_list.len(),
        piece_size,
        piece_hashes.len()
    );
    let pieces = calculate_hashes(&file_list, piece_size, &piece_hashes).await;

    /*for i in 0..pieces.len() {
        let known_hash = &pieces[i];
        let calculated_hash = &piece_hashes[i];
        if known_hash != calculated_hash {
            //println!("{}: {} - {}", i, known_hash, calculated_hash);
        }
    }*/
    check_files(&file_list, pieces, &piece_hashes, piece_size);
}

fn check_files(
    file_list: &Vec<TorrentDataFile>,
    pieces: Vec<String>,
    piece_hashes: &Vec<String>,
    piece_size: u64,
) {
    assert!(piece_size > 0);
    if piece_hashes.len() != pieces.len() {
        /*println!(
            "{}",
            format!(
                "Number of pieces expected ({}) versus calculated ({}) is not the same",
                piece_hashes.len(),
                pieces.len()
            )
        );*/
    } else {
        let mut total_bytes = 0;
        let mut matched;
        for file in file_list {
            matched = true;
            let start_piece = total_bytes / piece_size;
            let end_piece =
                ((total_bytes as f64 + file.size as f64) / piece_size as f64).ceil() as u64;
            total_bytes = total_bytes + file.size as u64;
            for i in start_piece..end_piece {
                if piece_hashes[i as usize] != pieces[i as usize] {
                    matched = false;
                }
            }
            if matched {
                println!("{}", format!("{:?}", file.path));
            } else {
                //println!("{:?} is not valid", file.path);
            }
        }
    }
}

#[derive(Debug)]
pub struct TorrentDataFile {
    path: PathBuf,
    size: i64,
    md5sum: Option<String>,
}
fn get_file_list(torrent: &Torrent) -> Vec<TorrentDataFile> {
    let mut files = Vec::new();

    if let Some(file_list) = &torrent.info.files {
        for file in file_list {
            let mut path = PathBuf::new();
            if torrent.info.name.len() > 0 {
                path.push(&torrent.info.name);
            }
            for part in &file.path {
                path.push(part);
            }

            let mut md5sum = None;
            if file.md5sum.is_some() {
                let sum_string = file.md5sum.as_ref().unwrap();
                md5sum = Some(String::from(sum_string));
            }
            let torrent_file = TorrentDataFile {
                path,
                size: file.size,
                md5sum,
            };
            files.push(torrent_file);
        }
    } else {
        let mut path = PathBuf::new();
        path.push(&torrent.info.name);
        let mut md5sum = None;
        if torrent.info.md5sum.is_some() {
            let sum_string = torrent.info.md5sum.as_ref().unwrap();
            md5sum = Some(String::from(sum_string));
        }
        let torrent_file = TorrentDataFile {
            path,
            size: torrent.info.length.unwrap() as i64,
            md5sum,
        };
        files.push(torrent_file);
    }
    files
}

fn get_piece_size(torrent: &Torrent) -> u64 {
    torrent.info.piece_length
}
fn get_piece_hashes(torrent: &Torrent) -> Vec<String> {
    let mut hashes = Vec::new();
    for x in (0..torrent.info.pieces.len()).step_by(20) {
        let slice = &torrent.info.pieces[x..x + 20];
        let hash = slice
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        hashes.push(hash);
    }

    hashes
}

async fn calculate_hashes(
    file_list: &Vec<TorrentDataFile>,
    piece_size: u64,
    pieces: &Vec<String>,
) -> Vec<String> {
    let mut piece_hashes = Vec::new();
    if file_list.len() > 0 {
        let mut buffer = Vec::new();

        let mut start_piece = 0;
        let mut total_bytes_read = 0;
        for file in file_list {
            let end_piece = start_piece + (file.size as f64 / piece_size as f64).ceil() as usize;
            /*println!(
                "File {:?} pieces {} to {}",
                file.path, start_piece, end_piece
            );*/
            let mut pieces_for_file = read_file(
                &mut buffer,
                file,
                piece_size,
                &pieces[start_piece..pieces.len()],
            )
            .await;
            total_bytes_read += file.size;
            /*println!(
                "Read {} pieces, buffer length is {} bytes",
                pieces_for_file.len(),
                buffer.len()
            );*/
            piece_hashes.append(&mut pieces_for_file);
            let total_pieces = (total_bytes_read / piece_size as i64) as usize;
            if total_pieces > piece_hashes.len() {
                /*println!(
                    "Should have read {} pieces by now - have actually read {}.",
                    total_pieces,
                    piece_hashes.len()
                );*/
                for _i in 0..total_pieces - piece_hashes.len() {
                    piece_hashes.push("".to_string());
                }
                let buffer_size = total_bytes_read - (total_pieces * piece_size as usize) as i64;
                //println!("Should have {} bytes in the buffer", buffer_size);
                let mut buffer_pad = vec![0; buffer_size as usize];
                buffer.append(&mut buffer_pad);
            }
            start_piece = piece_hashes.len();
        }

        if buffer.len() > 0 || pieces.len() - piece_hashes.len() == 1 {
            //println!("Appending final piece");
            //println!("Buffer length is {} bytes", buffer.len());
            piece_hashes.push(hash_bytes(buffer).await);
        }
    }

    piece_hashes
}

async fn read_file(
    buffer: &mut Vec<u8>,
    file: &TorrentDataFile,
    piece_size: u64,
    pieces: &[String],
) -> Vec<String> {
    let mut piece_hashes = Vec::new();

    let start_piece = 0;
    let end_piece = start_piece
        + ((buffer.len() + file.size as usize) as f64 / piece_size as f64).ceil() as u64;
    let num_pieces = (end_piece - start_piece) as usize;

    let mut file_size = 0;
    if let Ok(metadata) = fs::metadata(&file.path) {
        file_size = metadata.len();
    };
    let mut total_bytes_read = 0;

    if file_size != file.size as u64 {
        println!(
            "Skipping {:?}: file size {} != {}",
            file.path, file_size, file.size
        );
        buffer.clear();
    } else {
        println!(
            "Will read {} pieces from {:?} - size {}",
            end_piece - start_piece,
            file.path,
            file_size
        );
        let mut start_file = File::open(&file.path).unwrap();
        let mut futures = Vec::new();
        let mut file_invalid = false;
        for i in 0..num_pieces {
            let mut to_read = piece_size as usize;
            let mut read_bytes = Vec::new();
            if !buffer.is_empty() {
                println!("Buffer has {} bytes", buffer.len());
                assert!(buffer.len() <= piece_size as usize);
                read_bytes.append(buffer);
                to_read = to_read - read_bytes.len();
                println!("Will need to read {} bytes to complete the piece", to_read);
            }
            if file.size - total_bytes_read < piece_size as i64 {
                to_read = (file.size - total_bytes_read) as usize;
                println!(
                    "Setting read buffer to {} bytes to avoid running off file end",
                    to_read
                );
            }
            let mut read_buffer = vec![0; to_read];
            let bytes_read = start_file.read(&mut read_buffer).unwrap();
            total_bytes_read += bytes_read as i64;
            if read_bytes.len() + bytes_read == piece_size as usize {
                read_bytes.append(&mut read_buffer);
                let digest_future = hash_bytes(read_bytes);
                let result = tokio::spawn(async move {
                    let digest = digest_future.await;
                    let mut _hashes: Vec<String> = vec![String::new(); num_pieces];
                    digest
                });
                if i == 0 {
                    let digest = result.await.unwrap();
                    piece_hashes.push(digest);
                } else {
                    futures.push(result);
                }
                buffer.clear();
            } else if bytes_read > 0 {
                buffer.clear();
                println!(
                    "Couldn't read a full piece, filling buffer with {} bytes",
                    bytes_read
                );
                buffer.append(&mut read_bytes);
                read_buffer.truncate(bytes_read + 1);
                buffer.append(&mut read_buffer);
            }
        }

        for future in futures {
            piece_hashes.push(future.await.unwrap());
        }
        assert_eq!(total_bytes_read as u64, file_size);
    }

    piece_hashes
}

async fn hash_bytes(bytes: Vec<u8>) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(&bytes);
    hasher.digest().to_string()
}
