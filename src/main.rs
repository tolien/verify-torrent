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
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::Error;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Node(String, u64);

#[derive(Debug, Deserialize)]
struct TorrentFile {
    path: Vec<String>,
    #[serde(rename = "length")]
    size: u64,
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
        "{} files, piece size {} bytes, {} pieces",
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
    check_files(&file_list, &pieces, &piece_hashes, piece_size);
}

fn check_files(
    file_list: &[TorrentDataFile],
    pieces: &[String],
    piece_hashes: &[String],
    piece_size: u64,
) {
    assert!(piece_size > 0);
    if piece_hashes.len() == pieces.len() {
        let mut total_bytes = 0;
        let mut matched;
        let mut valid = 0;
        let mut invalid = 0;
        for file in file_list {
            matched = true;
            let start_piece = total_bytes / piece_size;
            let mut end_piece = (total_bytes + file.size as u64) / piece_size;
            if (total_bytes + file.size as u64) % piece_size > 0 {
                end_piece += 1;
            }
            total_bytes += file.size as u64;
            for i in start_piece..end_piece {
                let index: usize = i.try_into().unwrap();
                if piece_hashes.get(index) != pieces.get(index) {
                    matched = false;
                }
            }
            if matched {
                println!("{}", format!("{:?}", file.path));
                valid += 1;
            } else {
                //println!("{:?} is not valid", file.path);
                invalid += 1;
            }
        }
        println!("{} ok, {} not ok", valid, invalid);
    }
}

#[derive(Debug)]
pub struct TorrentDataFile {
    path: PathBuf,
    size: u64,
    md5sum: Option<String>,
}
fn get_file_list(torrent: &Torrent) -> Vec<TorrentDataFile> {
    let mut files = Vec::new();

    if let Some(file_list) = &torrent.info.files {
        for file in file_list {
            let mut path = PathBuf::new();
            if !torrent.info.name.is_empty() {
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
            size: torrent.info.length.unwrap() as u64,
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
    file_list: &[TorrentDataFile],
    piece_size: u64,
    pieces: &[String],
) -> Vec<String> {
    let mut piece_hashes = Vec::new();
    if !file_list.is_empty() {
        let mut buffer = Vec::new();

        let mut total_bytes_read: u64 = 0;
        for file in file_list {
            let start_piece: usize = (total_bytes_read / piece_size).try_into().unwrap();
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
            let total_pieces: usize = (total_bytes_read / piece_size).try_into().unwrap();
            if total_pieces > piece_hashes.len() {
                /*println!(
                    "Should have read {} pieces by now - have actually read {}.",
                    total_pieces,
                    piece_hashes.len()
                );*/
                for _i in 0..total_pieces - piece_hashes.len() {
                    piece_hashes.push("".to_string());
                }
                let expected_buffer_size = total_bytes_read % piece_size;
                assert!(expected_buffer_size < piece_size);
                if buffer.len() as u64 != expected_buffer_size {
                    buffer.clear();
                    println!("Should have {} bytes in the buffer, actually have {} bytes", expected_buffer_size, buffer.len());
                    let mut buffer_pad = vec![0; expected_buffer_size.try_into().unwrap()];
                    buffer.append(&mut buffer_pad);
                }
            }
        }

        if !buffer.is_empty() || pieces.len() - piece_hashes.len() == 1 {
            //println!("Appending final piece");
            println!("Buffer length is {} bytes", buffer.len());
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

    let mut num_pieces: usize = ((buffer.len() as u64 + file.size) / piece_size)
        .try_into()
        .unwrap();
    if (buffer.len() as u64 + file.size) % piece_size > 0 {
        num_pieces += 1;
    }

    let mut file_size = 0;
    if let Ok(metadata) = fs::metadata(&file.path) {
        file_size = metadata.len();
    };
    let mut total_bytes_read = 0;

    let piece_offset_from_file_start = if buffer.is_empty() { 0 } else { piece_size - buffer.len() as u64 };

    if file_size == file.size as u64 {
        let mut start_file = File::open(&file.path).unwrap();
        let mut futures = Vec::new();
        let mut file_invalid = false;
        let mut i = 0;
        while !file_invalid && i < num_pieces {
            let mut to_read = piece_size;
            let mut read_bytes = Vec::new();
            if !buffer.is_empty() {
                assert!(buffer.len() as u64 <= piece_size);
                read_bytes.append(buffer);
                to_read -= read_bytes.len() as u64;
            }
            if file.size - total_bytes_read < piece_size as u64 {
                to_read = file.size - total_bytes_read;
            }

            let mut read_buffer = read_bytes_from_file(&mut start_file, to_read.try_into().unwrap()).unwrap();
            let bytes_read = read_buffer.len();
            total_bytes_read += bytes_read as u64;
            if (read_bytes.len() + bytes_read) as u64 == piece_size {
                read_bytes.append(&mut read_buffer);
                let digest_future = hash_bytes(read_bytes);
                let result = tokio::spawn(async move {
                    let digest = digest_future.await;
                    let mut _hashes: Vec<String> = vec![String::new(); num_pieces];
                    digest
                });
                if i == 0 {
                    let digest = result.await.unwrap();
                    if digest != pieces[i] {
                        println!("Expected: {}, actual: {}", pieces[i], digest);
                        file_invalid = true;
                    }
                    piece_hashes.push(digest);
                } else {
                    futures.push(result);
                }
                buffer.clear();
            } else if bytes_read > 0 {
                buffer.clear();
                buffer.append(&mut read_bytes);
                read_buffer.truncate(bytes_read + 1);
                buffer.append(&mut read_buffer);
            }
            i += 1;
        }

        if file_invalid {
            let pieces_to_fill: usize = ((piece_offset_from_file_start + ((num_pieces - 2) as u64 * piece_size)) / piece_size) as usize;

            println!("File is invalid, have read {} bytes", total_bytes_read);
            let skip_to_bytes =
                total_bytes_read as u64 + (pieces_to_fill as u64 * piece_size) as u64;
            println!(
                "Have read {} bytes, there are {} pieces outstanding",
                total_bytes_read, pieces_to_fill
            );
            assert!(skip_to_bytes > 0);
            assert!(skip_to_bytes < file.size as u64);

            start_file.seek(SeekFrom::Start(skip_to_bytes)).unwrap();

            let to_read = file.size - skip_to_bytes;
            let mut read_buffer= read_bytes_from_file(&mut start_file, to_read.try_into().unwrap()).unwrap();
            buffer.clear();
            buffer.append(&mut read_buffer);
            assert_eq!(buffer.len() as u64, to_read);
        } else {
            for future in futures {
                piece_hashes.push(future.await.unwrap());
            }
            assert_eq!(total_bytes_read as u64, file_size);
        }
    } else {
        buffer.clear();
    }
    piece_hashes
}

fn read_bytes_from_file(file: &mut File, bytes_to_read: usize) -> Result<Vec<u8>, Error> {
    let mut read_buffer = vec![0; bytes_to_read];
    let read_result = file.read(&mut read_buffer);
    if read_result.is_ok() {
        Ok(read_buffer)
    }
    else {
        Err(read_result.err().unwrap())
    }
}

async fn hash_bytes(bytes: Vec<u8>) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(&bytes);
    hasher.digest().to_string()
}
