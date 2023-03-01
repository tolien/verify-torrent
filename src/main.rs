extern crate serde;
extern crate serde_bencode;
extern crate sha1;
#[macro_use]
extern crate serde_derive;
extern crate clap;
extern crate serde_bytes;
use clap::{Command, Arg};

use serde_bencode::de;
use serde_bytes::ByteBuf;
use sha1::{Digest};
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::Error;
use std::path::PathBuf;
use std::str;


use log::{debug, error, info, trace};
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Handle;


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
            path: self.path.clone(),
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
    #[serde(rename = "meta version")]
    version: Option<u8>
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

    let matches = Command::new("torrent-verify")
        .arg(
            Arg::new("file")
                .short('f')
                .long("config")
                .help("Path to the torrent file to verify")
                .required(true),
        )
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .help("Quiet mode. Don't show progress.")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("list_type")
                .long("list")
                .help("list files of type")
                .value_parser(["notfound", "bad", "ok", "unverified"])
        )
        .arg(
            Arg::new("list_type")
                .long("list0")
                .help("list files of type, separated by nulls (ideal for xargs)")
                .value_parser(["notfound", "bad", "ok", "unverified"])
        )
        .get_matches();

    if let Some(torrent_file) = matches.get_one::<String>("file") {
        let mut file = File::open(torrent_file).unwrap_or_else(|_| {
            panic!("Couldn't open torrent");
        });

        let quiet_mode = matches.get_flag("quiet");
        bootstrap_logger(quiet_mode);
        info!("Quiet mode is set to {:?}", quiet_mode);

        info!("{}", format!("Checking torrent {:?}", torrent_file));
        let mut buffer = Vec::new();
        match file.read_to_end(&mut buffer) {
            Ok(_) => match de::from_bytes::<Torrent>(&buffer) {
                Ok(t) => verify_torrent(&t).await,
                Err(e) => error!("ERROR: {:?}", e),
            },
            Err(e) => error!("ERROR: {:?}", e),
        }
    }
}

async fn verify_torrent(torrent: &Torrent) {
    let file_list = get_file_list(torrent);
    let piece_size = get_piece_size(torrent);
    let piece_hashes = get_piece_hashes(torrent);

    debug!(
        "{} files, piece size {} bytes, {} pieces",
        file_list.len(),
        piece_size,
        piece_hashes.len()
    );
    let pieces = calculate_hashes(&file_list, piece_size, &piece_hashes).await;

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
                info!("{}", format!("{:?}", file.path));
                valid += 1;
            } else {
                println!("{:?} is not valid", file.path);
                invalid += 1;
            }
        }
        info!("{} ok, {} not ok", valid, invalid);
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
            let pieces_result = read_file(
                &mut buffer,
                file,
                piece_size,
                &pieces[start_piece..pieces.len()],
            )
            .await;
            if let Ok(mut pieces_for_file) = pieces_result {

                total_bytes_read += file.size;
                debug!(
                    "Read {} pieces, buffer length is {} bytes",
                    pieces_for_file.len(),
                    buffer.len()
                );
                piece_hashes.append(&mut pieces_for_file);
                let total_pieces: usize = (total_bytes_read / piece_size).try_into().unwrap();
                debug!("Total bytes read: {}, file size: {}", total_bytes_read, file.size);
                if total_pieces > piece_hashes.len() {
                    trace!(
                        "Should have read {} pieces by now - have actually read {}.",
                        total_pieces,
                        piece_hashes.len()
                    );
                    for _i in 0..total_pieces - piece_hashes.len() {
                        piece_hashes.push("".to_string());
                    }
                    let expected_buffer_size = total_bytes_read % piece_size;
                    assert!(expected_buffer_size < piece_size);
                    if buffer.len() as u64 != expected_buffer_size {
                        buffer.clear();
                        trace!("Should have {} bytes in the buffer, actually have {} bytes", expected_buffer_size, buffer.len());
                        let mut buffer_pad = vec![0; expected_buffer_size.try_into().unwrap()];
                        buffer.append(&mut buffer_pad);
                    }
                }
            }
            else {

            };
        }

        if !buffer.is_empty() || pieces.len() - piece_hashes.len() == 1 {
            trace!("Buffer length is {} bytes", buffer.len());
            piece_hashes.push(hash_bytes(&buffer));
        }
    }

    piece_hashes
}

async fn read_file(
    buffer: &mut Vec<u8>,
    file: &TorrentDataFile,
    piece_size: u64,
    pieces: &[String],
) -> Result<Vec<String>, Error> {
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

    debug!("file: {:?}, size {}", &file.path, file.size);
    trace!("has {} pieces", num_pieces);
    trace!("entering read_file with buffer size {} bytes", buffer.len());
    if file_size == file.size as u64 {
        let mut start_file = File::open(&file.path).unwrap();
        let mut futures = Vec::new();
        let mut file_invalid = false;
        let mut i = 0;
        while !file_invalid && i < num_pieces {
            if i > 0 {
                assert!(buffer.is_empty());
            }
            //println!("Piece {} of file", i);
            let mut to_read = piece_size;
            let mut read_bytes = Vec::new();
            if !buffer.is_empty() {
                if buffer.len() as u64 > piece_size {
                    //println!("Buffer has {} bytes, this is bigger than the piece size of {} bytes (by {} bytes). This is broken somewhere.", buffer.len(), piece_size, buffer.len() as u64 - piece_size);
                }
                assert!(buffer.len() as u64 <= piece_size);
                read_bytes.append(buffer);
                to_read -= read_bytes.len() as u64;
            }
            // if there aren't enough bytes left in the file
            if file.size < to_read + total_bytes_read {
                //println!("Was going to read {} bytes but there are {} bytes remaining of the file", to_read, file.size - total_bytes_read);
                to_read = file.size - total_bytes_read;
            }
            //println!("Have read {} bytes already, need to read {} bytes to complete the piece", read_bytes.len(), to_read);

            let mut read_buffer = read_bytes_from_file(&mut start_file, to_read.try_into().unwrap()).unwrap();
            let bytes_read = read_buffer.len();
            total_bytes_read += bytes_read as u64;
            assert_eq!(bytes_read as u64, to_read);
            assert!((read_bytes.len() + bytes_read) as u64 <= piece_size);
            if (read_bytes.len() + bytes_read) as u64 == piece_size {
                read_bytes.append(&mut read_buffer);
                let digest_future = hash_bytes(&read_bytes);
                let result = tokio::spawn(async move {
                    let digest = digest_future;
                    let mut _hashes: Vec<String> = vec![String::new(); num_pieces];
                    digest
                });
                if i == 0 {
                    let digest = result.await.unwrap();
                    if digest != pieces[i] {
                        debug!("Expected: {}, actual: {}", pieces[i], digest);
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
            let pieces_to_fill = (piece_offset_from_file_start + ((num_pieces - 2) as u64 * piece_size)) / piece_size;

            trace!("File is invalid, have read {} bytes", total_bytes_read);
            let skip_to_bytes =
                total_bytes_read as u64 + (pieces_to_fill * piece_size) as u64;
            trace!(
                "Have read {} bytes including, there are {} pieces outstanding",
                total_bytes_read, pieces_to_fill
            );
            assert!(skip_to_bytes > 0);
            assert!(skip_to_bytes < file.size as u64);

            debug!("Seeking to {} bytes from the start of the file.", skip_to_bytes);
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
        debug!("Expected file size {} - actual file size {}", file.size, file_size);
        buffer.clear();
    }
    trace!("Leaving read_file with {} bytes in the buffer", buffer.len());
    Ok(piece_hashes)
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

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = sha1::Sha1::new();
    trace!("Hashing {} bytes", bytes.len());
    hasher.update(bytes);
    format!("{:X}", hasher.finalize()).to_lowercase()
}

fn bootstrap_logger(quiet_mode: bool) -> Handle {

    let level = if quiet_mode {
        LevelFilter::Off
    }
    else {
        LevelFilter::Info
    };
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}][{h({l})}] {m}{n}",
        )))
        .build();

    let stdout_appender = Appender::builder().build("stdout", Box::new(stdout));
    let config = log4rs::config::Config::builder()
        .appender(stdout_appender)
        .logger(
            Logger::builder()
                .appender("stdout")
                .additive(false)
                .build("stdout_log", LevelFilter::Trace),
        )
        .build(Root::builder().appender("stdout").build(level))
        .unwrap();

    log4rs::init_config(config).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::hash_bytes;
    use hex_literal::hex;
    use sha1::{Sha1, Digest};

    #[test]
    fn hash_and_encoding() {
        let bytes = b"Nobody inspects the spammish repetition";

       let mut hasher = Sha1::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        assert_eq!(result.as_slice(), hex!("531b07a0f5b66477a21742d2827176264f4bbfe2"));
        assert_eq!(hash_bytes(bytes), "531b07a0f5b66477a21742d2827176264f4bbfe2");
    }        
}
