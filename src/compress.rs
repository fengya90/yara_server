use std::io::{Cursor, Read};
use zip::ZipArchive;

pub async fn extract_first_file_as_bytes(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)?;

    if archive.len() == 0 {
        return Err("Zip archive is empty".into());
    }

    let mut file = archive.by_index(0)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?; // 读全部内容到 Vec<u8>

    Ok(content)
}