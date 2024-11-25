This project is a BitTorrent implementation in Rust, focusing on the following key phases:

1. **Decoding:**

   - Decode integers, strings, lists, and other elements in accordance with the BitTorrent protocol.

2. **Torrent File Parsing and Hash Calculation:**

   - Parse the contents of a torrent file, extracting necessary information such as file names, file sizes, and the list of trackers.
   - Calculate the hashes of the file pieces using the specified hashing algorithm (e.g., SHA-1).

3. **Peer Handshake and Content Downloading:**
   - Establish a handshake with peers according to the BitTorrent protocol.
   - Implement the logic for downloading content from multiple peers concurrently.

