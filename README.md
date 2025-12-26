# NXErase

[![Rust](https://img.shields.io/badge/Made_with-Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://www.kernel.org/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)]()

**NXErase** is a secure deletion utility designed to protect sensitive data from theft, malware, and unauthorized recovery, specifically optimized for the era of **Solid State Drives (SSDs)**, **NVMe**, and **Full Disk Encryption**.

While traditional tools (`shred`, `srm`, `dd`) were built for spinning hard drives, NXErase addresses the specific challenges of flash storage (specifically **Wear Leveling** and **Garbage Collection**) by combining cryptographic overwriting with hardware-aware command sets to ensure deleted files cannot be retrieved by bad actors.

---

## 📑 Table of Contents
- [Why NXErase?](#-why-nxerase-the-nvme-advantage)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Technical Architecture](#-technical-architecture)
- [Security & Safety Mechanisms](#-security--safety-mechanisms)
- [Limitations](#-limitations)
- [License](#-license)

---

## ⚡ Why NXErase? (The NVMe Advantage)

Legacy tools are becoming dangerous placebos on modern hardware. When `shred` overwrites a file on an SSD, the drive's firmware (Wear Leveling) often writes the new random data to *new* physical cells to preserve drive health. The original data remains in the old cells until the drive decides to garbage collect them, leaving a window of opportunity for malware or data thieves to recover the information.

**NXErase fixes this by using a 3-stage destruction process:**

1.  **Overwrite:** Writes cryptographically strong random noise to the logical address.
2.  **Punch Hole (The SSD Fix):** Issues a `FALLOC_FL_PUNCH_HOLE` syscall. On supported filesystems (Ext4, Btrfs, XFS), this sends an immediate **TRIM/DISCARD** command to the controller, explicitly marking the physical blocks as invalid/garbage.
3.  **Obfuscate:** Renames the file to a random string before unlinking to hide metadata.

**Comparison:**

| Feature | **NXErase** | `shred` / `srm` | `rm` |
| :--- | :--- | :--- | :--- |
| **Storage Target** | **NVMe / SSD / HDD** | Spinning HDD | Generic |
| **Method** | Crypto Overwrite + **TRIM** | Overwrite Only | Unlink Only |
| **Recovery Protection** | **High** (Force GC + Obfuscation) | **Low on SSD** | None |
| **Speed** | **Multi-threaded** (Rayon) | Single-threaded | Instant |
| **Sanitization**| **Yes** (Crypto Erase) | No | No |
| **Immutable Files** | **Auto-unlocks** (`chattr -i`) | Fails | Fails |

---

## 🚀 Key Features

*   **Parallel Execution:** Uses a thread pool (`rayon`) to wipe thousands of small files instantly, saturating the high command queue depth of modern NVMe drives.
*   **NVMe Sanitize Mode:** Interfaces directly with the drive controller to perform instant **Crypto Erase** (destroys the internal encryption key) or **Block Erase** (wipes all NAND).
*   **Immutable File Handling:** Automatically detects `chattr +i` (locked) files. If run as root, it uses raw IOCTLs to unlock, wipe, and remove them transparently.
*   **Audit Logging:** Optional `--log-file` produces timestamped logs for compliance and audit trails.
*   **Memory Safe:** Uses streaming iterators to handle directories containing millions of files without crashing system RAM.

---

## 📦 Installation

### Prerequisites
*   **Rust (Cargo):** To compile from source.
*   **nvme-cli:** Required only if you plan to use the `--sanitize` feature.

### Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/nxerase.git
cd nxerase

# 2. Build Release Binary
cargo build --release

# 3. Install to system path
sudo cp target/release/nxerase /usr/local/bin/
sudo chmod +x /usr/local/bin/nxerase
```

### Dependencies (Optional)

If you need the Device Sanitization feature:
```bash
# Debian/Ubuntu
sudo apt install nvme-cli

# Fedora
sudo dnf install nvme-cli

# Arch Linux
sudo pacman -S nvme-cli
```
---

## 🛠 Usage

### File Deletion (Standard Mode)

Securely wipe files or directories. Safe to use on mounted filesystems.
```bash
# Wipe a single file
nxerase secret.pdf

# Wipe a directory recursively (multi-threaded)
nxerase -r private_photos/

# Wipe with audit logging enabled
nxerase --log-file /var/log/wipe.log sensitive_data/
```

### Device Sanitization (Destructive)

WARNING: This destroys ALL data on the entire drive. Requires root.
```bash
# Instant Crypto Erase (Recommended for NVMe)
# This destroys the drive's internal encryption key, making data unrecoverable instantly.
sudo nxerase --sanitize --device /dev/nvme0n1
```
### Command Line Options

Flag	Description
```bash
-j, --jobs <N>	Number of worker threads (Default: Logical CPU count).

--throttle <MS>	Sleep <MS> milliseconds between 1MB chunks (reduces thermal load).

--no-progress	Disable the interactive progress bar (recommended for scripts).

--allow-hardlinks	Force overwriting of files with multiple hard links.

-n, --dry-run	Simulate the operation without deleting anything.

--log-file <PATH>	Append audit logs to the specified file.
```
----------

## 🧠 Technical Architecture

For every file processed, NXErase performs a rigorous pipeline designed to defeat forensic recovery:

1.  **TOCTOU Verification:** Opens the file using O_NOFOLLOW and verifies Inode/Device IDs to prevent Time-of-Check Time-of-Use race conditions.
    
2.  **Unlock:** Checks FS_IMMUTABLE_FL via ioctl. If set, clears it (requires root).
    
3.  **Overwrite:** Fills the file with random data generated by the OS CSPRNG (OsRng).
    
4.  **Discard:** Calls fallocate with FALLOC_FL_PUNCH_HOLE. This triggers the SSD firmware to mark blocks as garbage immediately.
    
5.  **Obfuscate:** Renames the file to a random 12-char string (e.g., .tmp_a8z91lx) while holding the file descriptor.
    
6.  **Unlink:** Removes the obfuscated inode.
    

----------

## 🛡 Security & Safety Mechanisms

NXErase is built with a "Safety First" philosophy:

-   **Symlink Protection:** Explicitly checks lstat and opens with O_NOFOLLOW. It will **never** follow a symbolic link, preventing accidental deletion of system files.
    
-   **Hard Link Detection:** By default, it skips files with nlink > 1 to prevent destroying data shared by other file paths (e.g., backups/snapshots).
    
-   **Abort-on-Failure:** If the Overwrite phase fails (e.g., interruption, I/O error), the tool **aborts immediately** without deleting the file. This prevents leaving behind "ghost" files that look deleted but still contain recoverable data.
    
-   **Network Awareness:** Detects and warns if the target is on NFS/SMB/FUSE, where secure deletion guarantees cannot be enforced.
    

----------

## ⚠️ Limitations

1.  **Physical Guarantee:** No software-only tool can guarantee 100% physical erasure on flash storage due to Overprovisioning and bad-block remapping. For Top Secret classification, physical destruction or the --sanitize (firmware) command is required.
    
2.  **Journaling Filesystems:** Metadata (filenames, timestamps) might persist in the filesystem journal (Ext4/XFS) for a short time, though the file content will be destroyed.
    
3.  **LUKS:** This tool is most effective when used on a drive with Full Disk Encryption (LUKS). The combination of Overwrite + TRIM on an encrypted volume renders forensic recovery mathematically impossible without the master key.
    

----------

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
