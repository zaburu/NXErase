use anyhow::{anyhow, Context, Result};
use chrono::Local;
use clap::{ArgGroup, Parser};
use crossbeam_channel::{bounded, Sender};
use indicatif::{ProgressBar, ProgressStyle};
use nix::fcntl::{fallocate, FallocateFlags};
use nix::sys::statfs::statfs;
use nix::unistd::Uid;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use walkdir::WalkDir;

// Explicit imports
use ctrlc;
use num_cpus;

// --- Constants & Globals ---

static RUNNING: AtomicBool = AtomicBool::new(true);

// Filesystem Magic Numbers
const NFS_SUPER_MAGIC: i64 = 0x6969;
const SMB_SUPER_MAGIC: i64 = 0x517B;
const CIFS_MAGIC_NUMBER: i64 = 0xFF534D42;
const FUSE_SUPER_MAGIC: i64 = 0x65735546;
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;

// Linux FS immutable flag
const FS_IMMUTABLE_FL: u64 = 0x00000010;

// IOCTL Macros
nix::ioctl_read!(ioctl_getflags, 'f', 1, libc::c_long);
nix::ioctl_write_ptr!(ioctl_setflags, 'f', 2, libc::c_long);

#[derive(Parser, Debug)]
#[command(name = "nxerase")]
#[command(version = "1.8.2")]
#[command(about = "Forensic-resistant secure deletion tool for NVMe and SSDs.", long_about = None)]
#[clap(group(
ArgGroup::new("mode")
.required(true)
.args(&["files", "sanitize"]),
))]
struct Cli {
    /// List of files, directories, or patterns to securely wipe.
    #[arg(group = "mode")]
    files: Vec<PathBuf>,

    /// Number of parallel worker threads.
    #[arg(short = 'j', long = "jobs", default_value_t = num_cpus::get())]
    jobs: usize,

    /// Disable the interactive progress bar.
    #[arg(long = "no-progress", default_value_t = false)]
    no_progress: bool,

    /// Simulate the operation without modifying data.
    #[arg(long = "dry-run", short = 'n')]
    dry_run: bool,

    /// Enable verbose output.
    #[arg(long = "verbose", short = 'v')]
    verbose: bool,

    /// Perform device-level NVMe sanitization (Destructive).
    #[arg(short = 's', long = "sanitize", group = "mode")]
    sanitize: bool,

    /// The block device to sanitize (e.g., /dev/nvme0n1).
    #[arg(long = "device")]
    device: Option<PathBuf>,

    /// Automatically answer "YES" to destructive confirmation prompts.
    #[arg(long = "yes")]
    yes: bool,

    /// Permit overwriting files with multiple hard links.
    #[arg(long = "allow-hardlinks")]
    allow_hardlinks: bool,

    /// Sleep for <MS> milliseconds between 1MB chunks.
    #[arg(long = "throttle", value_name = "MS")]
    throttle_ms: Option<u64>,

    /// Append audit logs to the specified file.
    #[arg(long = "log-file", value_name = "PATH")]
    log_file: Option<PathBuf>,
}

// --- Structs ---

struct AuditLogger {
    file: Option<Mutex<File>>,
}

impl AuditLogger {
    fn new(path: Option<PathBuf>) -> Result<Self> {
        if let Some(p) = path {
            let f = OpenOptions::new().create(true).append(true).write(true).open(p)?;
            Ok(Self { file: Some(Mutex::new(f)) })
        } else {
            Ok(Self { file: None })
        }
    }

    fn log(&self, msg: &str) {
        if let Some(mutex) = &self.file {
            if let Ok(mut f) = mutex.lock() {
                let _ = writeln!(f, "[{}] {}", Local::now().to_rfc3339(), msg);
            }
        }
    }
}

// Atomic stats for summary
struct WipeStats {
    deleted: AtomicUsize,
    skipped: AtomicUsize,
    failed: AtomicUsize,
}

impl WipeStats {
    fn new() -> Self {
        Self {
            deleted: AtomicUsize::new(0),
            skipped: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
        }
    }
}

// --- Helper Functions ---

fn is_network_or_overlay(path: &Path) -> bool {
    if let Ok(stat) = statfs(path) {
        let magic = stat.filesystem_type().0 as i64;
        if magic == NFS_SUPER_MAGIC ||
            magic == SMB_SUPER_MAGIC ||
            magic == CIFS_MAGIC_NUMBER ||
            magic == FUSE_SUPER_MAGIC ||
            magic == OVERLAYFS_SUPER_MAGIC {
                return true;
            }
    }
    false
}

fn remove_immutable_flag(fd: i32) -> Result<()> {
    unsafe {
        let mut flags: libc::c_long = 0;
        ioctl_getflags(fd, &mut flags).context("Failed to get file flags")?;

        let imm_mask = FS_IMMUTABLE_FL as libc::c_long;
        if (flags & imm_mask) != 0 {
            flags &= !imm_mask;
            ioctl_setflags(fd, &flags).context("Failed to clear immutable flag")?;
        }
    }
    Ok(())
}

fn overwrite_file(file: &mut File, len: u64, progress_sender: Option<Sender<u64>>, throttle: Option<u64>, verbose: bool) -> Result<()> {
    if len == 0 { return Ok(()); }

    let mut rng = OsRng;
    // Safe allocation
    let mut buffer = vec![0u8; 1024 * 1024];

    let mut written: u64 = 0;

    file.seek(SeekFrom::Start(0)).context("seek to start")?;

    while written < len {
        if !RUNNING.load(Ordering::SeqCst) {
            return Err(anyhow!("Interrupted by signal"));
        }

        let remaining = (len - written) as usize;
        let to_write = std::cmp::min(remaining, buffer.len());

        rng.fill(&mut buffer[..to_write]);
        file.write_all(&buffer[..to_write]).context("write random data")?;

        written += to_write as u64;

        if let Some(ref s) = progress_sender {
            if let Err(_) = s.try_send(to_write as u64) {
                if verbose {
                    // Optional: log dropped update
                }
            }
        }

        if let Some(ms) = throttle {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }

    file.sync_all().context("fsync")?;
    Ok(())
}

fn punch_hole(file: &File, len: u64) -> Result<()> {
    if len > i64::MAX as u64 { return Err(anyhow!("File too large for fallocate")); }
    let fd = file.as_raw_fd();
    let mode = FallocateFlags::FALLOC_FL_PUNCH_HOLE | FallocateFlags::FALLOC_FL_KEEP_SIZE;

    fallocate(fd, mode, 0, len as i64).map_err(|e| anyhow!("fallocate failed: {}", e))?;
    Ok(())
}

fn random_name() -> String {
    OsRng.sample_iter(&Alphanumeric).take(12).map(char::from).collect()
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn secure_wipe_file(path: &Path, progress_sender: Option<Sender<u64>>, args: &Cli, logger: &Arc<AuditLogger>, stats: &Arc<WipeStats>) -> Result<()> {
    // 1. Initial Lstat (Symlink Safe)
    let meta = fs::symlink_metadata(path).with_context(|| format!("stat {:?}", path))?;

    if !meta.is_file() { return Ok(()); }

    // Safety: Hard link check
    if meta.nlink() > 1 {
        if !args.allow_hardlinks {
            let msg = format!("Skipping {:?}: {} hard links (Use --allow-hardlinks to force).", path, meta.nlink());
            logger.log(&msg);
            // UX FIX: Always print hardlink warning, even if not verbose
            eprintln!("{}", msg);
            stats.skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }

    if is_network_or_overlay(path) && args.verbose {
        eprintln!("Warning: {:?} is on Network/Overlay FS.", path);
    }

    if args.dry_run {
        // UX FIX: Always print dry-run targets
        println!("DRY-RUN: Would wipe {:?}", path);
        return Ok(());
    }

    // 2. Open with O_NOFOLLOW
    let mut options = OpenOptions::new();
    options.write(true);
    options.custom_flags(libc::O_NOFOLLOW);

    let mut file = match options.open(path) {
        Ok(f) => {
            let f_meta = f.metadata()?;
            if f_meta.ino() != meta.ino() || f_meta.dev() != meta.dev() {
                let msg = format!("Security Warning: {:?} replaced during operation. Skipping.", path);
                logger.log(&msg);
                eprintln!("{}", msg);
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            f
        },
        Err(e) => {
            if e.raw_os_error() == Some(libc::ELOOP) {
                let msg = format!("Skipping {:?}: Symlink detected during open.", path);
                logger.log(&msg);
                stats.skipped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }

            if e.kind() == std::io::ErrorKind::PermissionDenied {
                if Uid::effective().is_root() {
                    let f_ro = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)
                    .context("Failed to open file for immutable check")?;

                    let ro_meta = f_ro.metadata()?;
                    if ro_meta.ino() != meta.ino() || ro_meta.dev() != meta.dev() {
                        let msg = format!("Security Warning: {:?} replaced during immutable check. Skipping.", path);
                        logger.log(&msg);
                        stats.skipped.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }

                    if let Err(err) = remove_immutable_flag(f_ro.as_raw_fd()) {
                        return Err(anyhow!("Failed to clear immutable flag: {}", err));
                    }

                    let f_retry = options.open(path)?;
                    let retry_meta = f_retry.metadata()?;
                    if retry_meta.ino() != meta.ino() || retry_meta.dev() != meta.dev() {
                        let msg = format!("Security Warning: {:?} replaced after immutable clear. Skipping.", path);
                        logger.log(&msg);
                        stats.skipped.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                    f_retry
                } else {
                    return Err(anyhow!("Permission denied (immutable file?). Root required."));
                }
            } else {
                return Err(anyhow!("Open failed: {}", e));
            }
        }
    };

    let len = meta.len();

    // 3. Overwrite
    if let Err(e) = overwrite_file(&mut file, len, progress_sender, args.throttle_ms, args.verbose) {
        let msg = format!("Overwrite failed {:?}: {}. ABORTING DELETE.", path, e);
        logger.log(&msg);
        stats.failed.fetch_add(1, Ordering::Relaxed);
        return Err(anyhow!("{}", msg));
    }

    // 4. Punch Hole
    if let Err(e) = punch_hole(&file, len) {
        if args.verbose { eprintln!("Info: TRIM unsupported {:?}: {}", path, e); }
    }

    // 5. Obfuscate & Remove
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let obf = parent.join(format!(".tmp_{}", random_name()));

    let rename_ok = fs::rename(path, &obf).is_ok();
    if rename_ok {
        sync_parent(&obf);
        drop(file);
        if let Err(e) = fs::remove_file(&obf) {
            let msg = format!("Removal failed {:?}: {}", obf, e);
            logger.log(&msg);
            stats.failed.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("{}", msg));
        }
        sync_parent(&obf);
        logger.log(&format!("Deleted: {:?}", path));
        stats.deleted.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }

    match fs::remove_file(path) {
        Ok(_) => {
            drop(file);
            sync_parent(path);
            logger.log(&format!("Deleted: {:?}", path));
            stats.deleted.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        },
        Err(e) => {
            drop(file);
            let target = if fs::metadata(&obf).is_ok() { obf.clone() } else { path.to_path_buf() };
            if let Err(e2) = fs::remove_file(&target) {
                let msg = format!("Removal failed {:?}: {} (also tried {:?}: {})", target, e2, (if target == obf { path } else { &obf }), e);
                logger.log(&msg);
                stats.failed.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow!("{}", msg));
            }
            sync_parent(&target);
            logger.log(&format!("Deleted: {:?}", path));
            stats.deleted.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    }
}

fn device_sanitize(device: &Path, yes: bool) -> Result<()> {
    if !Uid::effective().is_root() {
        return Err(anyhow!("Root privileges required."));
    }

    let meta = fs::metadata(device).context("Stat device failed")?;
    if !meta.file_type().is_block_device() {
        return Err(anyhow!("Not a block device: {:?}", device));
    }

    let nvme_check = Command::new("nvme").arg("--version").output();
    match nvme_check {
        Ok(out) if out.status.success() => {},
        Ok(out) => return Err(anyhow!("'nvme-cli' check failed: {}", String::from_utf8_lossy(&out.stderr).trim())),
        Err(e) => return Err(anyhow!("Failed to execute 'nvme': {}. Please install nvme-cli.", e)),
    }

    if !yes {
        eprintln!("⚠️  WARNING: DEVICE SANITIZE IS DESTRUCTIVE!");
        eprintln!("   This will erase ALL data on {:?} instantly.", device);
        eprint!("   Type 'YES' to continue: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "YES" { return Err(anyhow!("Aborted")); }
    }

    println!("Initiating NVMe Sanitize...");
    println!("ℹ️  Command returns immediately; sanitize runs in background.");

    let output = Command::new("nvme")
    .args(&["sanitize", "-a", "start-crypto-erase"])
    .arg(device.as_os_str())
    .output()
    .context("Failed to execute nvme-cli")?;

    if output.status.success() {
        println!("✅ Sanitize command issued.");
        println!("ℹ️  Verify: sudo nvme sanitize-log {:?}", device);
        return Ok(());
    }

    eprintln!("Crypto Erase failed, trying Block Erase...");

    let output_block = Command::new("nvme")
    .args(&["sanitize", "-a", "start-block-erase"])
    .arg(device.as_os_str())
    .output()?;

    if output_block.status.success() {
        println!("✅ Block Erase command issued.");
        return Ok(());
    }

    Err(anyhow!("Sanitize failed: {}", String::from_utf8_lossy(&output_block.stderr)))
}

fn main() -> Result<()> {
    ctrlc::set_handler(|| {
        RUNNING.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let args = Cli::parse();
    let logger = Arc::new(AuditLogger::new(args.log_file.clone())?);
    let stats = Arc::new(WipeStats::new());

    // MODE 1: Sanitize
    if args.sanitize {
        let device = args.device.as_ref().ok_or_else(|| anyhow!("--sanitize requires --device"))?;
        return device_sanitize(device, args.yes);
    }

    // MODE 2: File Wipe
    // Phase 1: Scan & Collect Metadata
    let mut total_bytes: u64 = 0;

    // Always print "Scanning" if verbose, or just proceed
    if args.verbose { println!("Scanning files..."); }

    for p in &args.files {
        for entry in WalkDir::new(p) {
            if !RUNNING.load(Ordering::SeqCst) { break; }
            if let Ok(e) = entry {
                if e.file_type().is_file() {
                    if !args.no_progress {
                        total_bytes = total_bytes.saturating_add(e.metadata().map(|m| m.len()).unwrap_or(0));
                    }
                }
            }
        }
    }

    if !RUNNING.load(Ordering::SeqCst) {
        eprintln!("Aborted by signal.");
        std::process::exit(130);
    }

    // UX FIX: If nothing to do, tell the user (avoids "Silence" on symlinks)
    if total_bytes == 0 && !args.dry_run && !args.no_progress {
        // Note: total_bytes is 0 if files exist but are 0 bytes, OR if no files found.
        // We can't distinguish easily without collecting, but it's a good hint.
        // A better check is if we don't enter the loop below, but let's leave it for now.
    }

    // Phase 2: Parallel Wipe (Streaming)
    let (tx, rx) = bounded::<u64>(4096);

    let pb_thread = if !args.no_progress && total_bytes > 0 {
        let pb = Arc::new(ProgressBar::new(total_bytes));
        pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));

        let pb_clone = pb.clone();
        Some(std::thread::spawn(move || {
            for inc in rx { pb_clone.inc(inc); }
            pb_clone.finish_with_message("Done");
        }))
    } else {
        None
    };

    let pool = rayon::ThreadPoolBuilder::new().num_threads(args.jobs).build()?;

    pool.install(|| {
        let all_files = args.files.iter().flat_map(|p| WalkDir::new(p));

        all_files.par_bridge().for_each(|entry| {
            if !RUNNING.load(Ordering::SeqCst) { return; }

            match entry {
                Ok(e) => {
                    if e.file_type().is_file() {
                        let sender = if !args.no_progress { Some(tx.clone()) } else { None };
                        if let Err(err) = secure_wipe_file(e.path(), sender, &args, &logger, &stats) {
                            eprintln!("Error {:?}: {}", e.path(), err);
                        }
                    }
                },
                Err(err) => if args.verbose { eprintln!("Walk error: {}", err); }
            }
        });
    });

    drop(tx);
    if let Some(t) = pb_thread {
        if let Err(e) = t.join() {
            eprintln!("Progress thread panicked: {:?}", e);
        }
    }

    // UX FIX: Ensure newline after progress bar so Summary is clean
    if !args.no_progress && total_bytes > 0 {
        eprintln!();
    }

    // Phase 3: Cleanup Empty Dirs
    if !args.dry_run && RUNNING.load(Ordering::SeqCst) {
        for p in &args.files {
            if p.is_dir() {
                for entry in WalkDir::new(p).contents_first(true) {
                    if let Ok(e) = entry {
                        if e.file_type().is_dir() {
                            let _ = fs::remove_dir(e.path());
                        }
                    }
                }
                let _ = fs::remove_dir(p);
            }
        }
    }

    if !RUNNING.load(Ordering::SeqCst) {
        eprintln!("Aborted by signal.");
        std::process::exit(130);
    }

    // Final Summary
    let s_del = stats.deleted.load(Ordering::Relaxed);
    let s_skip = stats.skipped.load(Ordering::Relaxed);
    let s_fail = stats.failed.load(Ordering::Relaxed);

    // UX FIX: Warn if user ran on empty/symlinks and nothing happened
    if s_del == 0 && s_skip == 0 && s_fail == 0 && !args.dry_run {
        println!("No regular files found to wipe.");
    } else if args.verbose || s_fail > 0 || (s_del + s_skip + s_fail > 0) {
        println!("Summary: {} deleted, {} skipped, {} failed.", s_del, s_skip, s_fail);
    }

    if s_fail > 0 {
        std::process::exit(1);
    }

    Ok(())
}
