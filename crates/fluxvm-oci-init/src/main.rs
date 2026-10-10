// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxvm-oci-init`: PID 1 of a FluxVM OCI sandbox (or of the builder VM that makes its rootfs).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("fluxvm-oci-init runs as PID 1 inside a Linux guest");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs;
    use std::io::{self, Write};
    use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail};
    use fluxvm_oci_init::config::{
        BLOBS_TAG, BootConfig, CONFIG_FILE, DEFAULT_PATH, EGRESS_PROXY_PORT, EGRESS_PROXY_URL,
        EXIT_MARKER, ExitPolicy, GUEST_IP_MARKER, HostEntry, INIT_ERR, InitConfig, META_TAG,
        NetworkMode, POWEROFF_VIA_INIT_ENV, PrivateNetwork, ProcessSpec, SECRETS_FILE, TOKEN_FILE,
        TOOLS_DIR, UNPACK_ERR, UNPACK_OK, UnpackConfig, valid_env_name, valid_host_name,
        with_secrets,
    };
    use fluxvm_oci_init::supervise::{
        HealthCheck, HealthEvent, HealthState, RestartPolicy, STOP_GRACE, health_line,
        restart_delay, restart_line,
    };
    use fluxvm_oci_init::{dhcp, unpack, user};

    /// Initramfs layout: `/init` (this binary), `/fluxvm/{fluxvm-guest-agent,mke2fs}`, `/fluxvm/meta` (virtiofs).
    const INITRAMFS_TOOLS: &str = "/fluxvm";
    const META_DIR: &str = "/fluxvm/meta";
    const DISK: &str = "/dev/vda";
    const NEWROOT: &str = "/newroot";
    const LOWER: &str = "/lower";
    const UPPER: &str = "/upper";
    const TARGET: &str = "/target";
    const BLOBS_DIR: &str = "/blobs";
    const VMADDR_CID_HOST: u32 = 2;

    static STOP: AtomicBool = AtomicBool::new(false);

    fn say(line: &str) {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }

    fn one_line(e: &anyhow::Error) -> String {
        format!("{e:#}").replace('\n', " ")
    }

    pub fn main() {
        if std::process::id() != 1 {
            eprintln!("fluxvm-oci-init must run as PID 1");
            std::process::exit(1);
        }
        install_signal_handlers();
        let cfg = early_mounts().and_then(|()| read_config());
        match cfg {
            Ok(InitConfig::Unpack(u)) => {
                match unpack_mode(&u) {
                    Ok(()) => say(UNPACK_OK),
                    Err(e) => say(&format!("{UNPACK_ERR} {}", one_line(&e))),
                }
                poweroff();
            }
            Ok(InitConfig::Boot(b)) => {
                if let Err(e) = boot_mode(&b) {
                    say(&format!("{INIT_ERR} {}", one_line(&e)));
                    poweroff();
                }
            }
            Err(e) => {
                say(&format!("{INIT_ERR} {}", one_line(&e)));
                poweroff();
            }
        }
    }

    extern "C" fn on_stop(_: libc::c_int) {
        STOP.store(true, Ordering::SeqCst);
    }

    fn install_signal_handlers() {
        unsafe {
            for sig in [libc::SIGUSR2, libc::SIGTERM, libc::SIGPWR] {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
                // No SA_RESTART: waitpid must return EINTR so the reaper sees STOP.
                sa.sa_flags = 0;
                libc::sigemptyset(&mut sa.sa_mask);
                libc::sigaction(sig, &sa, std::ptr::null_mut());
            }
        }
    }

    fn cstr(s: &str) -> Result<CString> {
        CString::new(s).with_context(|| format!("{s:?} contains NUL"))
    }

    fn mount(
        src: &str,
        target: &str,
        fstype: Option<&str>,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) -> Result<()> {
        let (s, t) = (cstr(src)?, cstr(target)?);
        let f = fstype.map(cstr).transpose()?;
        let d = data.map(cstr).transpose()?;
        let rc = unsafe {
            libc::mount(
                s.as_ptr(),
                t.as_ptr(),
                f.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
                flags,
                d.as_ref().map_or(std::ptr::null(), |d| d.as_ptr().cast()),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("mount {src} on {target}"));
        }
        Ok(())
    }

    fn mount_new(
        src: &str,
        target: &str,
        fstype: &str,
        flags: libc::c_ulong,
        data: Option<&str>,
    ) -> Result<()> {
        fs::create_dir_all(target).with_context(|| format!("mkdir {target}"))?;
        mount(src, target, Some(fstype), flags, data)
    }

    fn early_mounts() -> Result<()> {
        let nosuid = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        mount_new("proc", "/proc", "proc", nosuid, None)?;
        mount_new("sysfs", "/sys", "sysfs", nosuid, None)?;
        if let Err(e) = mount_new(
            "devtmpfs",
            "/dev",
            "devtmpfs",
            libc::MS_NOSUID,
            Some("mode=0755"),
        ) {
            // CONFIG_DEVTMPFS_MOUNT may already have done it.
            if !Path::new("/dev/null").exists() {
                return Err(e);
            }
        }
        mount_new(
            "devpts",
            "/dev/pts",
            "devpts",
            libc::MS_NOSUID | libc::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        )?;
        let _ = fs::remove_file("/dev/ptmx");
        std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx").context("linking /dev/ptmx")?;
        mount_new(
            "shm",
            "/dev/shm",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=1777"),
        )?;
        mount_new(
            META_TAG,
            META_DIR,
            "virtiofs",
            libc::MS_RDONLY | nosuid,
            None,
        )
    }

    /// `config.json`, with the secrets file (when the host wrote one) merged into the process environment.
    fn read_config() -> Result<InitConfig> {
        let path = format!("{META_DIR}/{CONFIG_FILE}");
        let raw = fs::read(&path).with_context(|| format!("reading {path}"))?;
        let mut cfg: InitConfig =
            serde_json::from_slice(&raw).with_context(|| format!("parsing {path}"))?;
        let secrets_path = format!("{META_DIR}/{SECRETS_FILE}");
        if let InitConfig::Boot(b) = &mut cfg
            && let Ok(raw) = fs::read(&secrets_path)
        {
            let secrets: std::collections::BTreeMap<String, String> =
                serde_json::from_slice(&raw).with_context(|| format!("parsing {secrets_path}"))?;
            if let Some(bad) = secrets.keys().find(|k| !valid_env_name(k)) {
                bail!("{secrets_path}: {bad:?} is not an environment variable name");
            }
            b.process.env = with_secrets(&b.process.env, &secrets);
        }
        Ok(cfg)
    }

    fn run(program: &str, args: &[&str]) -> Result<()> {
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("running {program}"))?;
        if !out.status.success() {
            bail!(
                "{program} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    // ---- unpack (builder VM) ----

    fn unpack_mode(cfg: &UnpackConfig) -> Result<()> {
        run(
            &format!("{INITRAMFS_TOOLS}/mke2fs"),
            &[
                "-q",
                "-F",
                "-t",
                "ext4",
                "-m",
                "0",
                "-L",
                "fluxvm-root",
                DISK,
            ],
        )?;
        mount_new(DISK, TARGET, "ext4", 0, None)?;
        mount_new(
            BLOBS_TAG,
            BLOBS_DIR,
            "virtiofs",
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        for (i, layer) in cfg.layers.iter().enumerate() {
            if layer.blob.is_empty() || !layer.blob.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("layer {i}: bad blob name {:?}", layer.blob);
            }
            let path = format!("{BLOBS_DIR}/{}", layer.blob);
            let file =
                fs::File::open(&path).with_context(|| format!("layer {i}: opening {path}"))?;
            let reader = io::BufReader::with_capacity(1 << 20, file);
            let diff_id = unpack::apply_layer(
                Path::new(TARGET),
                reader,
                layer.compression,
                &unpack::Options::privileged(),
            )
            .with_context(|| format!("layer {i}"))?;
            if diff_id != layer.diff_id {
                bail!(
                    "layer {i}: diff_id mismatch (image says {}, tar is {diff_id})",
                    layer.diff_id
                );
            }
        }
        unsafe { libc::sync() };
        let t = cstr(TARGET)?;
        if unsafe { libc::umount(t.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error()).context("unmounting the new rootfs");
        }
        Ok(())
    }

    // ---- boot ----

    fn write_fresh(path: &str, contents: &str) -> Result<()> {
        // The image may ship these as symlinks (resolv.conf -> ../run/...); replace, never follow.
        let _ = fs::remove_file(path);
        fs::write(path, contents).with_context(|| format!("writing {path}"))
    }

    /// Appends `<router> name…` to the `/etc/hosts` written above.
    fn add_gateway_hosts(names: &[String], router: Option<Ipv4Addr>) -> Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        let Some(gw) = router else {
            say("fluxvm-oci-init: no gateway in the DHCP lease; gateway_hosts not added");
            return Ok(());
        };
        if let Some(bad) = names.iter().find(|n| !valid_host_name(n)) {
            bail!("gateway host {bad:?} is not a valid host name");
        }
        let path = format!("{NEWROOT}/etc/hosts");
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {path}"))?;
        writeln!(f, "{gw}\t{}", names.join(" ")).with_context(|| format!("writing {path}"))
    }

    fn add_hosts(entries: &[HostEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let path = format!("{NEWROOT}/etc/hosts");
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {path}"))?;
        for e in entries {
            if let Some(bad) = e.names.iter().find(|n| !valid_host_name(n)) {
                bail!("host {bad:?} is not a valid host name");
            }
            if !e.names.is_empty() {
                writeln!(f, "{}\t{}", e.ip, e.names.join(" "))
                    .with_context(|| format!("writing {path}"))?;
            }
        }
        Ok(())
    }

    fn boot_mode(b: &BootConfig) -> Result<()> {
        if b.read_only_root {
            mount_new(DISK, LOWER, "ext4", libc::MS_RDONLY, None)?;
            mount_new("tmpfs", UPPER, "tmpfs", 0, Some("mode=0755"))?;
            fs::create_dir_all(format!("{UPPER}/u"))?;
            fs::create_dir_all(format!("{UPPER}/w"))?;
            mount_new(
                "overlay",
                NEWROOT,
                "overlay",
                0,
                Some(&format!(
                    "lowerdir={LOWER},upperdir={UPPER}/u,workdir={UPPER}/w"
                )),
            )?;
        } else {
            mount_new(DISK, NEWROOT, "ext4", 0, None)?;
        }

        // Everything that must exist in the root is made now, before it turns read-only.
        for d in ["proc", "sys", "dev", "tmp", "run", "etc", ".fluxvm"] {
            let p = unpack::secure_join(Path::new(NEWROOT), Path::new(d))?;
            fs::create_dir_all(&p).with_context(|| format!("mkdir {}", p.display()))?;
        }
        for m in &b.mounts {
            m.validate()?;
            let p = unpack::secure_join(
                Path::new(NEWROOT),
                Path::new(m.target.trim_start_matches('/')),
            )?;
            fs::create_dir_all(&p)
                .with_context(|| format!("creating volume mount point {}", m.target))?;
        }
        let cwd = unpack::secure_join(Path::new(NEWROOT), Path::new(&b.process.cwd))?;
        fs::create_dir_all(&cwd)
            .with_context(|| format!("creating working directory {}", b.process.cwd))?;

        let host = cstr(&b.hostname)?;
        unsafe { libc::sethostname(host.as_ptr(), b.hostname.len() as _) };
        write_fresh(
            &format!("{NEWROOT}/etc/hostname"),
            &format!("{}\n", b.hostname),
        )?;
        write_fresh(
            &format!("{NEWROOT}/etc/hosts"),
            &format!(
                "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t{}\n",
                b.hostname
            ),
        )?;
        if let Err(e) = link_up("lo") {
            say(&format!("fluxvm-oci-init: loopback: {}", one_line(&e)));
        }
        let private: Vec<[u8; 6]> = b
            .networks
            .iter()
            .filter_map(|n| n.parse().ok().map(|(mac, _, _)| mac))
            .collect();
        if !b.networks.is_empty()
            && let Err(e) = configure_private(&b.networks)
        {
            say(&format!(
                "fluxvm-oci-init: private network: {}",
                one_line(&e)
            ));
        }
        add_hosts(&b.hosts)?;
        if b.network == NetworkMode::Dhcp {
            match configure_dhcp(&private) {
                Ok(lease) => {
                    let mut servers = lease.dns.clone();
                    if servers.is_empty() {
                        servers.extend(lease.router);
                    }
                    let resolv: String = servers
                        .iter()
                        .map(|s| format!("nameserver {s}\n"))
                        .collect();
                    write_fresh(&format!("{NEWROOT}/etc/resolv.conf"), &resolv)?;
                    add_gateway_hosts(&b.gateway_hosts, lease.router)?;
                }
                Err(e) => say(&format!("fluxvm-oci-init: network: {}", one_line(&e))),
            }
        }

        if b.read_only_root {
            mount(NEWROOT, NEWROOT, None, libc::MS_BIND, None)?;
            mount(
                "none",
                NEWROOT,
                None,
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                None,
            )?;
        }
        let nosuid = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        mount(
            "proc",
            &format!("{NEWROOT}/proc"),
            Some("proc"),
            nosuid,
            None,
        )?;
        mount(
            "sysfs",
            &format!("{NEWROOT}/sys"),
            Some("sysfs"),
            nosuid | libc::MS_RDONLY,
            None,
        )?;
        mount(
            "/dev",
            &format!("{NEWROOT}/dev"),
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )?;
        mount(
            "tmpfs",
            &format!("{NEWROOT}/tmp"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=1777"),
        )?;
        mount(
            "tmpfs",
            &format!("{NEWROOT}/run"),
            Some("tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some("mode=0755"),
        )?;
        let tools = format!("{NEWROOT}{TOOLS_DIR}");
        mount(
            INITRAMFS_TOOLS,
            &tools,
            None,
            libc::MS_BIND | libc::MS_REC,
            None,
        )?;
        mount(
            "none",
            &tools,
            None,
            libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
            None,
        )?;

        for m in &b.mounts {
            let target = unpack::secure_join(
                Path::new(NEWROOT),
                Path::new(m.target.trim_start_matches('/')),
            )?;
            let ro = if m.read_only { libc::MS_RDONLY } else { 0 };
            mount(
                &m.tag,
                &target.to_string_lossy(),
                Some("virtiofs"),
                libc::MS_NOSUID | libc::MS_NODEV | ro,
                None,
            )
            .with_context(|| format!("mounting volume {} at {}", m.tag, m.target))?;
        }

        switch_root()?;

        if b.egress_proxy {
            std::thread::spawn(|| {
                if let Err(e) = egress_relay() {
                    say(&format!("fluxvm-oci-init: egress relay: {}", one_line(&e)));
                }
            });
        }
        let mut agent = start_agent(b)
            .map_err(|e| say(&format!("fluxvm-oci-init: agent: {}", one_line(&e))))
            .ok();
        let mut main_pid = start_main(b);
        let mut sup = Supervision::new(b);

        loop {
            if STOP.load(Ordering::SeqCst) {
                poweroff();
            }
            loop {
                let mut status = 0;
                let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if pid <= 0 {
                    break;
                }
                let code = exit_code_of(status);
                if Some(pid) == main_pid {
                    let Some(code) = code else { continue };
                    main_pid = None;
                    sup.main_exited(b, code);
                } else if Some(pid) == agent {
                    say("fluxvm-oci-init: guest agent exited; restarting");
                    std::thread::sleep(Duration::from_secs(1));
                    agent = start_agent(b).ok();
                } else if sup.check.is_some_and(|(c, _)| c == pid) {
                    sup.check = None;
                    sup.health_result(b, code == Some(0), main_pid);
                }
            }
            let now = Instant::now();
            if sup.restart_at.is_some_and(|at| now >= at) {
                sup.restart_at = None;
                main_pid = start_main(b);
                sup.started(now);
            }
            sup.tick(b, now, main_pid);
            if agent.is_none() {
                agent = start_agent(b).ok();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Exit code of a reaped child: its status, or 128 + the signal that killed it.
    fn exit_code_of(status: i32) -> Option<i32> {
        if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Some(128 + libc::WTERMSIG(status))
        } else {
            None
        }
    }

    /// Starts the container's process; a failure is init's error (and the end, under `exit_policy: poweroff`).
    fn start_main(b: &BootConfig) -> Option<i32> {
        match spawn_in_container(b, &b.process.argv, false) {
            Ok(pid) => Some(pid),
            Err(e) => {
                say(&format!("{INIT_ERR} {}", one_line(&e)));
                if b.exit_policy == ExitPolicy::Poweroff {
                    poweroff();
                }
                None
            }
        }
    }

    /// Restarts and health checks of the container's process (decisions in `fluxvm_oci_init::supervise`).
    struct Supervision {
        restarts: u32,
        restart_at: Option<Instant>,
        started_at: Instant,
        health: HealthState,
        next_check: Option<Instant>,
        /// A running health check: its pid and when it started.
        check: Option<(i32, Instant)>,
        /// When init sent SIGTERM to an unhealthy process.
        stopping: Option<Instant>,
        stopped_unhealthy: bool,
    }

    impl Supervision {
        fn new(b: &BootConfig) -> Self {
            let now = Instant::now();
            Self {
                restarts: 0,
                restart_at: None,
                started_at: now,
                health: HealthState::default(),
                next_check: b.healthcheck.as_ref().map(|h| now + interval(h)),
                check: None,
                stopping: None,
                stopped_unhealthy: false,
            }
        }

        fn started(&mut self, now: Instant) {
            self.started_at = now;
            self.health.reset();
            self.stopping = None;
        }

        fn main_exited(&mut self, b: &BootConfig, code: i32) {
            if let Some((c, _)) = self.check.take() {
                unsafe { libc::kill(-c, libc::SIGKILL) };
            }
            self.stopping = None;
            let unhealthy = std::mem::take(&mut self.stopped_unhealthy);
            match restart_delay(b.restart, b.max_restarts, self.restarts, code, unhealthy) {
                Some(delay) => {
                    self.restarts += 1;
                    say(&restart_line(self.restarts, code));
                    self.restart_at = Some(Instant::now() + delay);
                }
                None => {
                    say(&format!("{EXIT_MARKER} {code}"));
                    if b.exit_policy == ExitPolicy::Poweroff {
                        poweroff();
                    }
                }
            }
        }

        fn health_result(&mut self, b: &BootConfig, ok: bool, main_pid: Option<i32>) {
            let Some(hc) = &b.healthcheck else { return };
            let counts = self.started_at.elapsed() >= Duration::from_secs(hc.start_period_seconds);
            match self.health.record(ok, counts, hc.retries) {
                HealthEvent::Unchanged => {}
                HealthEvent::Healthy => say(&health_line(true)),
                HealthEvent::Unhealthy => {
                    say(&health_line(false));
                    if b.restart != RestartPolicy::No
                        && let Some(p) = main_pid
                        && self.stopping.is_none()
                    {
                        unsafe { libc::kill(-p, libc::SIGTERM) };
                        self.stopping = Some(Instant::now());
                        self.stopped_unhealthy = true;
                    }
                }
            }
        }

        fn tick(&mut self, b: &BootConfig, now: Instant, main_pid: Option<i32>) {
            if let (Some(t), Some(p)) = (self.stopping, main_pid)
                && now >= t + STOP_GRACE
            {
                unsafe { libc::kill(-p, libc::SIGKILL) };
                self.stopping = None;
            }
            let Some(hc) = &b.healthcheck else { return };
            if let Some((c, t0)) = self.check
                && now >= t0 + Duration::from_secs(hc.timeout_seconds)
            {
                unsafe { libc::kill(-c, libc::SIGKILL) };
            }
            if self.check.is_none()
                && main_pid.is_some()
                && self.next_check.is_some_and(|n| now >= n)
            {
                self.next_check = Some(now + interval(hc));
                match spawn_in_container(b, &hc.command, true) {
                    Ok(pid) => self.check = Some((pid, now)),
                    Err(_) => self.health_result(b, false, main_pid),
                }
            }
        }
    }

    fn interval(h: &HealthCheck) -> Duration {
        Duration::from_secs(h.interval_seconds)
    }

    /// Move the prepared root over the initramfs (pivot_root cannot leave rootfs) and enter it.
    fn switch_root() -> Result<()> {
        std::env::set_current_dir(NEWROOT)?;
        mount(".", "/", None, libc::MS_MOVE, None)?;
        let dot = cstr(".")?;
        if unsafe { libc::chroot(dot.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error()).context("chroot");
        }
        std::env::set_current_dir("/")?;
        Ok(())
    }

    fn proxy_env(cmd: &mut Command, existing: &[String]) {
        let has = |k: &str| {
            existing
                .iter()
                .any(|e| e.split_once('=').is_some_and(|(ek, _)| ek == k))
        };
        for k in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"] {
            if !has(k) {
                cmd.env(k, EGRESS_PROXY_URL);
            }
        }
        for k in ["no_proxy", "NO_PROXY"] {
            if !has(k) {
                cmd.env(k, "localhost,127.0.0.1,::1");
            }
        }
    }

    fn start_agent(b: &BootConfig) -> Result<i32> {
        let mut cmd = Command::new(format!("{TOOLS_DIR}/fluxvm-guest-agent"));
        cmd.args([
            "--port",
            &b.agent_port.to_string(),
            "--token-file",
            &format!("{TOOLS_DIR}/meta/{TOKEN_FILE}"),
        ])
        .env_clear()
        .env("PATH", DEFAULT_PATH)
        .env("HOME", "/root")
        .env(POWEROFF_VIA_INIT_ENV, "1")
        .stdin(Stdio::null())
        .current_dir("/");
        if b.egress_proxy {
            proxy_env(&mut cmd, &[]);
        }
        Ok(cmd.spawn().context("starting the guest agent")?.id() as i32)
    }

    /// Runs `argv` as the container's process would run: its user, environment, directory, `no_new_privs`, and its own
    /// session (so a signal to the group reaches its children). `quiet` discards the output (health checks).
    fn spawn_in_container(b: &BootConfig, argv: &[String], quiet: bool) -> Result<i32> {
        let p: &ProcessSpec = &b.process;
        let Some(program) = argv.first() else {
            bail!("empty command");
        };
        let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
        let group = fs::read_to_string("/etc/group").unwrap_or_default();
        let id = user::resolve_user(&p.user, &passwd, &group)?;
        let has = |k: &str| {
            p.env
                .iter()
                .any(|e| e.split_once('=').is_some_and(|(ek, _)| ek == k))
        };

        let mut cmd = Command::new(program);
        cmd.args(&argv[1..]).env_clear();
        for e in &p.env {
            if let Some((k, v)) = e.split_once('=') {
                cmd.env(k, v);
            }
        }
        if !has("HOME") {
            cmd.env("HOME", &id.home);
        }
        if !has("HOSTNAME") {
            cmd.env("HOSTNAME", &b.hostname);
        }
        if b.egress_proxy {
            proxy_env(&mut cmd, &p.env);
        }
        let out = || {
            if quiet {
                Stdio::null()
            } else {
                Stdio::inherit()
            }
        };
        cmd.current_dir(&p.cwd)
            .stdin(Stdio::null())
            .stdout(out())
            .stderr(out())
            .gid(id.gid)
            .uid(id.uid);
        unsafe {
            cmd.pre_exec(|| {
                let (one, zero): (libc::c_ulong, libc::c_ulong) = (1, 0);
                if libc::setsid() < 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .with_context(|| format!("starting {program:?} as {}", p.user))?;
        Ok(child.id() as i32)
    }

    fn poweroff() -> ! {
        say("fluxvm-oci-init: powering off");
        unsafe {
            libc::sync();
            libc::kill(-1, libc::SIGTERM);
        }
        std::thread::sleep(Duration::from_millis(500));
        unsafe {
            libc::kill(-1, libc::SIGKILL);
            libc::sync();
            libc::reboot(libc::RB_POWER_OFF);
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // ---- egress: 127.0.0.1:3128 -> host vsock 3128 ----

    fn vsock_connect(cid: u32, port: u32) -> Result<fs::File> {
        unsafe {
            let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error()).context("socket(AF_VSOCK)");
            }
            let file = fs::File::from_raw_fd(fd);
            let mut addr: libc::sockaddr_vm = std::mem::zeroed();
            addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            addr.svm_cid = cid;
            addr.svm_port = port;
            if libc::connect(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            ) != 0
            {
                return Err(io::Error::last_os_error())
                    .context("connecting to the host egress proxy");
            }
            Ok(file)
        }
    }

    fn egress_relay() -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", EGRESS_PROXY_PORT))
            .context("binding 127.0.0.1:3128")?;
        for conn in listener.incoming() {
            let Ok(tcp) = conn else { continue };
            std::thread::spawn(move || {
                let _ = relay(tcp);
            });
        }
        Ok(())
    }

    fn relay(tcp: TcpStream) -> Result<()> {
        let vs = vsock_connect(VMADDR_CID_HOST, u32::from(EGRESS_PROXY_PORT))?;
        let (mut tcp_r, mut vs_w) = (tcp.try_clone()?, vs.try_clone()?);
        let up = std::thread::spawn(move || {
            let _ = io::copy(&mut tcp_r, &mut vs_w);
            unsafe { libc::shutdown(vs_w.as_raw_fd(), libc::SHUT_WR) };
        });
        let (mut vs_r, mut tcp_w) = (vs, tcp);
        let _ = io::copy(&mut vs_r, &mut tcp_w);
        let _ = tcp_w.shutdown(std::net::Shutdown::Write);
        let _ = up.join();
        Ok(())
    }

    // ---- network ----

    #[repr(C)]
    struct IfReqAddr {
        name: [u8; 16],
        addr: libc::sockaddr_in,
        _pad: [u8; 8],
    }

    #[repr(C)]
    struct IfReqFlags {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    fn ifname(name: &str) -> Result<[u8; 16]> {
        if name.is_empty() || name.len() > 15 {
            bail!("bad interface name {name:?}");
        }
        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name.as_bytes());
        Ok(n)
    }

    fn sin(ip: Ipv4Addr) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(ip).to_be(),
            },
            sin_zero: [0; 8],
        }
    }

    fn sa(ip: Ipv4Addr) -> libc::sockaddr {
        let s = sin(ip);
        unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(s) }
    }

    fn ctl_socket() -> Result<UdpSocket> {
        UdpSocket::bind("0.0.0.0:0").context("control socket")
    }

    fn ioctl<T>(sock: &UdpSocket, req: libc::c_ulong, arg: &mut T, what: &str) -> Result<()> {
        if unsafe { libc::ioctl(sock.as_raw_fd(), req as _, arg as *mut T) } != 0 {
            return Err(io::Error::last_os_error()).context(what.to_string());
        }
        Ok(())
    }

    fn link_up(name: &str) -> Result<()> {
        let s = ctl_socket()?;
        let mut r = IfReqFlags {
            name: ifname(name)?,
            flags: 0,
            _pad: [0; 22],
        };
        ioctl(
            &s,
            libc::SIOCGIFFLAGS as libc::c_ulong,
            &mut r,
            "SIOCGIFFLAGS",
        )?;
        r.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ioctl(
            &s,
            libc::SIOCSIFFLAGS as libc::c_ulong,
            &mut r,
            "SIOCSIFFLAGS",
        )
    }

    fn nics() -> Result<Vec<(String, [u8; 6])>> {
        let mut names: Vec<String> = fs::read_dir("/sys/class/net")?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n != "lo")
            .collect();
        names.sort();
        let mut out = Vec::new();
        for name in names {
            let raw = fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
            let bytes: Vec<u8> = raw
                .trim()
                .split(':')
                .map(|h| u8::from_str_radix(h, 16))
                .collect::<Result<_, _>>()
                .context("parsing MAC")?;
            let mac: [u8; 6] = bytes.try_into().ok().context("MAC is not 6 bytes")?;
            out.push((name, mac));
        }
        Ok(out)
    }

    /// The first card that is not on a private network.
    fn first_nic(private: &[[u8; 6]]) -> Result<(String, [u8; 6])> {
        nics()?
            .into_iter()
            .find(|(_, mac)| !private.contains(mac))
            .context("no network interface")
    }

    fn configure_private(nets: &[PrivateNetwork]) -> Result<()> {
        let cards = nics()?;
        for n in nets {
            let (mac, ip, len) = n.parse()?;
            let Some((name, _)) = cards.iter().find(|(_, m)| *m == mac) else {
                bail!("network {}: no card with MAC {}", n.name, n.mac);
            };
            link_up(name)?;
            set_address(name, ip, u32::from(len), None)?;
            say(&format!(
                "fluxvm-oci-init: {name} {ip}/{len} (network {})",
                n.name
            ));
        }
        Ok(())
    }

    fn configure_dhcp(private: &[[u8; 6]]) -> Result<dhcp::Reply> {
        let (name, mac) = first_nic(private)?;
        link_up(&name)?;
        let sock =
            UdpSocket::bind(("0.0.0.0", dhcp::CLIENT_PORT)).context("binding DHCP client port")?;
        sock.set_broadcast(true)?;
        let n = ifname(&name)?;
        if unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                n.as_ptr().cast(),
                (name.len() + 1) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error()).context("SO_BINDTODEVICE");
        }
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        let server = (Ipv4Addr::BROADCAST, dhcp::SERVER_PORT);
        let xid =
            u32::from_ne_bytes([mac[2], mac[3], mac[4], mac[5]]) ^ std::process::id() ^ 0x464c_5856;
        let deadline = Instant::now() + Duration::from_secs(15);

        let recv = |want: &[u8]| -> Option<dhcp::Reply> {
            let until = Instant::now() + Duration::from_secs(2);
            let mut b = [0u8; 1500];
            while Instant::now() < until {
                if let Ok(n) = sock.recv(&mut b)
                    && let Some(r) = dhcp::parse(&b[..n], xid, mac)
                    && want.contains(&r.message_type)
                {
                    return Some(r);
                }
            }
            None
        };

        while Instant::now() < deadline {
            sock.send_to(&dhcp::discover(xid, mac), server)?;
            let Some(offer) = recv(&[dhcp::OFFER]) else {
                continue;
            };
            sock.send_to(&dhcp::request(xid, mac, &offer), server)?;
            let Some(ack) = recv(&[dhcp::ACK, dhcp::NAK]) else {
                continue;
            };
            if ack.message_type == dhcp::NAK {
                continue;
            }
            apply_lease(&name, &ack)?;
            say(&format!("{GUEST_IP_MARKER} {}", ack.address));
            say(&format!(
                "fluxvm-oci-init: {name} {}/{} via {}",
                ack.address,
                ack.prefix_len(),
                ack.router
                    .map_or_else(|| "-".to_string(), |r| r.to_string())
            ));
            return Ok(ack);
        }
        bail!("no DHCP lease on {name}")
    }

    fn apply_lease(name: &str, lease: &dhcp::Reply) -> Result<()> {
        set_address(name, lease.address, lease.prefix_len(), lease.router)
    }

    fn set_address(
        name: &str,
        address: Ipv4Addr,
        bits: u32,
        router: Option<Ipv4Addr>,
    ) -> Result<()> {
        let s = ctl_socket()?;
        let mut a = IfReqAddr {
            name: ifname(name)?,
            addr: sin(address),
            _pad: [0; 8],
        };
        ioctl(
            &s,
            libc::SIOCSIFADDR as libc::c_ulong,
            &mut a,
            "SIOCSIFADDR",
        )?;
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        a.addr = sin(Ipv4Addr::from(mask));
        ioctl(
            &s,
            libc::SIOCSIFNETMASK as libc::c_ulong,
            &mut a,
            "SIOCSIFNETMASK",
        )?;
        if let Some(gw) = router {
            let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
            rt.rt_dst = sa(Ipv4Addr::UNSPECIFIED);
            rt.rt_genmask = sa(Ipv4Addr::UNSPECIFIED);
            rt.rt_gateway = sa(gw);
            rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as _;
            ioctl(
                &s,
                libc::SIOCADDRT as libc::c_ulong,
                &mut rt,
                "adding the default route",
            )?;
        }
        Ok(())
    }
}
