import {useState} from 'react';
import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import MacCloud from '@site/src/components/MacCloud';
import Reveal from '@site/src/components/Reveal';

import styles from './mac.module.css';

const REPO = 'https://github.com/zyvorai/zyvor-fluxvm';

type Stat = {value: string; label: string; note: string};

// Every figure was measured on one Apple M4 running macOS 27.2. Sources are in docs/macos.md,
// docs/macos-sandboxes.md and docs/oci-sandboxes.md ("Measured" / "Verified" sections).
const STATS: Stat[] = [
  {value: '~10 s', label: 'Cold boot to SSH', note: 'Debian 13 through the REST API'},
  {value: '~2 s', label: 'Warm start', note: 'restore a saved VM state instead of booting'},
  {value: '0.7 s', label: 'Snapshot', note: 'running VM, APFS-cloned disk'},
  {value: '~1.75 s', label: 'Container sandbox', note: 'cold start of a cached OCI image (warm claim ~1.3 s)'},
];

type Capability = {title: string; body: string; status: 'ok' | 'warn'; tag: string; to?: string};

const CAPABILITIES: Capability[] = [
  {
    title: 'Linux VMs',
    body: 'Debian and Ubuntu ARM64 guests from named images, with cloud-init, port forwards, shared folders, snapshots and `fluxctl run` throwaway shells.',
    status: 'ok',
    tag: 'Verified on M4',
    to: '/docs/macos',
  },
  {
    title: 'Agent sandboxes',
    body: 'Disposable machines for coding agents: TTL, exec and files, speculate-and-approve changesets, offline or allow-listed egress, and a warm pool.',
    status: 'ok',
    tag: 'Verified on M4',
    to: '/docs/macos-sandboxes',
  },
  {
    title: 'Container sandboxes',
    body: 'Run an OCI image as its own VM, one container per VM, with a digest-verified rootfs cache and its own warm pool.',
    status: 'ok',
    tag: 'Core verified on M4',
    to: '/docs/oci-sandboxes',
  },
  {
    title: 'macOS guests',
    body: 'Clone a prepared macOS template for clean-room testing and CI. Apple allows two macOS VMs running at once per Mac.',
    status: 'ok',
    tag: 'Verified by hand',
    to: '/docs/macos#macos-guests',
  },
  {
    title: 'Stacks',
    body: 'Describe a database, an app and a test runner in one `fluxvm.toml` and bring them up with `fluxctl up`, with discovery by name.',
    status: 'ok',
    tag: 'Verified on M4',
    to: '/docs/macos-stacks',
  },
  {
    title: 'Mac Studio options',
    body: 'Multiple displays, bridged networking, per-VM vmnet networks, memory balloon, USB, ASIF overlay disks, macOS 27 provisioning.',
    status: 'warn',
    tag: 'Implemented, mostly not yet hardware-verified',
    to: '/docs/macos#mac-studio-options',
  },
];

type MacRow = {name: string; role: string; fluxvm: string};

// Chips, memory ceilings and ports are Apple's published figures, read from apple.com on 2026-10-10 (see the
// sources in docs/macos-architecture.md). The FluxVM column is guidance: capacity numbers are estimates from
// docs/agent-density.md, not measurements, and only one Apple M4 has been tested.
const MACS: MacRow[] = [
  {
    name: 'Mac mini',
    role: 'M6 (up to 32 GB) or M5 Pro (up to 64 GB). Three Thunderbolt ports (4 on M6, 5 on M5 Pro), 2.5 GbE with a 10 GbE option.',
    fluxvm:
      'A quiet, always-on host for one to a few Linux VMs and a handful of small agent sandboxes. The estimate for a 16 GB mini is 4 to 8 active tiny sandboxes; a 64 GB M5 Pro leaves room for macOS guest templates.',
  },
  {
    name: 'Mac Studio',
    role: 'M5 Max (up to 128 GB) or M5 Ultra (up to 512 GB, the 512 GB option ships late October). Four Thunderbolt 5 ports (six on M5 Ultra), 10 GbE.',
    fluxvm:
      'The team host: CI runners, many agent sandboxes and macOS guests next to large models in unified memory. The estimate for 64 GB or more is 25 to 40 active tiny sandboxes. 10 GbE and Thunderbolt 5 suit a fleet; multi-Mac clusters are not yet verified.',
  },
  {
    name: 'MacBook Pro',
    role: 'M5 (up to 32 GB), M5 Pro (up to 64 GB) or M5 Max (up to 128 GB). Thunderbolt 4 on M5, Thunderbolt 5 on M5 Pro and Max; no built-in Ethernet.',
    fluxvm:
      'Disposable VMs and sandboxes where you work. Shared folders keep your editor on macOS while builds run in Linux.',
  },
];

const MACOS27 = [
  {
    title: 'Layered disk images',
    body: 'DiskImageKit stacks a read-only base, an ASIF cache and a copy-on-write overlay. FluxVM already has an ASIF overlay option for fast throwaway disks.',
    tag: 'Implemented, not yet hardware-verified',
  },
  {
    title: 'Unattended macOS guests',
    body: 'Guest provisioning can skip Setup Assistant and create a user, so a macOS template needs no clicking. FluxVM exposes it as provision options.',
    tag: 'Implemented, not yet hardware-verified',
  },
  {
    title: 'Custom Virtio devices',
    body: 'A vendor Virtio device with a host-side provider and a guest driver. Ping, echo, stats, capabilities and bulk fill, zero, copy and CRC through guest memory work on a Debian 13 guest.',
    tag: 'Verified on M4 (control plane and bulk operations)',
  },
  {
    title: 'Shared vmnet networks and physical USB',
    body: 'VMs that name one vmnet network share it through a broker, and a physical USB device can be passed through with Accessory Access. Both need signing this Mac did not allow.',
    tag: 'Implemented, blocked on this host by signing; not verified',
  },
];

function Hero() {
  return (
    <header className={styles.hero}>
      <div className="container">
        <div className={styles.pills}>
          <span className={styles.pill}>Apple silicon</span>
          <span className={styles.pill}>macOS 27</span>
          <span className={clsx(styles.pill, styles.pillBlue)}>vz backend</span>
          <span className={styles.pill}>Virtualization.framework</span>
        </div>
        <Heading as="h1" className={styles.heroTitle}>
          Your own <span className={styles.gradientText}>Mac cloud.</span>
          <br />
          One signed runner per VM.
        </Heading>
        <p className={styles.heroSub}>
          FluxVM puts a REST API, a warm pool and a fleet scheduler on top of Apple's
          Virtualization.framework. Linux VMs, macOS guests, agent sandboxes and
          container sandboxes on a Mac mini, a Mac Studio or a MacBook Pro.
        </p>
        <div className={styles.buttons}>
          <Link className="button button--primary button--lg" href="#install">
            Get started
          </Link>
          <Link className="button button--outline button--lg button--secondary" to="/mac-cloud">
            Build a Mac cloud
          </Link>
        </div>
        <MacCloud caption="An illustration of the setup FluxVM is built for. One Apple M4 is verified today; multi-Mac fleets are not yet." />
      </div>
    </header>
  );
}

function RealCapture() {
  return (
    <section className={clsx(styles.section, styles.darkBand)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Not a mockup</p>
            <Heading as="h2" className={styles.h2}>
              A real guest, on a real Mac
            </Heading>
          </div>
          <img
            className={styles.heroShot}
            src={useBaseUrl('/img/macos/velora-debian-macos27.png')}
            alt="A Debian 13 guest running on Virtualization.framework, captured on an Apple M4 with macOS 27"
            loading="lazy"
          />
          <p className={styles.shotCaption}>
            A Debian 13 guest on an Apple M4 with macOS 27, shown in Velora's app.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

type Perk = {icon: string; hue: string; title: string; body: string; to?: string};

// Each perk is backed by a section of docs/macos.md, docs/oci-sandboxes.md or deploy/launchd-notes.md.
const PERKS: Perk[] = [
  {
    icon: 'M',
    hue: 'linear-gradient(135deg,#5e5ce6,#bf5af2)',
    title: 'Apple silicon native',
    body: 'Daemon, API, fluxctl and a Swift runner built for arm64. No QEMU, no emulation, no Linux VM in the middle.',
    to: '/docs/macos',
  },
  {
    icon: 'R',
    hue: 'linear-gradient(135deg,#ff9f0a,#ff375f)',
    title: 'Rosetta in Linux guests',
    body: 'Run x86_64 Linux binaries and linux/amd64 container images inside arm64 guests through Apple\'s Rosetta share.',
    to: '/docs/macos#display-audio-sharing-and-usb-options',
  },
  {
    icon: 'K',
    hue: 'linear-gradient(135deg,#8e8e93,#3a3a3c)',
    title: 'Keychain sign-in',
    body: 'fluxctl signin keeps a guest password in your login Keychain and types it into the display. It is never returned by the API.',
    to: '/docs/macos#stored-sign-in',
  },
  {
    icon: 'A',
    hue: 'linear-gradient(135deg,#0a84ff,#64d2ff)',
    title: 'APFS clones',
    body: 'Disks and snapshots are copy-on-write clones (cp -c). A throwaway VM costs almost no disk until it writes.',
    to: '/docs/macos#how-it-works',
  },
  {
    icon: 'F',
    hue: 'linear-gradient(135deg,#30d158,#64d2ff)',
    title: 'Shared folders',
    body: 'Edit in your favourite macOS editor; build in Linux. virtiofs shares, read-only enforced by the host: fluxctl run -v ~/src:/mnt/src.',
    to: '/docs/macos#quick-start',
  },
  {
    icon: '5K',
    hue: 'linear-gradient(135deg,#ff375f,#bf5af2)',
    title: 'Retina displays',
    body: 'Guest displays up to 5120 x 2880 at 220 ppi, audio out, and a window that follows your resize.',
    to: '/docs/macos#display-audio-sharing-and-usb-options',
  },
  {
    icon: 'L',
    hue: 'linear-gradient(135deg,#1c1c1e,#48484a)',
    title: 'launchd, not cron',
    body: 'fluxctl service install writes a LaunchAgent, so a headless Mac mini serves VMs after every reboot.',
    to: '/docs/mac-cloud#run-it-as-a-service',
  },
  {
    icon: 'AI',
    hue: 'linear-gradient(135deg,#64d2ff,#5e5ce6)',
    title: 'Agents can see the screen',
    body: 'Screenshots, keyboard and mouse for any vz guest, without Screen Recording or Accessibility permission on the host.',
    to: '/docs/macos#agent-screen-and-input',
  },
];

function BuiltForMac() {
  return (
    <section className={clsx(styles.section, styles.alt)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Built for Mac people</p>
            <Heading as="h2" className={styles.h2}>
              Feels like it belongs on your Mac
            </Heading>
            <p className={styles.lead}>
              FluxVM uses the parts of macOS you already trust: Virtualization.framework, APFS,
              the Keychain, launchd and Rosetta.
            </p>
          </div>
          <div className={styles.grid4}>
            {PERKS.map((p) => (
              <div key={p.title} className={styles.perk}>
                <span className={styles.perkIcon} style={{background: p.hue}}>
                  {p.icon}
                </span>
                <Heading as="h3">{p.to ? <Link to={p.to}>{p.title}</Link> : p.title}</Heading>
                <p>{p.body}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

type Guest = {name: string; boot: string; body: string; tag: string; ok: boolean};

const GUESTS: Guest[] = [
  {
    name: 'macOS guest',
    boot: 'IPSW install, macOS boot loader',
    body: 'A real macOS userspace for Xcode, signing and UI tests. Prepare a template once, then clone it with APFS in an instant; every clone gets its own machine identity.',
    tag: 'Verified by hand on M4',
    ok: true,
  },
  {
    name: 'Linux VM',
    boot: 'EFI from disk, or direct kernel',
    body: 'Debian 13, Debian 12 and Ubuntu 24.04 ARM64 from named images, with cloud-init, port forwards, shared folders, snapshots and the vsock guest agent.',
    tag: 'Verified on M4',
    ok: true,
  },
  {
    name: 'Container VM',
    boot: 'Direct kernel, read-only root',
    body: 'An OCI image in its own lightweight VM: uid 65534, no SSH, agent-only exec, a digest-verified rootfs cache and a warm pool.',
    tag: 'Core verified on M4',
    ok: true,
  },
];

function VzExplained() {
  return (
    <section className={styles.section}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>vz and macOS virtualization</p>
            <Heading as="h2" className={styles.h2}>
              Apple's hypervisor. FluxVM's API.
            </Heading>
            <p className={styles.lead}>
              The <code>vz</code> backend drives Apple's Virtualization.framework, the same
              hypervisor behind macOS's own virtual machines. On a Mac, <code>"backend": "auto"</code>{' '}
              resolves to <code>vz</code>.
            </p>
          </div>
          <div className={styles.stack}>
            <div className={styles.stackRow}>
              <span className={styles.stackLabel}>You</span>
              <div className={styles.stackItems}>
                <code>fluxctl</code>
                <code>REST :7788</code>
                <code>MCP</code>
                <code>Python / Go / TS SDKs</code>
              </div>
            </div>
            <div className={styles.stackArrow} aria-hidden="true" />
            <div className={styles.stackRow}>
              <span className={styles.stackLabel}>Daemon</span>
              <div className={styles.stackItems}>
                <code>fluxctl serve</code>
                <code>warm pool</code>
                <code>APFS clones</code>
                <code>egress proxy over vsock</code>
              </div>
            </div>
            <div className={styles.stackArrow} aria-hidden="true" />
            <div className={clsx(styles.stackRow, styles.stackRowHot)}>
              <span className={styles.stackLabel}>Per VM</span>
              <div className={styles.stackItems}>
                <code>fluxvm-vz-runner</code>
                <span>signed with com.apple.security.virtualization, one process per guest</span>
              </div>
            </div>
            <div className={styles.stackArrow} aria-hidden="true" />
            <div className={styles.stackRow}>
              <span className={styles.stackLabel}>Apple</span>
              <div className={styles.stackItems}>
                <code>Virtualization.framework</code>
                <code>Hypervisor.framework</code>
                <code>Apple silicon</code>
              </div>
            </div>
          </div>
          <div className={styles.grid3}>
            {GUESTS.map((g) => (
              <div key={g.name} className={styles.card}>
                <Heading as="h3">{g.name}</Heading>
                <p className={styles.boot}>{g.boot}</p>
                <p>{g.body}</p>
                <span className={clsx(styles.tag, g.ok ? styles.tagOk : styles.tagWarn)}>{g.tag}</span>
              </div>
            ))}
          </div>
          <p className={clsx(styles.footnote, 'text--center')}>
            Apple's licence allows two macOS guests running at once per Mac; the fleet scheduler
            respects it. Snapshot restore needs an unlocked login session.{' '}
            <Link to="/docs/macos-architecture">Full architecture &rarr;</Link>
          </p>
        </Reveal>
      </div>
    </section>
  );
}

const INSTALL_TABS: {id: string; label: string; note: ReactNode; code: string}[] = [
  {
    id: 'source',
    label: 'From source',
    note: 'Needs Xcode 27 for the Swift runner. The build signs the runner for you.',
    code: [
      'xcode-select --install',
      'brew install hivex',
      'git clone https://github.com/zyvorai/zyvor-fluxvm && cd zyvor-fluxvm',
      'cargo build -p fluxctl',
      './scripts/macos-live-test.sh   # boots Debian 13 through the API',
    ].join('\n'),
  },
  {
    id: 'brew',
    label: 'Homebrew',
    note: (
      <>
        Each version tag builds a Homebrew package; the tap is not published yet. See{' '}
        <a href={`${REPO}/tree/main/packaging/homebrew`}>packaging/homebrew</a>.
      </>
    ),
    code: ['brew install zyvorai/fluxvm/fluxvm   # once the tap is published', 'brew services start fluxvm'].join('\n'),
  },
  {
    id: 'first',
    label: 'First VM',
    note: 'A throwaway VM and a shell. Everything you did is gone when you leave.',
    code: [
      'fluxctl run                                 # debian-13, a shell as you',
      'fluxctl run -v ~/src:/mnt/src -p 8080:80    # share a folder, forward a port',
      'fluxctl run ubuntu-24.04 -- uname -a        # one command, its exit code',
      'fluxctl sandbox run alpine:3.22 --rm -- echo hi',
    ].join('\n'),
  },
];

function Install() {
  const [tab, setTab] = useState(INSTALL_TABS[0].id);
  const [copied, setCopied] = useState(false);
  const current = INSTALL_TABS.find((t) => t.id === tab) ?? INSTALL_TABS[0];
  const copy = () => {
    navigator.clipboard?.writeText(current.code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <section className={clsx(styles.section, styles.darkBand)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Install</p>
            <Heading as="h2" id="install" className={styles.h2}>
              From zero to a VM in a minute
            </Heading>
          </div>
          <div className={styles.terminal}>
            <div className={styles.windowBar}>
              <span className={styles.dotRed} />
              <span className={styles.dotYellow} />
              <span className={styles.dotGreen} />
              <div className={styles.tabs} role="tablist">
                {INSTALL_TABS.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    role="tab"
                    aria-selected={t.id === tab}
                    className={clsx(styles.tabBtn, t.id === tab && styles.tabActive)}
                    onClick={() => setTab(t.id)}>
                    {t.label}
                  </button>
                ))}
              </div>
              <button type="button" className={styles.copyBtn} onClick={copy}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className={styles.terminalBody}>
              {current.code.split('\n').map((line) => (
                <div key={line}>
                  <span className={styles.prompt}>$ </span>
                  {line}
                </div>
              ))}
            </pre>
          </div>
          <p className={clsx(styles.footnote, 'text--center')}>{current.note}</p>
        </Reveal>
      </div>
    </section>
  );
}

function Numbers() {
  return (
    <section className={styles.section}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Measured, not promised</p>
            <Heading as="h2" className={styles.h2}>
              Fast enough to be disposable
            </Heading>
            <p className={styles.lead}>
              A saved VM state restores in about two seconds, so an agent can have a clean machine
              for every task instead of sharing one.
            </p>
          </div>
          <div className={styles.stats}>
            {STATS.map((s) => (
              <div key={s.label} className={styles.stat}>
                <span className={styles.statValue}>{s.value}</span>
                <span className={styles.statLabel}>{s.label}</span>
                <span className={styles.statNote}>{s.note}</span>
              </div>
            ))}
          </div>
          <p className={clsx(styles.footnote, 'text--center')}>
            All figures were measured on one Apple M4 with macOS 27.2. Your Mac, disk and image will
            differ. See <Link to="/docs/macos-architecture#15-measured-numbers">where each number comes from</Link>.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function WhatYouCanRun() {
  return (
    <section className={clsx(styles.section, styles.alt)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>What you can run</p>
            <Heading as="h2" className={styles.h2}>
              One API for every kind of machine
            </Heading>
            <p className={styles.lead}>
              Every row is the same REST API, the same <code>fluxctl</code> and the same MCP server
              that FluxVM uses on Linux. Each tag says what has and has not run on real hardware.
            </p>
          </div>
          <div className={styles.grid3}>
            {CAPABILITIES.map((c) => (
              <div key={c.title} className={styles.card}>
                <Heading as="h3">{c.to ? <Link to={c.to}>{c.title}</Link> : c.title}</Heading>
                <p>{c.body}</p>
                <span className={clsx(styles.tag, c.status === 'ok' ? styles.tagOk : styles.tagWarn)}>{c.tag}</span>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function HowItWorks() {
  return (
    <section className={styles.section}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>How it works</p>
            <Heading as="h2" className={styles.h2}>
              The daemon never touches the hypervisor
            </Heading>
            <p className={styles.lead}>
              FluxVM starts one small signed helper, <code>fluxvm-vz-runner</code>, for every VM. The
              runner owns the guest and talks to the daemon over a control socket and a vsock proxy.
              A crash in one guest cannot take the daemon or another VM with it.
            </p>
          </div>
          <img
            className={styles.diagram}
            src={useBaseUrl('/img/macos/architecture.svg')}
            alt="Clients call the FluxVM daemon, which starts one signed runner per VM; Linux, container and macOS guests each run in their own runner"
            loading="lazy"
          />
          <div className={styles.grid3}>
            <div className={styles.card}>
              <Heading as="h3">Warm pool</Heading>
              <p>
                Each warm slot is a stopped VM with its own MAC address and its own snapshot. A new
                sandbox restores one in about two seconds instead of booting.
              </p>
            </div>
            <div className={styles.card}>
              <Heading as="h3">APFS clones</Heading>
              <p>
                Disks and snapshots are copy-on-write clones on the Mac's own file system, so a
                throwaway VM costs almost no disk until it writes.
              </p>
            </div>
            <div className={styles.card}>
              <Heading as="h3">vsock, not the network</Heading>
              <p>
                The guest agent, the egress allow-list and offline sandboxes all use vsock, so a
                sandbox with no network card can still run commands and move files.
              </p>
            </div>
          </div>
          <img
            className={styles.diagram}
            style={{marginTop: '1.5rem'}}
            src={useBaseUrl('/img/macos/warm-pool.svg')}
            alt="Warm pool lifecycle: build a slot, snapshot and stop it, claim it by restoring, delete when done"
            loading="lazy"
          />
          <p className="text--center">
            <Link to="/docs/macos-architecture">Read the full architecture →</Link>
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function MacPicker() {
  const [selected, setSelected] = useState(MACS[1].name);
  const mac = MACS.find((m) => m.name === selected) ?? MACS[0];
  return (
    <div className={styles.picker}>
      <div className={styles.segmented} role="tablist">
        {MACS.map((m) => (
          <button
            key={m.name}
            type="button"
            role="tab"
            aria-selected={m.name === selected}
            className={clsx(styles.segment, m.name === selected && styles.segmentActive)}
            onClick={() => setSelected(m.name)}>
            {m.name}
          </button>
        ))}
      </div>
      <div className={styles.pickerBody}>
        <div>
          <p className={styles.pickerLabel}>What Apple ships</p>
          <p>{mac.role}</p>
        </div>
        <div>
          <p className={styles.pickerLabel}>What it means for FluxVM</p>
          <p>{mac.fluxvm}</p>
        </div>
      </div>
    </div>
  );
}

function ChooseYourMac() {
  return (
    <section className={clsx(styles.section, styles.alt)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Choose your Mac</p>
            <Heading as="h2" className={styles.h2}>
              From a Mac mini to a Mac Studio cluster
            </Heading>
            <p className={styles.lead}>
              Unified memory is the budget: it is shared by macOS, your models and every guest.
              FluxVM does not enforce guest memory on a Mac, so size for the sum.
            </p>
          </div>
          <img
            className={styles.diagram}
            src={useBaseUrl('/img/macos/readme-macs.jpg')}
            alt="Mac mini for home, Mac Studio for a team, MacBook Pro for development"
            loading="lazy"
          />
          <MacPicker />
          <p className={clsx(styles.footnote, 'text--center')}>
            Chips, memory and ports are Apple's figures, read from{' '}
            <a href="https://www.apple.com/mac-mini/specs/">Mac mini</a>,{' '}
            <a href="https://www.apple.com/mac-studio/specs/">Mac Studio</a> and{' '}
            <a href="https://www.apple.com/macbook-pro/specs/">MacBook Pro</a> specs on 2026-10-10. Capacity
            guidance is an estimate, not a measurement; FluxVM has only been run on an Apple M4.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function NewInMacOS() {
  return (
    <section className={styles.section}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>New Macs, new macOS</p>
            <Heading as="h2" className={styles.h2}>
              What macOS 27 adds for virtual machines
            </Heading>
            <p className={styles.lead}>
              The newest Macs ship with macOS 27. Apple's Virtualization.framework gained features that
              FluxVM already has hooks for. They are the reason to run the newest OS on a build host.
            </p>
          </div>
          <div className={styles.grid3}>
            {MACOS27.map((c) => (
              <div key={c.title} className={styles.card}>
                <Heading as="h3">{c.title}</Heading>
                <p>{c.body}</p>
                <span className={clsx(styles.tag, styles.tagWarn)}>{c.tag}</span>
              </div>
            ))}
          </div>
          <p className={clsx(styles.footnote, 'text--center')}>
            From Apple's WWDC26 session{' '}
            <a href="https://developer.apple.com/videos/play/wwdc2026/224/">Expand the capabilities of your Virtualization app</a>.
            Nested virtualization is documented to need an M3 or later and macOS 15; we have not verified it on hardware.
          </p>
        </Reveal>
      </div>
    </section>
  );
}

function Honest(): ReactNode {
  return (
    <section className={styles.section}>
      <div className="container">
        <Reveal>
          <div className={styles.honest}>
            <Heading as="h3">What we have and have not verified</Heading>
            <ul>
              <li>
                Everything marked verified ran on <strong>one Apple M4 with macOS 27.2</strong>. Multi-Mac
                clusters and Thunderbolt model sharding have not been run.
              </li>
              <li>
                A sandbox with a network card sits on an <strong>unfiltered NAT</strong>. Only offline
                and allow-listed sandboxes are isolated from the network.
              </li>
              <li>
                Mac Studio options (displays, bridging, vmnet, balloon, ASIF, provisioning) are
                implemented but mostly not yet verified on hardware. The custom Virtio guest bus (control and bulk),
                host capabilities and fleet placement are the exceptions; the vmnet broker and physical
                USB are not verified.
              </li>
              <li>
                The fleet registry now places <code>vz</code> requests with the Apple scorer, using the
                capabilities each node reports. It was checked on one Mac plus simulated nodes; no
                second Mac has been used.
              </li>
            </ul>
            <p style={{marginTop: '0.75rem', marginBottom: 0}}>
              <Link to="/docs/macos#what-is-verified">The full list →</Link>
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Cta() {
  return (
    <section className={styles.cta}>
      <div className="container">
        <Reveal>
          <Heading as="h2" className={styles.h2}>
            Try it on the Mac you have
          </Heading>
          <p className={styles.ctaSub}>
            Build <code>fluxctl</code>, run <code>fluxctl serve</code>, and create your first VM or
            sandbox through the API.
          </p>
          <div className={styles.buttons}>
            <Link className="button button--primary button--lg" href={`${REPO}#quick-start`}>
              Quick start
            </Link>
            <Link className="button button--outline button--lg button--secondary" to="/docs/macos">
              Mac guide
            </Link>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

export default function MacPage(): ReactNode {
  return (
    <Layout
      title="FluxVM on Mac"
      description="Linux VMs, macOS guests, agent sandboxes and container sandboxes on Apple silicon, through one REST API on Apple's Virtualization.framework.">
      <Hero />
      <main>
        <Numbers />
        <BuiltForMac />
        <VzExplained />
        <RealCapture />
        <WhatYouCanRun />
        <HowItWorks />
        <ChooseYourMac />
        <Install />
        <NewInMacOS />
        <Honest />
        <Cta />
      </main>
    </Layout>
  );
}
