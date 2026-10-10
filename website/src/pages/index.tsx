import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import MacCloud from '@site/src/components/MacCloud';
import MacHardware from '@site/src/components/MacHardware';
import Reveal from '@site/src/components/Reveal';

import styles from './index.module.css';

const REPO = 'https://github.com/zyvorai/zyvor-fluxvm';

function Chevron({children, to, href}: {children: ReactNode; to?: string; href?: string}) {
  return (
    <Link className={styles.chevron} to={to} href={href}>
      {children}
      <span aria-hidden="true"> &rsaquo;</span>
    </Link>
  );
}

function Hero() {
  return (
    <header className={styles.hero}>
      <div className={styles.heroInner}>
        <p className={styles.eyebrow}>FluxVM</p>
        <Heading as="h1" className={styles.heroTitle}>
          Real VMs.
          <br />
          <span className={styles.gradient}>Real API.</span>
        </Heading>
        <p className={styles.heroSub}>
          One Rust control plane for every hypervisor. Now with a Mac cloud.
        </p>
        <div className={styles.heroCtas}>
          <Link className={styles.pillPrimary} to="/mac">
            Explore Mac
          </Link>
          <Link className={styles.pillGhost} href={`${REPO}#quickstart`}>
            Get started
          </Link>
        </div>
      </div>
      <div className={styles.heroArt}>
        <MacCloud />
      </div>
    </header>
  );
}

function ProductTiles() {
  return (
    <section className={styles.tiles}>
      <Reveal className={clsx(styles.tile, styles.tileDark)}>
        <div className={styles.tileCopy}>
          <Heading as="h2" className={styles.tileTitle}>
            Mac mini
          </Heading>
          <p className={styles.tileSub}>A quiet host for a lot of VMs.</p>
          <div className={styles.tileLinks}>
            <Chevron to="/mac">Learn more</Chevron>
            <Chevron to="/docs/mac-cloud">Set one up</Chevron>
          </div>
        </div>
        <MacHardware kind="mini" className={styles.hardware} />
        <p className={styles.tileFoot}>Agent sandboxes &middot; container VMs &middot; Linux dev boxes</p>
      </Reveal>
      <Reveal className={clsx(styles.tile, styles.tileStudio)} delay={120}>
        <div className={styles.tileCopy}>
          <Heading as="h2" className={styles.tileTitle}>
            Mac Studio
          </Heading>
          <p className={styles.tileSub}>A cloud on your desk.</p>
          <div className={styles.tileLinks}>
            <Chevron to="/mac-cloud">Build a Mac cloud</Chevron>
            <Chevron to="/docs/macos#macos-guests">macOS guests</Chevron>
          </div>
        </div>
        <MacHardware kind="studio" className={styles.hardware} />
        <p className={styles.tileFoot}>Xcode CI on macOS guests &middot; many VMs next to large models</p>
      </Reveal>
      <Reveal className={clsx(styles.tile, styles.tileLight)}>
        <div className={styles.tileCopy}>
          <Heading as="h2" className={styles.tileTitle}>
            Agent sandboxes
          </Heading>
          <p className={styles.tileSub}>A clean machine for every task.</p>
          <div className={styles.tileLinks}>
            <Chevron to="/docs/macos-sandboxes">Learn more</Chevron>
            <Chevron to="/docs/mcp">Use with MCP</Chevron>
          </div>
        </div>
        <div className={styles.term}>
          <div className={styles.termBar}>
            <span />
            <span />
            <span />
          </div>
          <pre>
            <span className={styles.ok}>$</span> fluxctl sandbox create --ttl 15m --offline{'\n'}
            <span className={styles.dim}>  ready in 2.1 s (warm pool)</span>
            {'\n'}
            <span className={styles.ok}>$</span> fluxctl exec sb1 -- make test{'\n'}
            <span className={styles.ok}>  &#10003; 128 passed</span>
          </pre>
        </div>
      </Reveal>
      <Reveal className={clsx(styles.tile, styles.tileBlue)} delay={120}>
        <div className={styles.tileCopy}>
          <Heading as="h2" className={styles.tileTitle}>
            Every hypervisor
          </Heading>
          <p className={styles.tileSub}>One spec. One API. Five backends.</p>
          <div className={styles.tileLinks}>
            <Chevron to="/docs/PRODUCT_OVERVIEW">Learn more</Chevron>
            <Chevron to="/docs/api">See the API</Chevron>
          </div>
        </div>
        <div className={styles.backends}>
          {['Firecracker', 'Cloud Hypervisor', 'QEMU / KVM', 'FluxVM hypervisor', 'vz on Mac'].map((b, i) => (
            <span key={b} className={clsx(styles.backend, i === 4 && styles.backendMac)}>
              {b}
            </span>
          ))}
        </div>
      </Reveal>
    </section>
  );
}

function Statement() {
  return (
    <section className={styles.statement}>
      <Reveal>
        <p className={styles.statementText}>
          No libvirtd. No XML.{' '}
          <span className={styles.gradient}>Just a JSON spec, a REST API and a vsock agent</span>{' '}
          that does the same thing on a Linux server and on the Mac on your desk.
        </p>
      </Reveal>
    </section>
  );
}

const NUMBERS = [
  {value: '~2 s', label: 'Warm start on a Mac', note: 'restore a saved VM instead of booting'},
  {value: '0.7 s', label: 'Snapshot', note: 'a running VM, APFS-cloned disk'},
  {value: '5', label: 'Backends', note: 'four on Linux, vz on a Mac'},
  {value: '3', label: 'SDKs', note: 'Python, Go and TypeScript'},
];

function Numbers() {
  return (
    <section className={styles.numbers}>
      <Reveal>
        <div className={styles.numberGrid}>
          {NUMBERS.map((n) => (
            <div key={n.label} className={styles.number}>
              <span className={styles.numberValue}>{n.value}</span>
              <span className={styles.numberLabel}>{n.label}</span>
              <span className={styles.numberNote}>{n.note}</span>
            </div>
          ))}
        </div>
        <p className={styles.numbersFoot}>
          Mac figures measured on one Apple M4 with macOS 27.2.{' '}
          <Link to="/docs/macos#what-is-verified">What is verified</Link>
        </p>
      </Reveal>
    </section>
  );
}

const MAC_LOVES = [
  {t: 'Apple silicon native', d: 'A signed Swift runner per VM. No QEMU, no emulation.'},
  {t: 'Rosetta inside Linux', d: 'x86_64 binaries and linux/amd64 images in arm64 guests.'},
  {t: 'APFS clones', d: 'Copy-on-write disks. A throwaway VM costs almost nothing.'},
  {t: 'Keychain sign-in', d: 'Guest passwords live in your login Keychain, never the API.'},
  {t: 'Shared folders', d: 'Edit on macOS, build in Linux, over virtiofs.'},
  {t: 'launchd service', d: 'fluxctl service install. Up after every reboot.'},
];

function MacLoves() {
  return (
    <section className={styles.loves}>
      <Reveal>
        <p className={styles.eyebrowBlue}>Built for Mac people</p>
        <Heading as="h2" className={styles.lovesTitle}>
          Feels right at home on macOS.
        </Heading>
        <div className={styles.lovesGrid}>
          {MAC_LOVES.map((l) => (
            <div key={l.t} className={styles.love}>
              <Heading as="h3">{l.t}</Heading>
              <p>{l.d}</p>
            </div>
          ))}
        </div>
        <div className={styles.lovesCta}>
          <Chevron to="/mac">Everything FluxVM does on a Mac</Chevron>
        </div>
      </Reveal>
    </section>
  );
}

function Platform() {
  return (
    <section className={styles.platform}>
      <Reveal className={styles.platformGrid}>
        <div className={styles.platformCard}>
          <Heading as="h3">On Linux</Heading>
          <p>
            Native eBPF networking, Secure Containers (GA), a Kubernetes operator without KubeVirt, live
            backups and a fleet registry.
          </p>
          <Chevron to="/docs/network-fabric">Network Fabric</Chevron>
        </div>
        <div className={styles.platformCard}>
          <Heading as="h3">For AI agents</Heading>
          <p>
            An MCP server, egress allow-lists on method, host and path, file change-sets and VM fork for
            disposable machines.
          </p>
          <Chevron to="/docs/mcp">MCP server</Chevron>
        </div>
        <div className={styles.platformCard}>
          <Heading as="h3">Open source</Heading>
          <p>
            Apache-2.0, the whole repository. Every claim on this site links to what has and has not been
            verified.
          </p>
          <Chevron href={REPO}>GitHub</Chevron>
        </div>
      </Reveal>
    </section>
  );
}

function Closing() {
  return (
    <section className={styles.closing}>
      <Reveal>
        <MacHardware kind="mini" className={styles.closingArt} />
        <Heading as="h2" className={styles.closingTitle}>
          Your Mac cloud starts
          <br />
          with one Mac.
        </Heading>
        <div className={styles.heroCtas}>
          <Link className={styles.pillPrimary} href={`${REPO}#your-own-mac-cloud`}>
            Get started
          </Link>
          <Link className={styles.pillGhost} href="mailto:sales@zyvor.dev">
            Talk to Zyvor
          </Link>
        </div>
      </Reveal>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="FluxVM: real VMs, real API, your own Mac cloud"
      description="One Rust control plane for Firecracker, Cloud Hypervisor, QEMU/KVM, the FluxVM hypervisor and Apple's Virtualization.framework. Linux VMs, macOS guests and agent sandboxes on a Mac mini or Mac Studio.">
      <Hero />
      <main className={styles.main}>
        <ProductTiles />
        <Statement />
        <Numbers />
        <MacLoves />
        <Platform />
        <Closing />
      </main>
    </Layout>
  );
}
