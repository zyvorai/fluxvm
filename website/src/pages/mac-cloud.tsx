import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import MacCloud from '@site/src/components/MacCloud';
import Reveal from '@site/src/components/Reveal';

import styles from './mac.module.css';

type UseCase = {icon: string; hue: string; title: string; body: string; to: string};

const USE_CASES: UseCase[] = [
  {
    icon: 'CI',
    hue: 'linear-gradient(135deg,#0a84ff,#64d2ff)',
    title: 'Xcode CI on macOS guests',
    body: 'Clone a prepared macOS template per job with APFS, run xcodebuild over SSH, throw it away. Two macOS guests per Mac, so add Macs to add lanes.',
    to: '/docs/macos#macos-guests',
  },
  {
    icon: 'AI',
    hue: 'linear-gradient(135deg,#5e5ce6,#bf5af2)',
    title: 'An agent farm',
    body: 'Disposable Linux sandboxes for coding agents through MCP: TTL, offline or allow-listed egress, changesets, and a warm pool that restores in about 2 s.',
    to: '/docs/macos-sandboxes',
  },
  {
    icon: 'OCI',
    hue: 'linear-gradient(135deg,#30d158,#64d2ff)',
    title: 'Containers, each in a VM',
    body: 'OCI images as lightweight VMs with a read-only root and uid 65534. linux/amd64 images run under Rosetta.',
    to: '/docs/oci-sandboxes',
  },
  {
    icon: 'Dev',
    hue: 'linear-gradient(135deg,#ff9f0a,#ff375f)',
    title: 'Dev boxes for the team',
    body: 'Describe a database, an app and a test runner in fluxvm.toml; fluxctl up --fleet picks the Mac that fits.',
    to: '/docs/macos-stacks',
  },
];

const STEPS: {n: number; title: string; body: string; code: string}[] = [
  {
    n: 1,
    title: 'Run FluxVM on every Mac',
    body: 'A LaunchAgent in a logged-in session, so warm starts and snapshot restore keep working after a reboot.',
    code: 'fluxctl --config ~/.config/fluxvm/fluxvm.toml service install',
  },
  {
    n: 2,
    title: 'Start one fleet registry',
    body: 'Any Mac (or Linux host) can be the registry. It proxies creates and lists to the right node.',
    code: 'fluxvm-agent central --listen 0.0.0.0:7799',
  },
  {
    n: 3,
    title: 'Register each Mac',
    body: 'Every 10 s the node reports free CPU and memory, its macOS guest count and what Virtualization.framework can do on that Mac.',
    code: [
      'fluxvm-agent node --name studio-1 \\',
      '  --central http://fleet-registry:7799 \\',
      '  --advertise-url http://studio-1.local:7788',
    ].join('\n'),
  },
  {
    n: 4,
    title: 'Ask the fleet, not a Mac',
    body: 'With backend vz, the Apple scorer skips Macs that lack the feature or already run two macOS guests, and packs small VMs tightly.',
    code: [
      'curl -X POST fleet-registry:7799/fleet/vms \\',
      '  -H \'Content-Type: application/json\' \\',
      '  -d \'{"name":"ci-1","backend":"vz","image":"debian-13"}\'',
    ].join('\n'),
  },
];

function Hero() {
  return (
    <header className={styles.hero}>
      <div className="container">
        <div className={styles.pills}>
          <span className={styles.pill}>Mac mini</span>
          <span className={styles.pill}>Mac Studio</span>
          <span className={clsx(styles.pill, styles.pillBlue)}>vz fleet</span>
          <span className={styles.pill}>10 GbE &middot; Thunderbolt 5</span>
        </div>
        <Heading as="h1" className={styles.heroTitle}>
          Build a <span className={styles.gradientText}>Mac cloud</span>
          <br />
          from the Macs you have.
        </Heading>
        <p className={styles.heroSub}>
          A shelf of Mac minis and Mac Studios becomes one API: macOS guests for Xcode CI, Linux VMs,
          agent sandboxes and container VMs, placed on the Mac that fits.
        </p>
        <div className={styles.buttons}>
          <Link className="button button--primary button--lg" to="/docs/mac-cloud">
            Read the guide
          </Link>
          <Link className="button button--outline button--lg button--secondary" to="/mac">
            FluxVM on one Mac
          </Link>
        </div>
        <MacCloud caption="Illustration. Fleet placement is verified on one real Mac plus simulated nodes; no second Mac has been used yet." />
      </div>
    </header>
  );
}

function UseCases() {
  return (
    <section className={clsx(styles.section, styles.alt)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>What people build</p>
            <Heading as="h2" className={styles.h2}>
              One fleet, every kind of machine
            </Heading>
          </div>
          <div className={styles.grid4}>
            {USE_CASES.map((u) => (
              <div key={u.title} className={styles.perk}>
                <span className={styles.perkIcon} style={{background: u.hue}}>
                  {u.icon}
                </span>
                <Heading as="h3">
                  <Link to={u.to}>{u.title}</Link>
                </Heading>
                <p>{u.body}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Steps() {
  return (
    <section className={styles.section}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Four steps</p>
            <Heading as="h2" className={styles.h2}>
              From a shelf of Macs to one API
            </Heading>
          </div>
          <div className={styles.grid4}>
            {STEPS.map((s) => (
              <div key={s.n} className={styles.perk}>
                <span className={styles.perkIcon} style={{background: 'linear-gradient(135deg,#0a84ff,#5e5ce6)'}}>
                  {s.n}
                </span>
                <Heading as="h3">{s.title}</Heading>
                <p>{s.body}</p>
              </div>
            ))}
          </div>
          <div className={styles.terminal} style={{marginTop: '2rem'}}>
            <div className={styles.windowBar}>
              <span className={styles.dotRed} />
              <span className={styles.dotYellow} />
              <span className={styles.dotGreen} />
              <span className={styles.windowTitle}>Terminal &mdash; zsh</span>
            </div>
            <pre className={styles.terminalBody}>
              {STEPS.map((s, i) => (
                <div key={s.n}>
                  <span className={styles.prompt}># {s.n}. {s.title}</span>
                  {'\n'}
                  {s.code}
                  {i < STEPS.length - 1 && '\n\n'}
                </div>
              ))}
            </pre>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Checklist() {
  return (
    <section className={clsx(styles.section, styles.alt)}>
      <div className="container">
        <Reveal>
          <div className="text--center">
            <p className={styles.kicker}>Before you rack it</p>
            <Heading as="h2" className={styles.h2}>
              A headless Mac, done right
            </Heading>
          </div>
          <div className={styles.grid3}>
            <div className={styles.card}>
              <Heading as="h3">Stay logged in</Heading>
              <p>
                Virtualization.framework restores saved state only in an unlocked session. Use a
                dedicated user with automatic login and the screen lock off.
              </p>
            </div>
            <div className={styles.card}>
              <Heading as="h3">One APFS volume</Heading>
              <p>
                Keep templates and VM state on the same volume so clones are instant. A clone across
                volumes is a full copy of a 20+ GB disk.
              </p>
            </div>
            <div className={styles.card}>
              <Heading as="h3">Size for unified memory</Heading>
              <p>
                FluxVM does not cap guest memory on a Mac. Budget macOS, your models and every guest
                together; the scheduler keeps headroom.
              </p>
            </div>
          </div>
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
            <Heading as="h3">What is and is not verified</Heading>
            <ul>
              <li>
                Everything marked verified ran on <strong>one Apple M4 with macOS 27.2</strong>.
              </li>
              <li>
                <code>vz</code> placement in <code>fluxvm-agent central</code> was checked with one
                real Mac and simulated nodes. No multi-Mac fleet has run on real hardware yet.
              </li>
              <li>Thunderbolt RDMA, the shared vmnet broker and physical USB passthrough are not verified.</li>
            </ul>
            <p style={{marginTop: '0.75rem', marginBottom: 0}}>
              <Link to="/docs/macos-cluster#verified-and-not-verified">The full list &rarr;</Link>
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

export default function MacCloudPage(): ReactNode {
  return (
    <Layout
      title="Build a Mac cloud"
      description="Turn Mac minis and Mac Studios into one VM API with FluxVM: macOS guests for Xcode CI, Linux VMs, agent sandboxes and container VMs on Apple's Virtualization.framework.">
      <Hero />
      <main>
        <UseCases />
        <Steps />
        <Checklist />
        <Honest />
      </main>
    </Layout>
  );
}
