import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import FeatureHighlights from '@site/src/components/FeatureHighlights';
import Reveal from '@site/src/components/Reveal';

import styles from './index.module.css';

function HomepageHeader() {
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <div className={clsx(styles.heroGridSingle, 'text--center')}>
          <Heading as="h1" className="hero__title">
            FluxVM
          </Heading>
          <p className="hero__subtitle">
            Secure, isolated virtual machines — via Firecracker, Cloud
            Hypervisor, QEMU/KVM, or the in-tree FluxVM hypervisor — from one
            Rust-native control plane with a real REST API. Run it standalone
            as a libvirt replacement, or as the VM engine under another Zyvor
            product. Use optional TTL and CoW when you want disposable
            compute; longer-lived guests use the same API.
          </p>
          <div className={styles.buttons}>
            <Link
              className="button button--secondary button--lg"
              href="https://github.com/zyvorai/fluxvm#quick-start">
              Get Started
            </Link>
            <Link
              className="button button--outline button--lg button--secondary"
              to="https://github.com/zyvorai/fluxvm">
              View on GitHub
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}

function ProblemStatement() {
  return (
    <section className={styles.problem}>
      <div className="container">
        <Reveal className="row">
          <div className="col col--8 col--offset-2 text--center">
            <Heading as="h2" className={styles.sectionHeading}>
              Why FluxVM
            </Heading>
            <p>
              Teams that need a host-local VM control plane — CI runners,
              sandboxed code execution, per-branch environments, Kubernetes
              VM workloads, or longer-lived guests — are usually stuck
              choosing between manual libvirt/virsh scripting (XML, no REST
              API, no built-in TTL cleanup), a full private-cloud platform
              (disproportionate overhead when you only need a solid VM API),
              or container-only isolation (fine until the workload needs a
              real kernel boundary).
            </p>
            <p>
              FluxVM fills that gap: a Rust-native control plane with a real
              API, no libvirtd, no XML domain definitions —{' '}
              <code>fluxctl create</code> ≈{' '}
              <code>virsh define</code>+<code>start</code>,{' '}
              <code>fluxctl delete</code> ≈ <code>virsh destroy</code>, plus
              optional TTL-guaranteed cleanup when you want disposable
              compute.
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function TrustBand() {
  return (
    <section className={styles.trust}>
      <div className="container">
        <Reveal className={styles.trustGrid}>
          <div>
            <Heading as="h3" className={styles.sectionHeading}>
              Open, and honest about its limits
            </Heading>
            <p>
              Apache-2.0, entire repository, no dual licensing. This is a
              complete MVP/control-plane skeleton, not yet a finished
              multi-tenant security boundary — the jailer, cgroup v2
              control, and per-VM network namespaces are implemented;
              seccomp/AppArmor/SELinux policy, quotas, and audit logging
              still need adding before exposing it to untrusted tenants.
              Network Fabric is GA. Secure Containers is developer preview.
            </p>
            <Link to="https://github.com/zyvorai/fluxvm#maturity-whats-real-today">
              Read the full maturity caveat →
            </Link>
          </div>
          <div className={styles.trustBadges}>
            <img
              src="https://github.com/zyvorai/fluxvm/actions/workflows/ci.yml/badge.svg"
              alt="CI status"
            />
            <img
              src="https://img.shields.io/github/license/zyvorai/fluxvm"
              alt="Apache 2.0 license"
            />
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function EnterpriseCTA() {
  return (
    <section className={styles.enterprise}>
      <div className="container text--center">
        <Reveal>
          <Heading as="h2" className={styles.sectionHeading}>
            Standalone, or part of the Zyvor platform
          </Heading>
          <p className={styles.enterpriseCopy}>
            FluxVM itself is Apache-2.0 with no commercial tier — adopt it
            directly with no other Zyvor product required. It's also the VM
            engine under{' '}
            <Link to="https://github.com/zyvorai/fabric">Zyvor Fabric</Link>{' '}
            and Ragnarok, which do offer production support and SLAs, for
            teams that want the orchestration/UX layer on top.
          </p>
          <Link
            className="button button--primary button--lg"
            href="mailto:sales@zyvor.dev">
            Contact sales@zyvor.dev
          </Link>
        </Reveal>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="FluxVM — Rust-native VM control plane"
      description="Secure, isolated virtual machines via Firecracker, Cloud Hypervisor, QEMU/KVM, and the in-tree FluxVM hypervisor, from one Rust-native control plane. Optional TTL/CoW for disposable workloads.">
      <HomepageHeader />
      <main>
        <ProblemStatement />
        <Reveal>
          <FeatureHighlights />
        </Reveal>
        <TrustBand />
        <EnterpriseCTA />
      </main>
    </Layout>
  );
}
