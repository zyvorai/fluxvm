import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import FeatureHighlights from '@site/src/components/FeatureHighlights';

import styles from './index.module.css';

function HomepageHeader() {
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <div className={styles.heroGridSingle}>
          <div className="text--center">
            <Heading as="h1" className="hero__title">
              Disposable Compute Engine
            </Heading>
            <p className="hero__subtitle">
              Create secure, isolated, short-lived virtual machines — via
              Firecracker, Cloud Hypervisor, QEMU/KVM, or the in-tree FluxVM
              hypervisor — from one Rust-native control plane with a real
              REST API. Run it standalone as a libvirt replacement, or as
              the VM engine under another Zyvor product; it's the same
              binary and the same API either way.
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
      </div>
    </header>
  );
}

function ProblemStatement() {
  return (
    <section className={styles.problem}>
      <div className="container">
        <div className="row">
          <div className="col col--8 col--offset-2 text--center">
            <Heading as="h2">Why FluxVM</Heading>
            <p>
              Teams that need short-lived, isolated VMs — CI runners,
              sandboxed code execution, per-branch dev environments,
              Kubernetes-native disposable workloads — are usually stuck
              choosing between manual libvirt/virsh scripting (XML, no REST
              API, no built-in TTL cleanup), a full private-cloud platform
              (disproportionate overhead for something meant to be
              lightweight and short-lived), or container-only isolation
              (fine until the workload needs a real kernel boundary).
            </p>
            <p>
              FluxVM fills that specific gap: a control plane built around
              VMs that are supposed to be short-lived, with a real API and
              no libvirtd, no XML domain definitions, and TTL-guaranteed
              cleanup — <code>fluxvm create</code> ≈{' '}
              <code>virsh define</code>+<code>start</code>,{' '}
              <code>fluxvm delete</code> ≈ <code>virsh destroy</code>, plus
              a REST API libvirt doesn't have.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function TrustBand() {
  return (
    <section className={styles.trust}>
      <div className="container">
        <div className={styles.trustGrid}>
          <div>
            <Heading as="h3">Open, and honest about its limits</Heading>
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
        </div>
      </div>
    </section>
  );
}

function EnterpriseCTA() {
  return (
    <section className={styles.enterprise}>
      <div className="container text--center">
        <Heading as="h2">Standalone, or part of the Zyvor platform</Heading>
        <p>
          FluxVM itself is Apache-2.0 with no commercial tier — adopt it
          directly with no other Zyvor product required. It's also the VM
          engine under <Link to="https://github.com/zyvorai/fabric">Zyvor Fabric</Link> and{' '}
          Ragnarok, which do offer production support and SLAs, for teams
          that want the orchestration/UX layer on top.
        </p>
        <Link
          className="button button--primary button--lg"
          href="mailto:sales@zyvor.dev">
          Contact sales@zyvor.dev
        </Link>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="FluxVM — Disposable Compute Engine"
      description="Create secure, isolated, short-lived virtual machines via Firecracker, Cloud Hypervisor, QEMU/KVM, and the in-tree FluxVM hypervisor, from one Rust-native control plane.">
      <HomepageHeader />
      <main>
        <ProblemStatement />
        <FeatureHighlights />
        <TrustBand />
        <EnterpriseCTA />
      </main>
    </Layout>
  );
}
