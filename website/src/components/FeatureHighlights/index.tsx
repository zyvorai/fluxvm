import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  description: ReactNode;
  to: string;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Four backends, one control plane',
    description:
      'QEMU/KVM, Cloud Hypervisor, Firecracker, and the in-tree FluxVM hypervisor behind one VmBackend trait, with "backend":"auto" resolution and a vsock guest agent that needs no SSH.',
    to: '/docs/PRODUCT_OVERVIEW',
  },
  {
    title: 'Host-local libvirt replacement',
    description:
      'No libvirtd, no XML domain definitions — a direct command mapping (fluxvm create ≈ virsh define+start, fluxvm delete ≈ virsh destroy) plus a real REST API libvirt doesn\'t have.',
    to: '/docs/POSITIONING',
  },
  {
    title: 'Network Fabric (GA, schema v4)',
    description:
      'TC/eBPF or Cilium-coexistence VM-edge dataplane — IPv4/IPv6 L3+L4 policy, per-VM rate limits, security groups, live reconfigure, and REST observability, nftables as the default fallback.',
    to: '/docs/network-fabric',
  },
  {
    title: 'Kubernetes-native, without KubeVirt',
    description:
      'The DisposableVm CRD (verified end to end against a real k3s cluster, 9/9 checks) and the scheduler-native MicroVM path — a different, lighter model than KubeVirt, not a clone of it.',
    to: '/docs/microvm',
  },
  {
    title: 'TTL-guaranteed cleanup',
    description:
      'ttl_seconds on any VM spec means a forgotten or crashed job still gets torn down. Combined with the Firecracker jailer, cgroup v2, and network.mode:"none", this is the same isolation shape used for sandboxed/untrusted code execution.',
    to: '/docs/use-cases',
  },
  {
    title: 'Multi-host fleets, no Kubernetes required',
    description:
      'fluxvm-agent is a central fleet registry plus per-host heartbeat client with load-aware placement — verified across two real, physically separate hosts.',
    to: '/docs/operations',
  },
];

function Feature({title, description, to}: FeatureItem) {
  return (
    <div className="col col--4">
      <Link to={to} className={styles.card}>
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </Link>
    </div>
  );
}

export default function FeatureHighlights(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
