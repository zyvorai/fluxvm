import type {ReactNode} from 'react';
import clsx from 'clsx';
import useBaseUrl from '@docusaurus/useBaseUrl';

import styles from './styles.module.css';

type MacCloudProps = {
  className?: string;
  caption?: ReactNode;
};

/**
 * The animated Mac cloud illustration: a FluxVM control plane placing vz guests on Mac Studios and
 * Mac minis. The SVG animates itself (CSS inside the file) and honours prefers-reduced-motion, so it
 * also animates when embedded as an image in the README.
 */
export default function MacCloud({className, caption}: MacCloudProps): ReactNode {
  return (
    <figure className={clsx(styles.frame, className)}>
      <div className={styles.glow} aria-hidden="true" />
      <img
        className={styles.art}
        src={useBaseUrl('/img/mac-cloud.svg')}
        width={1600}
        height={900}
        alt="A FluxVM control plane placing vz virtual machines on two Mac Studios and two Mac minis linked by Thunderbolt 5 and 10 GbE: a macOS guest, an agent sandbox, a container VM and a Debian guest with Rosetta"
      />
      {caption && <figcaption className={styles.caption}>{caption}</figcaption>}
    </figure>
  );
}
