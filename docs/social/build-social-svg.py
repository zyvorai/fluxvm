import sys  # usage: python3 docs/social/build-social-svg.py docs/assets
LIGHT = dict(
    bg0="#ffffff", bg1="#f5f5f7", wash="#0071e3", wash_op="0.10", wash2_op="0.05",
    ink="#1d1d1f", sec="#6e6e73", card="#ffffff", card_stroke="#d2d2d7", shadow_op="0.10",
    blue0="#0071e3", blue1="#2997ff", link="#0071e3",
    chip_fill="#e8f2fd", chip_text="#0066cc", chip_stroke="#b9d7f7",
    wire="#0071e3", grid_op="0.0", tile_txt="#ffffff", api_sub="#dcecff", card_hi="#0071e3",
    hair="#e5e5ea")
DARK = dict(
    bg0="#000000", bg1="#0b0b0f", wash="#2997ff", wash_op="0.20", wash2_op="0.08",
    ink="#f5f5f7", sec="#a1a1a6", card="#1c1c1e", card_stroke="#3a3a3c", shadow_op="0.55",
    blue0="#0a84ff", blue1="#5eb0ff", link="#2997ff",
    chip_fill="#0b2542", chip_text="#66b2ff", chip_stroke="#17426f",
    wire="#2997ff", grid_op="0.0", tile_txt="#ffffff", api_sub="#d6e9ff", card_hi="#2997ff",
    hair="#2c2c2e")

def svg(p):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640" role="img" aria-label="FluxVM — Real VMs. Real API. One Rust control plane and one REST API for Firecracker, Cloud Hypervisor, QEMU/KVM, the FluxVM hypervisor and Apple Virtualization.framework (vz) on a Mac. No libvirtd, no XML.">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="640" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{p['bg0']}"/>
      <stop offset="1" stop-color="{p['bg1']}"/>
    </linearGradient>
    <radialGradient id="wash" cx="1010" cy="300" r="520" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{p['wash']}" stop-opacity="{p['wash_op']}"/>
      <stop offset="0.6" stop-color="{p['wash']}" stop-opacity="{p['wash2_op']}"/>
      <stop offset="1" stop-color="{p['wash']}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="blue" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{p['blue0']}"/>
      <stop offset="1" stop-color="{p['blue1']}"/>
    </linearGradient>
    <linearGradient id="blueText" x1="78" y1="0" x2="470" y2="0" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{p['blue0']}"/>
      <stop offset="1" stop-color="{p['blue1']}"/>
    </linearGradient>
    <linearGradient id="wire" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{p['wire']}" stop-opacity="0.9"/>
      <stop offset="1" stop-color="{p['wire']}" stop-opacity="0.35"/>
    </linearGradient>
    <linearGradient id="mac" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#5e5ce6"/>
      <stop offset="1" stop-color="#bf5af2"/>
    </linearGradient>
    <filter id="shadow" x="-20%" y="-30%" width="140%" height="180%" color-interpolation-filters="sRGB">
      <feGaussianBlur in="SourceAlpha" stdDeviation="9"/>
      <feOffset dy="8" result="b"/>
      <feColorMatrix in="b" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 {p['shadow_op']} 0" result="s"/>
      <feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow" x="-30%" y="-40%" width="160%" height="200%" color-interpolation-filters="sRGB">
      <feGaussianBlur in="SourceAlpha" stdDeviation="14"/>
      <feOffset dy="12" result="b"/>
      <feColorMatrix in="b" type="matrix" values="0 0 0 0 0.0  0 0 0 0 0.35  0 0 0 0 0.9  0 0 0 0.30 0" result="s"/>
      <feMerge><feMergeNode in="s"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>

  <rect width="1280" height="640" fill="url(#bg)"/>
  <rect width="1280" height="640" fill="url(#wash)"/>

  <!-- brand lockup -->
  <rect x="80" y="64" width="64" height="64" rx="15" fill="url(#blue)"/>
  <path d="M96.5 79.5 127.5 79.5 96.5 112.5 127.5 112.5" fill="none" stroke="#ffffff"
        stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="162" y="108" font-family="'Helvetica Neue',Helvetica,Arial,sans-serif"
        font-size="40" font-weight="700" fill="{p['ink']}" letter-spacing="-0.8">FluxVM</text>

  <!-- headline -->
  <text font-family="'Helvetica Neue',Helvetica,Arial,sans-serif" font-size="80" font-weight="700"
        letter-spacing="-2.4">
    <tspan x="76" y="252" fill="{p['ink']}">Real VMs.</tspan>
    <tspan x="76" y="336" fill="url(#blueText)">Real API.</tspan>
  </text>

  <!-- sub -->
  <g font-family="'Helvetica Neue',Helvetica,Arial,sans-serif" font-size="26" fill="{p['sec']}">
    <text x="80" y="398">One Rust control plane. One REST API.</text>
    <text x="80" y="434">No libvirtd, no XML.</text>
  </g>

  <!-- proof chips -->
  <g font-family="'Menlo','JetBrains Mono',monospace" font-size="17" font-weight="700" fill="{p['chip_text']}">
    <rect x="80" y="478" width="222" height="46" rx="23" fill="{p['chip_fill']}" stroke="{p['chip_stroke']}"/>
    <text x="102" y="507">Network Fabric GA</text>
    <rect x="316" y="478" width="150" height="46" rx="23" fill="{p['chip_fill']}" stroke="{p['chip_stroke']}"/>
    <text x="338" y="507">Apache-2.0</text>
    <rect x="480" y="478" width="242" height="46" rx="23" fill="{p['chip_fill']}" stroke="{p['chip_stroke']}"/>
    <text x="502" y="507">k3s + 2-host tested</text>
    <rect x="736" y="478" width="196" height="46" rx="23" fill="url(#mac)"/>
    <text x="758" y="507" fill="#ffffff">macOS &#183; vz</text>
  </g>

  <!-- diagram: one API fans out to five VMMs -->
  <g>
    <g fill="none" stroke="url(#wire)" stroke-width="2.5" stroke-linecap="round">
      <path d="M912 320 C 940 320, 940 152, 956 152"/>
      <path d="M912 320 C 940 320, 940 236, 956 236"/>
      <path d="M912 320 C 940 320, 940 320, 956 320"/>
      <path d="M912 320 C 940 320, 940 404, 956 404"/>
      <path d="M912 320 C 940 320, 940 488, 956 488"/>
    </g>
    <g fill="{p['wire']}">
      <circle cx="912" cy="320" r="5.5"/>
      <circle cx="956" cy="152" r="4.5"/>
      <circle cx="956" cy="236" r="4.5"/>
      <circle cx="956" cy="320" r="4.5"/>
      <circle cx="956" cy="404" r="4.5"/>
      <circle cx="956" cy="488" r="4.5"/>
    </g>

    <rect x="722" y="262" width="190" height="116" rx="26" fill="url(#blue)" filter="url(#glow)"/>
    <text x="817" y="312" text-anchor="middle" font-family="'Helvetica Neue',Helvetica,Arial,sans-serif"
          font-size="30" font-weight="700" fill="#ffffff">REST API</text>
    <text x="817" y="346" text-anchor="middle" font-family="'Menlo','JetBrains Mono',monospace"
          font-size="16" fill="{p['api_sub']}">fluxctl serve</text>

    <g font-family="'Helvetica Neue',Helvetica,Arial,sans-serif">
      <rect x="964" y="124" width="262" height="56" rx="14" fill="{p['card']}" stroke="{p['card_stroke']}" filter="url(#shadow)"/>
      <text x="984" y="149" font-size="19" font-weight="700" fill="{p['ink']}">Firecracker</text>
      <text x="984" y="169" font-size="13" font-family="'Menlo',monospace" fill="{p['sec']}">microVM &#183; jailer</text>
      <rect x="964" y="208" width="262" height="56" rx="14" fill="{p['card']}" stroke="{p['card_stroke']}" filter="url(#shadow)"/>
      <text x="984" y="233" font-size="19" font-weight="700" fill="{p['ink']}">Cloud Hypervisor</text>
      <text x="984" y="253" font-size="13" font-family="'Menlo',monospace" fill="{p['sec']}">Rust VMM</text>
      <rect x="964" y="292" width="262" height="56" rx="14" fill="{p['card']}" stroke="{p['card_stroke']}" filter="url(#shadow)"/>
      <text x="984" y="317" font-size="19" font-weight="700" fill="{p['ink']}">QEMU / KVM</text>
      <text x="984" y="337" font-size="13" font-family="'Menlo',monospace" fill="{p['sec']}">qcow2 &#183; QMP</text>
      <rect x="964" y="376" width="262" height="56" rx="14" fill="{p['card']}" stroke="{p['card_hi']}" stroke-opacity="0.75" stroke-width="1.5" filter="url(#shadow)"/>
      <text x="984" y="401" font-size="19" font-weight="700" fill="{p['ink']}">FluxVM hypervisor</text>
      <text x="984" y="421" font-size="13" font-family="'Menlo',monospace" fill="{p['sec']}">snapshots &#183; sandboxes</text>
      <circle cx="1208" cy="394" r="5" fill="#ff6a2a"/>
      <rect x="964" y="460" width="262" height="56" rx="14" fill="{p['card']}" stroke="url(#mac)" stroke-width="1.5" filter="url(#shadow)"/>
      <text x="984" y="485" font-size="19" font-weight="700" fill="{p['ink']}">Apple vz</text>
      <text x="984" y="505" font-size="13" font-family="'Menlo',monospace" fill="{p['sec']}">Virtualization.framework</text>
      <circle cx="1208" cy="478" r="5" fill="#bf5af2"/>
    </g>
  </g>

  <!-- footer -->
  <line x1="80" y1="556" x2="1200" y2="556" stroke="{p['hair']}" stroke-width="1"/>
  <text x="80" y="598" font-family="'Helvetica Neue',Helvetica,Arial,sans-serif" font-size="18"
        fill="{p['sec']}">Secure, isolated VMs on Linux and macOS · Host-local libvirt replacement</text>
  <text x="1200" y="586" text-anchor="end" font-family="'Menlo','JetBrains Mono',monospace"
        font-size="16" fill="{p['sec']}">github.com/zyvorai/fluxvm</text>
  <text x="1200" y="614" text-anchor="end" font-family="'Helvetica Neue',Helvetica,Arial,sans-serif"
        font-size="24" font-weight="700" fill="{p['link']}">zyvor.dev</text>
</svg>
'''
out=sys.argv[1]
open(f"{out}/social-preview.svg","w").write(svg(LIGHT))
open(f"{out}/social-preview-dark.svg","w").write(svg(DARK))
