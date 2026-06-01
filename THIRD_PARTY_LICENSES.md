# Third-Party Licenses — FreeSDN Agent

The FreeSDN agent's own source code is licensed **MIT** (see `LICENSE`). It
depends on third-party packages under their own licenses. The notable
non-permissive ones, and the obligations they carry when the agent is
distributed (e.g. as a PyInstaller-frozen binary), are listed here.

## PySide6 / Qt — LGPL-3.0

The desktop UI uses **PySide6** (Qt for Python), licensed **LGPL-3.0** (with a
separate commercial Qt option). The MIT agent may use and bundle it, provided
the LGPL conditions are met for any **distributed binary**:

- This notice and the LGPL-3.0 license text are included with the distribution.
- The corresponding source of PySide6/Qt is provided or offered (it is freely
  available from https://www.qt.io / https://pypi.org/project/PySide6/).
- The user can **replace** the bundled Qt/PySide6 libraries with their own
  compatible version. FreeSDN distributes Qt as replaceable shared libraries
  (not statically linked), satisfying the LGPL relink requirement.

The **headless daemon** build (`pip install .[daemon]`) omits PySide6 entirely,
so daemon-only deployments carry no Qt/LGPL obligation.

## scapy — GPL-2.0 (OPTIONAL, not in the default install)

Layer-2 capture features (ARP scan, and LLDP/CDP/DHCP passive discovery) use
**scapy**, which is **GPL-2.0-only**. To keep the default agent MIT, scapy is
**not** a default dependency — it ships only via the optional extra:

```
pip install "freesdn-agent[capture]"
```

**Installing the `[capture]` extra subjects that particular deployment to
GPL-2.0** (scapy's terms then govern the combined work). All scapy use in the
agent is lazy and guarded: without the extra, the L2-capture features
auto-disable and the rest of the agent runs normally under MIT. If you
redistribute an agent build that includes scapy, you must comply with GPL-2.0
for that build.

## Everything else

All other dependencies are permissively licensed (MIT / BSD / Apache-2.0 /
ISC / PSF). Run `pip-licenses` against the installed environment for the full
machine-readable inventory.
