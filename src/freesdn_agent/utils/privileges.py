"""
Privilege checking utilities for FreeSDN Agent.

Raw socket operations (ARP scanning) require administrator/root privileges.
"""

import logging
import os
import sys

logger = logging.getLogger(__name__)


#: Linux capability number for CAP_NET_RAW (linux/capability.h).
_CAP_NET_RAW = 13


def _linux_has_cap_net_raw() -> bool:
    """Does this process hold CAP_NET_RAW, without being root?

    Reads the effective capability set from ``/proc/self/status``. The kernel
    prints it as a 16-hex-digit mask, one bit per capability.

    This exists because the agent's OWN SHIPPED DEPLOYMENT is exactly this case.
    ``packaging/installers/build_deb.sh`` writes a unit with::

        User=freesdn-agent
        AmbientCapabilities=CAP_NET_RAW

    A euid check calls that unprivileged, so the .deb install advertised no ARP
    scanner and skipped every REQUIRES_ROOT listener -- including passive LLDP,
    the daemon's topology source -- while holding the one capability those need.
    Dropping root and granting a single capability is the correct way to run
    this, and the privilege check punished it.
    """
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    mask = int(line.split(":", 1)[1].strip(), 16)
                    return bool(mask >> _CAP_NET_RAW & 1)
    except (OSError, ValueError):
        # No procfs, or a shape we do not recognise. Fall back to the euid
        # check rather than guessing upward: claiming a capability we cannot
        # prove would turn a clean "skipped, no privilege" into a scanner that
        # fails at the socket.
        pass
    return False


def has_raw_socket_capability() -> bool:
    """Can this process open raw sockets?

    The single answer for the whole agent. Three modules used to ask this
    separately (``utils.privileges``, ``listeners.base``, ``services.capabilities``)
    and all three asked ``os.geteuid() == 0``, which is wrong for the packaged
    Linux deployment and had to be fixed in three places to be fixed at all.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning(f"Failed to check Windows admin status: {e}")
            return False

    try:
        if os.geteuid() == 0:
            return True
    except AttributeError:
        return False

    # Not root. On Linux a capability alone is enough, and is how we ship.
    if sys.platform.startswith("linux"):
        return _linux_has_cap_net_raw()
    return False


def check_admin_privileges() -> bool:
    """
    Check whether the agent can perform privileged network operations.

    Kept as the historical name; ``has_raw_socket_capability`` is what it means.
    """
    return has_raw_socket_capability()


def request_elevation() -> bool:
    """
    Request elevation of privileges (Windows only).

    On Windows, this will trigger a UAC prompt to restart with admin rights.
    On Unix systems, users should run with sudo manually.

    Returns:
        True if elevation was requested (Windows), False otherwise.
    """
    if sys.platform == "win32":
        try:
            import ctypes

            # Get the Python executable path
            python_exe = sys.executable

            # Build the command arguments
            # When running as a module (-m), we need to handle it properly
            if len(sys.argv) > 0 and sys.argv[0].endswith('__main__.py'):
                # Running as module (python -m freesdn_agent)
                # We need to set PYTHONPATH and run with -m
                # Get the src directory from the module path
                import freesdn_agent
                module_dir = os.path.dirname(os.path.dirname(freesdn_agent.__file__))

                # Create a batch file to set env and run - this is more reliable
                import tempfile
                batch_content = f'''@echo off
set PYTHONPATH={module_dir}
"{python_exe}" -m freesdn_agent
'''
                # write the helper into a per-invocation PRIVATE temp
                # directory with an unpredictable name (mkdtemp creates it with a
                # current-user-only ACL on Windows) and create the file with
                # O_EXCL so we never follow a pre-planted file/symlink. The old
                # code used a fixed, world-knowable path
                # (%TEMP%\\freesdn_agent\\run_elevated.bat) that a co-resident
                # local attacker could plant/replace before the UAC runas,
                # substituting arbitrary commands to run elevated.
                batch_dir = tempfile.mkdtemp(prefix='freesdn_agent_elev_')
                batch_path = os.path.join(batch_dir, 'run_elevated.bat')

                _fd = os.open(
                    batch_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                with os.fdopen(_fd, 'w') as f:
                    f.write(batch_content)

                logger.info(f"Requesting elevation via batch: {batch_path}")

                result = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    batch_path,
                    None,
                    None,
                    1  # SW_SHOWNORMAL
                )
            elif hasattr(sys, 'frozen'):
                # Running as frozen executable (PyInstaller, etc.)
                # Quote arguments with spaces
                quoted_args = []
                for arg in sys.argv[1:]:
                    if ' ' in arg:
                        quoted_args.append(f'"{arg}"')
                    else:
                        quoted_args.append(arg)

                params = ' '.join(quoted_args)
                logger.info(f"Requesting elevation: {python_exe} {params}")

                result = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    python_exe,
                    params,
                    None,
                    1  # SW_SHOWNORMAL
                )
            else:
                # Running as script - use the script path directly
                script_path = sys.argv[0]
                quoted_args = [f'"{script_path}"']
                for arg in sys.argv[1:]:
                    if ' ' in arg:
                        quoted_args.append(f'"{arg}"')
                    else:
                        quoted_args.append(arg)

                params = ' '.join(quoted_args)
                logger.info(f"Requesting elevation: {python_exe} {params}")

                result = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    python_exe,
                    params,
                    None,
                    1  # SW_SHOWNORMAL
                )

            # ShellExecuteW returns > 32 on success
            if result > 32:
                logger.info("Elevation requested successfully")
                return True
            else:
                logger.error(f"ShellExecuteW failed with code: {result}")
                return False

        except Exception as e:
            logger.error(f"Failed to request elevation: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    else:
        logger.info("On Unix systems, please run with sudo for full functionality")
        return False


def show_privilege_warning(parent=None) -> None:
    """
    Show a warning dialog about limited functionality without admin privileges.

    Args:
        parent: Parent widget for the dialog (optional)
    """
    try:
        from PySide6.QtWidgets import QMessageBox

        msg = QMessageBox(parent)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Limited Functionality")
        msg.setText("FreeSDN Agent is running without administrator privileges.")
        msg.setInformativeText(
            "Some network scanning features (ARP scanning) require elevated "
            "privileges to access raw network sockets.\n\n"
            "For full functionality, please restart the application as administrator."
        )

        if sys.platform == "win32":
            msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Retry)
            msg.setDefaultButton(QMessageBox.Ok)
            msg.button(QMessageBox.Retry).setText("Restart as Admin")

            result = msg.exec()

            if result == QMessageBox.Retry:
                if request_elevation():
                    # Elevation requested, close this instance
                    sys.exit(0)
        else:
            msg.setInformativeText(
                msg.informativeText() +
                "\n\nOn Linux/macOS, run with: sudo python -m freesdn_agent"
            )
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec()

    except ImportError:
        # Qt not available, just log
        logger.warning(
            "Running without admin privileges. "
            "Some scanning features may not work."
        )
