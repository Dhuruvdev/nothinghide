"""Startup module with dependency checking and loading animations.

Handles all CLI initialization tasks with proper progress indicators.
"""

import sys
import os
import time
import subprocess
from typing import Optional, List, Tuple

REQUIRED_PACKAGES = [
    ("typer", "typer"),
    ("rich", "rich"),
    ("httpx", "httpx"),
    ("email_validator", "email-validator"),
    ("halo", "halo"),
    ("yaspin", "yaspin"),
    ("colorama", "colorama"),
    ("dotenv", "python-dotenv"),
]

MIN_PYTHON_VERSION = (3, 10)


def get_python_version_string() -> str:
    """Get formatted Python version string."""
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def check_python_version() -> Tuple[bool, str]:
    """Check if Python version meets minimum requirements.
    
    Returns:
        Tuple of (success, message).
    """
    current = (sys.version_info.major, sys.version_info.minor)
    required_str = f"{MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}"
    
    if current < MIN_PYTHON_VERSION:
        return (
            False, 
            f"Python {required_str}+ required. Current: {get_python_version_string()}"
        )
    
    return (True, f"Python {get_python_version_string()}")


def check_package_installed(import_name: str) -> bool:
    """Check if a package can be imported.
    
    Args:
        import_name: The import name of the package.
        
    Returns:
        True if package is available.
    """
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def check_dependencies() -> Tuple[bool, List[str], List[str]]:
    """Check all required dependencies.
    
    Returns:
        Tuple of (all_ok, installed_packages, missing_packages).
    """
    installed = []
    missing = []
    
    for import_name, package_name in REQUIRED_PACKAGES:
        if check_package_installed(import_name):
            installed.append(package_name)
        else:
            missing.append(package_name)
    
    return (len(missing) == 0, installed, missing)


def install_missing_packages(packages: List[str]) -> Tuple[bool, str]:
    """Attempt to install missing packages.
    
    Args:
        packages: List of package names to install.
        
    Returns:
        Tuple of (success, message).
    """
    try:
        cmd = [sys.executable, "-m", "pip", "install", "--quiet"] + packages
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            return (True, f"Installed: {', '.join(packages)}")
        else:
            return (False, f"Failed to install packages: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        return (False, "Package installation timed out")
    except Exception as e:
        return (False, f"Installation error: {str(e)}")


def run_pip_check() -> Tuple[bool, str]:
    """Run pip check to verify dependency compatibility.
    
    Returns:
        Tuple of (success, message).
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "check"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return (True, "All dependencies compatible")
        else:
            return (False, f"Dependency conflicts:\n{result.stdout}")
            
    except subprocess.TimeoutExpired:
        return (False, "Dependency check timed out")
    except Exception as e:
        return (False, f"Check error: {str(e)}")


def load_core_modules() -> Tuple[bool, str]:
    """Load core application modules.
    
    Returns:
        Tuple of (success, message).
    """
    try:
        from . import config
        from . import utils
        from . import branding
        from . import email_check
        from . import password_check
        
        return (True, "Core modules loaded")
    except ImportError as e:
        return (False, f"Module import error: {str(e)}")
    except Exception as e:
        return (False, f"Module load error: {str(e)}")


def check_network_connectivity() -> Tuple[bool, str]:
    """Check basic network connectivity for API access.
    
    Returns:
        Tuple of (success, message).
    """
    try:
        import httpx
        
        response = httpx.get(
            "https://api.pwnedpasswords.com/range/00000",
            timeout=5.0
        )
        
        if response.status_code == 200:
            return (True, "Network connectivity OK")
        else:
            return (False, f"API returned status {response.status_code}")
            
    except httpx.TimeoutException:
        return (False, "Network timeout - check your connection")
    except httpx.ConnectError:
        return (False, "Cannot connect - check internet connection")
    except Exception as e:
        return (False, f"Network error: {str(e)}")


def initialize_colorama() -> None:
    """Initialize colorama for cross-platform color support."""
    try:
        import colorama
        colorama.init(autoreset=True)
    except ImportError:
        pass


def run_startup_sequence(
    skip_network_check: bool = False,
    auto_install: bool = True
) -> bool:
    """Run the complete startup sequence with loading animations.
    
    Args:
        skip_network_check: Skip network connectivity test.
        auto_install: Automatically install missing packages.
        
    Returns:
        True if startup was successful.
    """
    from halo import Halo
    
    initialize_colorama()
    
    steps_completed = 0
    total_steps = 5 if not skip_network_check else 4
    
    print()
    print("  \033[36m╔══════════════════════════════════════════════════════════╗\033[0m")
    print("  \033[36m║\033[0m           \033[1;37mNOTHINGHIDE CLI - Initializing\033[0m               \033[36m║\033[0m")
    print("  \033[36m╚══════════════════════════════════════════════════════════╝\033[0m")
    print()
    
    spinner = Halo(spinner='dots', color='cyan')
    
    spinner.start("Checking Python version...")
    time.sleep(0.3)
    success, message = check_python_version()
    if success:
        spinner.succeed(f"✓ {message}")
        steps_completed += 1
    else:
        spinner.fail(f"✗ {message}")
        print("\n  \033[31mPlease upgrade your Python version.\033[0m")
        return False
    
    spinner.start("Checking dependencies...")
    time.sleep(0.3)
    all_ok, installed, missing = check_dependencies()
    
    if all_ok:
        spinner.succeed(f"✓ All {len(installed)} packages installed")
        steps_completed += 1
    else:
        if auto_install:
            spinner.text = f"Installing {len(missing)} missing packages..."
            install_success, install_msg = install_missing_packages(missing)
            if install_success:
                spinner.succeed(f"✓ {install_msg}")
                steps_completed += 1
            else:
                spinner.fail(f"✗ {install_msg}")
                print(f"\n  \033[33mMissing packages: {', '.join(missing)}\033[0m")
                print(f"  \033[33mRun: pip install {' '.join(missing)}\033[0m")
                return False
        else:
            spinner.fail(f"✗ Missing packages: {', '.join(missing)}")
            print(f"\n  \033[33mRun: pip install {' '.join(missing)}\033[0m")
            return False
    
    spinner.start("Verifying dependency compatibility...")
    time.sleep(0.3)
    success, message = run_pip_check()
    if success:
        spinner.succeed(f"✓ {message}")
        steps_completed += 1
    else:
        spinner.warn(f"⚠ {message}")
        steps_completed += 1
    
    spinner.start("Loading core modules...")
    time.sleep(0.3)
    success, message = load_core_modules()
    if success:
        spinner.succeed(f"✓ {message}")
        steps_completed += 1
    else:
        spinner.fail(f"✗ {message}")
        return False
    
    if not skip_network_check:
        spinner.start("Checking network connectivity...")
        success, message = check_network_connectivity()
        if success:
            spinner.succeed(f"✓ {message}")
            steps_completed += 1
        else:
            spinner.warn(f"⚠ {message} (offline mode available)")
            steps_completed += 1
    
    print()
    print(f"  \033[32m✓ Initialization complete ({steps_completed}/{total_steps} checks passed)\033[0m")
    print()
    
    return True


def quick_start() -> bool:
    """Quick startup with minimal checks (for faster repeated runs).
    
    Returns:
        True if quick startup successful.
    """
    try:
        from . import config
        from . import utils
        from . import branding
        from . import main as main_module
        
        return True
    except ImportError as e:
        print(f"\033[31mImport error: {e}\033[0m")
        print("\033[33mRun with --full-init for detailed startup.\033[0m")
        return False


if __name__ == "__main__":
    success = run_startup_sequence()
    sys.exit(0 if success else 1)
