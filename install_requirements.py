"""Run this script once to install all dependencies."""
import subprocess
import sys

def install():
    print("Installing IDS requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("\n✅ All requirements installed successfully.")
    print("\nNext steps:")
    print("  1. (Optional) Generate demo model:  python generate_demo_model.py")
    print("  2. Launch the IDS:                  python main.py")
    print("\n⚠️  Linux/macOS: run with sudo for packet capture.")
    print("⚠️  Windows: install Npcap from https://npcap.com/ first.")

if __name__ == "__main__":
    install()
