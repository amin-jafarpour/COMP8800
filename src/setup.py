import subprocess

def change_mode(iface, mode):
    """
    """
    cmds = [
    f"sudo ip link set {iface} down",
    f"sudo iw dev {iface} set type {mode}", 
    f"sudo ip link set {iface} up"
    ]
    try:
        subprocess.run(cmds, shell=True, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")




