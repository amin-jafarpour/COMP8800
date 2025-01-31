import subprocess

def run_command(iface):
    """

    """
    cmds = [
    f"sudo ip link set dev {iface} down",
    f"sudo ip link set dev {iface} name wlp",
    f"sudo iw set dev wlp type monitor", # f"sudo iw dev wlp set type monitor",
    f"sudo ip link set dev wlp up"
    ]
    try:
        subprocess.run(cmds, shell=True, check=True, text=True)
        print(f"Executed: {cmds}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing {cmds}: {e}")





run_command('wlp')
