import subprocess
import sys

def change_mode(iface, mode):
    """
    """
    modes = ['managed', 'monitor']
    if mode.lower() not in modes:
        raise Exception(f'Unsupported interface mode {mode.lower()}')
    cmds = [
        ["sudo", "ip", "link", "set", iface, "down"],
        ["sudo", "iw", "dev", iface, "set", "type", mode.lower()],
        ["sudo", "ip",  "link", "set", iface, "up"]
    ]

    try:
        for cmd in cmds:
           subprocess.run(cmd, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")




def main():
    if len(sys.argv) < 3:
        print('Error: Missing arguments.')
        print(f'Usage: {sys.argv[0]} <Interface> <Mode>')
        print('Mode: managed, monitor')
        sys.exit(1)

    change_mode(sys.argv[1], sys.argv[2])






if __name__ == '__main__':
    main()
