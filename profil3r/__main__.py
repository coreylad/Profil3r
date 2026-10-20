import os
import sys

if not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from profil3r import core
from profil3r.colors import Colors

CONFIG = './config.json'


def print_logo():
    print(Colors.OKGREEN + Colors.BOLD + r'''___            ___  _  _  ____
| . \ _ _  ___ | | '<_>| |<__ / _ _
|  _/| '_>/ . \| |- | || | <_ \| '_>
|_|  |_|  \___/|_|  |_||_|<___/|_|

    ''' + Colors.ENDC)

    print("v1.0.4\n")
    print("You can buy me a coffee at : https://www.buymeacoffee.com/givocefo\n")


def main():
    print_logo()
    arguments = sys.argv[1:]

    if not arguments:
        print('''Profil3r is an OSINT tool that allows you to find potential profiles of a person on social networks, as well as their email addresses. This program also alerts you to the presence of a data leak for the found emails.

Usage : python3 profil3r <arguments>
for exemple : python3 profil3r john doe
              python3 profil3r john doe 67''')
        return

    profil3r = core.Core(CONFIG, arguments)
    profil3r.get_permutations()
    profil3r.run()


if __name__ == "__main__":
    main()
