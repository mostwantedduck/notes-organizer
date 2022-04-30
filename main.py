from libnmap.parser import NmapParser
from mdutils.mdutils import MdUtils
import os
import json
import sys

app_whatweb = "whatweb"
app_gobuster = "gobuster"
app_wfuzz = "wfuzz"

commands = {}
active_vhost = ""


def load_json(file_name):
    f = open(file_name)
    data = json.load(f)
    f.close()
    return data


def md_skeleton_add_pre_compromise_structure(md_file, host):
    md_file.new_header(level=2, title="Services")

    for srv in host.services:
        if srv.service == "ftp":
            md_file.new_header(level=3, title="FTP:{0}".format(srv.port))
            print("[+] Preparing enumeration for FTP:{0}...".format(srv.port))
            continue

        if srv.service == "kerberos-sec":
            md_file.new_header(level=3, title="Kerberos:{0}".format(srv.port))
            print("[+] Preparing enumeration for Kerberos:{0}...".format(srv.port))
            items_kbr = [
                "Do you have a username list?",
                [
                    "`%s`" % commands["kerberos"]["enum"]["kerbrute"].format(active_vhost),
                    "`%s`" % commands["kerberos"]["enum"]["nmap"].format(active_vhost, host.address)
                ]
            ]
            md_file.new_checkbox_list(items=items_kbr)
            continue

        if srv.service == "ldap" and srv.port == 389:
            md_file.new_header(level=3, title="LDAP:{0}".format(srv.port))
            print("[+] Preparing enumeration for LDAP:{0}...".format(srv.port))
            items_ldap = [
                "`%s`" % commands["ldap"]["enum"]["nmap"].format(host.address)
            ]
            md_file.new_checkbox_list(items=items_ldap)
            continue

        if srv.service == "netbios-ssn" and srv.port == 139:
            md_file.new_header(level=3, title="SMB:{0}".format(srv.port))
            print("[+] Preparing enumeration for SMB:{0}...".format(srv.port))

            items_smb = []

            for key, value in commands["smb"]["enum"].items():
                items_smb.extend(["`%s`" % value.format(host.address)])

            md_file.new_checkbox_list(items=items_smb)
            continue

        if srv.service == "http":
            md_file.new_header(level=3, title="WEB:{0}".format(srv.port))
            print("[+] Preparing enumeration for Web:{0}...".format(srv.port))

            items_http = []

            for key, value in commands["web"]["enum"].items():
                if key == app_whatweb or key == app_wfuzz:
                    items_http.append("`%s`" % value.format(host.address, srv.port))

                if key == app_gobuster:
                    extension = filter_extension(srv.banner)
                    if extension == "":
                        value = value.replace("#EXT", "")
                    else:
                        value = value.replace("#EXT", "-x {0}".format(extension))
                    items_http.append("`%s`" % value.format(host.address, srv.port))

            items_http.extend([
                "Checked for subdomains?",
                [
                    "`%s`" % commands["web"]["vhost"][app_gobuster].format(active_vhost),
                    "`%s`" % commands["web"]["vhost"][app_wfuzz].format(active_vhost)
                ],
                "Checked for fuzzing parameters?",
                [
                    "`%s`" % commands["web"]["fuzz"][app_wfuzz].format(active_vhost)
                ]
            ])

            md_file.new_checkbox_list(items=items_http)
            continue

    return md_file


def md_skeleton_add_review_list(md_file):
    md_file.new_header(level=2, title="Review")

    commands = load_json("{0}/todos.json".format(os.path.dirname(__file__)))
    items_dont_forget = commands["todos"]

    md_file.new_checkbox_list(items=items_dont_forget)
    return md_file


def md_skeleton_add_pre_compromise_sections(md_file, host):
    md_file.new_header(level=1, title="Commands Output")

    for srv in host.services:
        if srv.service == "http":
            md_file.new_header(level=2, title="{0: <6} Web".format(srv.port))

            for key, value in commands["web"]["enum"].items():
                md_file.new_header(level=3, title="{0}".format(key))
                md_file.insert_code("", language='bash')
                md_file.new_line()

    return md_file


def md_skeleton_add_compromise_sections(md_file):
    md_file.new_header(level=1, title="Exploitation")
    md_file.new_paragraph("add content...")
    md_file.new_line()
    return md_file


def md_skeleton_add_privesc_sections(md_file):
    md_file.new_header(level=1, title="Post Exploitation")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="System Information")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="File System")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="Running Processes")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="Installed Application")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="Users & Groups")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="Scheduled Jobs")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    return md_file


def md_skeleton_add_flags_sections(md_file):
    md_file.new_header(level=1, title="Loot")

    md_file.new_header(level=2, title="Proofs")
    contents = ["user.txt", "proof.txt"]
    contents.extend(["add flag here", "add flag here"])
    md_file.new_table(columns=2, rows=2, text=contents, text_align='center')
    md_file.new_line()

    md_file.new_header(level=2, title="Hashes")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="Passwords")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    md_file.new_header(level=2, title="Other")
    md_file.new_paragraph("add content...")
    md_file.new_line()

    return md_file


def md_skeleton_add_screenshot_sections(md_file):
    md_file.new_header(level=1, title="General Notes")
    md_file.new_paragraph("add content...")
    md_file.new_line()
    return md_file


def md_skeleton(project_name, hosts):
    file_name = project_name + ".md"

    host = hosts[0]

    md_file = MdUtils(file_name=file_name, title="Notes For {0}".format(project_name))

    md_file = md_skeleton_add_services(md_file, host)

    md_file = md_skeleton_add_pre_compromise_structure(md_file, host)

    md_file = md_skeleton_add_review_list(md_file)

    md_file = md_skeleton_add_pre_compromise_sections(md_file, host)

    md_file = md_skeleton_add_compromise_sections(md_file)

    md_file = md_skeleton_add_privesc_sections(md_file)

    md_file = md_skeleton_add_flags_sections(md_file)

    md_file = md_skeleton_add_screenshot_sections(md_file)

    md_file.new_table_of_contents(table_title='Contents', depth=2)

    md_file.create_md_file()

    return


def md_skeleton_add_services(md_file, host):
    md_file.new_header(level=1, title="Enumeration")
    md_file.new_paragraph("Host: %s (Up: %s)" % (host.address, host.is_up()))

    md_file.new_header(level=2, title="Nmap Results")

    rows = 1
    content = ["Port", "State", "Service", "Banner", "Verified?", "Comments"]

    for s in host.services:
        content.extend([s.port, s.state, s.service, s.banner, "Y/N", ""])
        rows = rows + 1

    md_file.new_table(columns=6, rows=rows, text=content, text_align='left')

    md_file.new_header(level=3, title="Nmap Raw")
    md_file.insert_code("copy raw content here...", language='bash')

    return md_file


def filter_extension(banner):
    if banner == "":
        return ""

    result = ""

    if banner.find('IIS') > 0:
        return "aspx,asp,html"

    if banner.find("nginx") > 0 or banner.find("apache") > 0:
        return "php,jsp"

    return result


def load_active_vhost():
    # TODO: Make it dynamic
    file_path = "/home/mwd/.active_vhost"
    # file_path = "/Users/daniel/.active_vhost"
    if not os.path.isfile(file_path):
        print("[-] VHOST not found. Add it to ~/.active_vhost file.")
        return ""

    active_vhost = open(file_path, "r")
    data = active_vhost.read().strip()
    active_vhost.close()

    return data


def load_hosts(nmap_parsed_raw):
    return nmap_parsed_raw.hosts


def run():
    global commands
    commands = load_json("{0}/commands.json".format(os.path.dirname(__file__)))

    nmap_path = "{0}/nmap/".format(os.getcwd())
    project_name = sys.argv[1]

    nmap_file_path = "%sscan.nmap.xml" % nmap_path

    print(nmap_file_path)

    global active_vhost
    active_vhost = load_active_vhost()

    if active_vhost == "":
        print("[-] ~/.active_vhost was not configured.")
        print("    -----------------------------------")
        zshrc_function = '''
        function cip(){
            echo "" > ~/.active
            echo "" > ~/.active_vhost
        }

        function lip() {
            export ip=$(cat ~/.active)
            export vhost=$(cat ~/.active_vhost)

            echo "\n[+] IP Loaded...: $ip"
            echo "\n[+] VHOST Loaded: $vhost"
        }

        function aip {
            echo "$1" > ~/.active
            echo "$2" > ~/.active_vhost
            lip
        }
        '''
        print(zshrc_function)
        print("    -----------------------------------")

    if os.path.isfile(nmap_file_path):
        nmap_parsed_raw = NmapParser.parse_fromfile(nmap_file_path)
        hosts = load_hosts(nmap_parsed_raw)
        md_skeleton(project_name, hosts)
        return

    print("[-] nmap files were not found. please run the commands below:")
    print("aip TARGET_IP VHOST")
    print("sudo nmap -sS -p- $ip -vvv -n -Pn -oN nmap/ports.nmap")
    print("nmap -sC -sV -p$(cat nmap/ports.nmap | grep -oP '\\d{2,5}/' | awk '{print $1}' "
          "FS=\"/\" | xargs | tr ' ' ',') -n -Pn $ip -oA nmap/scan.nmap")
    print("[+] run again")


if __name__ == '__main__':
    run()
