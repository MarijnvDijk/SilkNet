import sys
import os
import json
from optparse import OptionParser

from nets import NetParser
from drakvuf import DrakvufParser
from sysmon import SysmonParser

def parse_args() -> OptionParser:
    parser = OptionParser(f"Usage: {sys.argv[0]} <Source Type(s)> [Options]")
    source_types = parser.add_option_group('Source Types')
    source_types.add_option('-e', '--silketw', dest='silketw', action="store_true", default=False, help='enable silketw parsing')
    source_types.add_option('-s', '--sysmon', dest='sysmon', action="store_true", default=False, help='enable sysmon parsing')
    parser.add_option('-c', '--config', dest='config', type='string', default='config.json', help='config filename (default: config.json)')
    parser.add_option('-n', '--net-dir', dest='netsdir', type='string', default='nets', help='directory where behavioural nets are stored')
    drakvuf = parser.add_option_group('Drakvuf')
    drakvuf.add_option('--syscall-file', dest='syscall', help='log file containing syscall log')
    drakvuf.add_option('--sysret-file', dest='sysret', help='log file containing sysret log')
    drakvuf.add_option('--pid', dest='pid', help="PID of process to inspect")
    drakvuf.add_option('-i', '--analysis-id', dest='drakvuf_id', type='string', help='drakvuf analysis ID')
    sysmon = parser.add_option_group('Sysmon')
    sysmon.add_option('-x', dest='sysmonxml', help='Sysmon XML File')
    sysmon.add_option('--map-pid', dest='rpid', default=99999, help='Drakvuf Sample PID as found in Sysmon Logs')
    return parser

def demand(prompt, options) -> str:
    answer = ""
    if len(options) != 0:
        while answer not in (options):
            answer = input(prompt)
    else:
        while answer == "":
            answer = input(prompt)
    return answer

def generate_config(filename) -> None:
    config = {"sources":[]}
    if input("\t\t\\_ Add drakvuf support? [Y/n] ") in ["Y", "y", ""]:
        drakvuf = {"logtype":"drakvuf"}
        drakvuf['logdirectory'] = demand("\t\t\t\\_ logdirectory ", [])
        drakvuf['location'] = demand("\t\t\t\\_ loglocation (\"online\" or \"local\") ", ["online", "local"])
        if drakvuf['location'] == "online":
            drakvuf['url'] = demand("\t\t\t\\_ url ", [])
            authentication_required = demand("\t\t\t\\_ authentication required (\"yes\" or \"no\") ", ["yes", "no"])
            if authentication_required == "yes":
                drakvuf['authentication_required'] = True
                username = demand("\t\t\t\\_ username ", [])
                password = demand("\t\t\t\\_ password ", [])
                authentication = {"username": username, "password": password}
                drakvuf["authentication"]=authentication
            else:
                drakvuf['authentication_required'] = False
        config['sources'].append(drakvuf)
    if input("\t\t\\_ Add sysmon support? [Y/n] ") in ["Y", "y", ""]:
        sysmon = {"logtype":"sysmon"}
        sysmon['logdirectory'] = demand("\t\t\t\\_ logdirectory ", [])
        config['sources'].append(sysmon)
    f = open(filename, "w")
    f.write(json.dumps(config))
    f.close()

def parse_config(filename) -> dict:
    if not os.path.isfile(filename):
        print(f"[!] Could not access \"{filename}\"")
        print(f"\t\\_ Would you like to generate a new config file? ", end="")
        answer = input("[Y/n] ")
        if answer == "Y" or answer == "y" or answer == "":
            generate_config(filename)
            return parse_config(filename)
        elif answer == "N" or answer == "n":
            print("[+] Generating placeholder config... ")
            bogus_config = {"sources":[]}
            f = open(filename, "w")
            f.write(json.dumps(bogus_config))
            f.close()
            exit(0)
    else:
        f = open(filename, "r").read()
        return json.loads(f)

def print_results(type, detections, netnum):
    if len(detections) == 0:
        print(f"[+] {type.capitalize()} Result : Clean")
    else:
        print(f"[-] {type.capitalize()} Result : Malicious [1/{netnum}]")
        for detection in detections:
            print(f"\t\\_ {detection['name']}")

def main():
    parser = parse_args()
    (options, args) = parser.parse_args()

    config = parse_config(options.config)
    if options.pid == None:
        print("[!] PID is mandatory")
        parser.print_help()
        return
    elif options.sysmon == True and options.sysmonxml == None:
        print("[!] Please specify Sysmon XML filename")
        parser.print_help()
        return
    elif options.sysmon == True and options.rpid == 99999:
        print("[!] PID Map required when using sysmon")
        parser.print_help()
        return

    netParser = NetParser(options.netsdir, options.pid)
    for source in config['sources']:
        if "logtype" in source and source["logtype"] == "drakvuf":
            if source['location'] == "online" and options.drakvuf_id == None:
                print("[!] Drakvuf Analysis ID is required when retrieving from Drakvuf GUI")
                parser.print_help()
                return
            elif source['location'] == "local":
                if options.syscall == None:
                    print("[!] Sycall Log File is required (will be accessed from logdirectory in config)")
                    parser.print_help()
                    return      
            drakvufParser = DrakvufParser(source, options.drakvuf_id, netParser.important_ntapis)
            if source['location'] == "local":
                syscalls = drakvufParser.parse_log(options.syscall, "syscall")
            else:
                syscalls = drakvufParser.parse_log("syscall.log", "syscall")
        elif "logtype" in source and source["logtype"] == "sysmon" and options.sysmon:
            sysmonParser = SysmonParser(options.rpid, source)
            sysmonParser.parse_log(options.sysmonxml)
    detections = netParser.check(syscalls, 'drakvuf')
    print_results('drakvuf', detections, netParser.net_num)

if __name__ == "__main__":
    main()
