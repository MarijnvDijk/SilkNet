import xmltodict
from prettytable import PrettyTable

class SysmonParser:
    """
    Class for the Sysmon Log Parser.
    This class is used to handle all the Sysmon logs.

    ### Attributes

    private:
        _sysmon_config : dict
            An object that holds drakvuf config information.
        _map_pid : number
            The PID as displayed in Sysmon

    ### Methods
    
    private:

    public:
    """

    def __init__(self,
                 map_pid,
                 sysmon_config={},
                 ) -> None:
        self._sysmon_config = sysmon_config
        self._map_pid = map_pid
        self._config_valid = False

        self._validate_config()

    def _validate_config(self) -> None:
        """
        Loads the configuration information.
        """
        if "logdirectory" not in self._sysmon_config:
            print("[!] Sysmon config invalid")
            return
        self._config_valid = True

    def parse_log(self, name):
        f = open(f"{self._sysmon_config['logdirectory']}/{name}", 'r').read()
        obj = xmltodict.parse(f)
        process_creation_events = []
        processes = []
        for event in obj['Events']['Event']:
            if event['System']['EventID'] == "1":
                process_creation_events.append(event)
        for event in process_creation_events:
            process_creation_info = {}
            for attribute in event['EventData']['Data']:
                if attribute['@Name'] in ['ProcessId', 'User', 'CommandLine', 'ParentProcessId', 'Image']:
                    process_creation_info[attribute['@Name']] = attribute['#text']
            processes.append(process_creation_info)
        
        proctree_order = [[self._map_pid]]
        pids_seen = [self._map_pid]
        for proc in processes:
            if proc['ProcessId'] == self._map_pid:
                print(proc['Image'])
        while True:
            child = False
            for proc in processes:
                if proc['ParentProcessId'] in pids_seen and proc['ProcessId'] not in pids_seen:
                    pids_seen.append(proc['ProcessId'])
                    proctree_order.append([proc['ParentProcessId'], proc['ProcessId']])
                    child = True
            if child == False:
                break
        last_pid = self._map_pid
        indent = 1
        for group in range(1, len(proctree_order)):
            if proctree_order[group][0] != last_pid:
                last_pid = proctree_order[group][0]
                indent += 1
            for proc in processes:
                if proc['ProcessId'] == proctree_order[group][1]:
                    print(indent * '\t' + '\\_ ' + proc['Image'])
        print()

        table = PrettyTable()
        table.field_names = ["ParentProcessId", "ProcessId", "Image", "CommandLine", "User"]
        rows = []
        for proc in processes:
            if proc['ProcessId'] in pids_seen:
                rows.append([proc['ParentProcessId'], proc['ProcessId'], proc['Image'], proc['CommandLine'], proc['User']])
        rows.reverse()
        for row in rows:
            table.add_row(row)
        print(table)