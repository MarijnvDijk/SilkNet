import os
import xml.etree.ElementTree as ET
import xmltodict
import json

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

    def parse_log(self, name) -> dict:
        f = open(f"{self._sysmon_config['logdirectory']}/{name}", 'r').read()
        obj = xmltodict.parse(f)
        process_creation = []
        for event in obj['Events']['Event']:
            if event['System']['EventID'] == "1":
                process_creation.append(event)
        for event in process_creation:
            processInfo = {}
            # for attribute in event['EventData']['Data']: