import os
import json
import requests
from requests.auth import HTTPBasicAuth

class DrakvufParser:
    """
    Class for the Drakvuf Log Parser.
    This class is used to handle all the Drakvuf logs.

    ### Attributes

    private:
        _drakvuf_config : dict
            An object that holds drakvuf config information.
        _analysis_id : string
            A drakvuf analysis ID

    ### Methods
    
    private:

    public:
    """

    def __init__(self,
                 drakvuf_config={},
                 analysis_id="",
                 important_apis=[]
                 ) -> None:
        self._drakvuf_config = drakvuf_config
        self._analysis_id = analysis_id
        self._important_apis=important_apis
        self._config_valid = False

        self._validate_config()

    def _validate_config(self) -> None:
        """
        Loads the configuration information.
        """
        if "location" not in self._drakvuf_config:
            print("[!] Drakvuf config invalid")
            return
        elif self._drakvuf_config['location'] == "url":
            if "url" not in self._drakvuf_config or "authentication_required" not in self._drakvuf_config:
                print("[!] Drakvuf config invalid")
                return
            elif self._drakvuf_config['authentication_required'] == True and "authentication" not in self._drakvuf_config:
                print("[!] Drakvuf config invalid")
                return
        elif self._drakvuf_config['location'] == "local":
            if "logdirectory" not in self._drakvuf_config:
                print("[!] Drakvuf config invalid")
                return
        self._config_valid = True

    def _retrieve_online(self, type) -> str:
        if not os.path.isdir('logs'):
            os.mkdir('logs')
        basic = HTTPBasicAuth(self._drakvuf_config['authentication']['username'], self._drakvuf_config['authentication']['password'])
        r = requests.get(f"{self._drakvuf_config['url']}/logs/{self._analysis_id}/{type}", auth=basic, allow_redirects=True)
        open(f"logs/{type}.log", 'wb').write(r.content)

    def parse_log(self, name, type) -> dict:
        valid_types = ["syscall", "sysret"]
        if type not in valid_types:
            print("[!] Invalid drakvuf log type !")
            return {}
        if self._drakvuf_config['location'] == 'online':
            self._retrieve_online(type)
        f = open(f"{self._drakvuf_config['logdirectory']}/{name}").readlines()
        related_events = []
        for line in f:
            if json.loads(line)['Method'] in self._important_apis:
                related_events.append(json.loads(line))
        return related_events
