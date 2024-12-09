import os
import json

class NetParser:
    """
    Class for the Behavioural Net Parser.
    This class is used to handle all the Behaviour Net Activity.

    ### Attributes

    private:
        _net_dir : string
            A directory that holds all behaviour nets.

    ### Methods
    
    private:

    public:
    """

    def __init__(self,
                 net_dir,
                 pid
                 ) -> None:
        self._net_dir = net_dir
        self._nets = []
        self.net_num = len(self._nets)
        self.important_ntapis = []
        self._pid = pid

        self._parse_nets()

    def _parse_nets(self) -> None:
        if not os.path.isdir('nets'):
            print(f"[!] No directory \"{self._net_dir}\"")
            return
        for filename in os.listdir(self._net_dir):
            f = os.path.join(self._net_dir, filename)
            if os.path.isfile(f):
                self._nets.append(json.loads(open(f, "r").read()))
        self.net_num = len(self._nets)
        for net in self._nets:
            for transition in net['transitions']:
                if transition['NTAPI'] not in self.important_ntapis:
                    self.important_ntapis.append(transition['NTAPI'])
        
    def check(self, behaviour, type) -> list:
        valid_types = ['drakvuf', 'silketw', 'sysmon']
        if type not in valid_types:
            return None
        if type == 'drakvuf':
            detection = []
            relevant_calls = []
            for net in self._nets:
                for transition in net['transitions']:
                    highest_order=transition['order']
                    for call in behaviour:
                        if transition['entity'] == 'PID':
                            if call['PID'] == int(self._pid) and call['Method'] == transition['NTAPI']:
                                call['order'] = transition['order']
                                relevant_calls.append(call)
                        if transition['entity'] == 'child' and call['Method'] == transition['NTAPI']:
                            if call['PPID'] == int(self._pid):
                                call['order'] = transition['order']
                                relevant_calls.append(call)
                started_net = False
                lowest_order=0
                for call in relevant_calls:
                    if call['order'] == 0:
                        started_net = True
                    if call['order'] == lowest_order+1 and started_net == True:
                        lowest_order += 1
                if lowest_order == highest_order and started_net == True:
                    detection_object = {'name': net['name']}
                    detection.append(detection_object)
        return detection