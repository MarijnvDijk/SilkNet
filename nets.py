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
            seen_order=[]
            for net in self._nets:
                for transition in net['transitions']:
                    highest_order=transition['order']
                    for call in behaviour:
                        valid = True
                        if transition['entity'] == 'PID':
                            if call['PID'] == int(self._pid) and call['Method'] == transition['NTAPI']:
                                for arg in transition['Args']:
                                    if call[arg['key']] != arg['value']:
                                        valid = False
                                    if 'nz' in arg and call[arg['key']] != "0x0":
                                        valid = True
                                if valid == True:
                                    if transition['order'] not in seen_order:
                                        if 'donttouch' not in call:
                                            call['order'] = transition['order']
                                            call['donttouch'] = 1
                                    else:
                                        call['order'] = -1
                                    relevant_calls.append(call)
                                    if call['order'] == transition['order']:
                                        seen_order.append(transition['order'])
                        if transition['entity'] == 'child' and call['Method'] == transition['NTAPI']:
                            if call['PPID'] == int(self._pid):
                                for arg in transition['Args']:
                                    if call[arg['key']] != arg['value']:
                                        valid = False
                                    if 'nz' in arg and call[arg['key']] != "0x0":
                                        valid = True
                                if valid == True:
                                    if transition['order'] not in seen_order:
                                        if 'donttouch' not in call:
                                            call['order'] = transition['order']
                                            call['donttouch'] = 1
                                    else:
                                        call['order'] = -1
                                    relevant_calls.append(call)
                                    if call['order'] == transition['order']:
                                        seen_order.append(transition['order'])
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