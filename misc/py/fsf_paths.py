#!/usr/bin/python

import sys
import argparse
import httplib
import json


#       PC2                  PC1
#      (674)               (59066)
#   (2) SW1 (676) -- (59590) SW2 (59491) 
#     \                    /
#       --  (1) SW3 (678) --
#

hosts = {}
hosts['sw1'] = {'mac': 'ff:ff:ff:ff:ff:ff', 'ip': ''}
hosts['sw2'] = {'mac': 'ee:ee:ee:ee:ee:ee', 'ip': ''}


switches = {}
switches['sw1'] = {'dpid': '00:00:cc:4e:24:0c:08:00', 'hport': '674'}
switches['sw2'] = {'dpid': '00:00:ac:4b:c8:41:ef:c0', 'hport': '59066'}
switches['sw3'] = {'dpid': '00:00:cc:4e:24:0c:0c:00', 'hport': None}

paths = {}
paths['sw1'] = {}
paths['sw1']['sw2'] = {'route': ['sw1', 'sw2'], 'linkp': '676'}
paths['sw1']['sw3'] = {'route': ['sw1', 'sw3'], 'linkp': '2'}

paths['sw2'] = {}
paths['sw2']['sw1'] = {'route': ['sw2', 'sw1'], 'linkp': '59590'}
paths['sw2']['sw3'] = {'route': ['sw2', 'sw3'], 'linkp': '59491'}

paths['sw3'] = {}
paths['sw3']['sw1'] = {'route': ['sw3', 'sw1'], 'linkp': '1'}
paths['sw3']['sw2'] = {'route': ['sw3', 'sw2'], 'linkp': '678'}


class RestApi(object):

    def __init__(self, server, port):
        self.server = server
        self.port = port


    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200

    def rest_call(self, data, action):
        path = '/wm/staticflowentrypusher/json'
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, self.port)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        print ret
        conn.close()
        return ret

def make_json_flow(hop, srcm, dstm, inp, outp, vlan, i):
    return {'switch': switches[hop]['dpid'],
            'name': 'flow-mod-'+str(i),
#            'src-mac': srcm,
#            'dst-mac': dstm,
            'ingress-port': inp,
            'vlan-id': vlan,
            'active': 'true',
            'actions': 'output='+str(outp)
            }

def make_entries(src, dst, vlan, other):
    flows = []
    fiter = 0
    hopc = 0
    plen = len(paths[src][dst]['route'])

    for hop in paths[src][dst]['route']:
        # source
        if (hop==src):
            flows.append(make_json_flow(hop,
                                        hosts[src]['mac'],
                                        hosts[dst]['mac'],
                                        switches[hop]['hport'],
                                        paths[src][dst]['linkp'],
                                        vlan,
                                        fiter))
            flows.append(make_json_flow(hop,
                                        hosts[dst]['mac'],
                                        hosts[src]['mac'],
                                        paths[src][dst]['linkp'],
                                        switches[hop]['hport'],
                                        vlan,
                                        fiter+1))
        # destination
        elif (hop==dst):
            flows.append(make_json_flow(hop,
                                        hosts[src]['mac'],
                                        hosts[dst]['mac'],
                                        paths[dst][src]['linkp'],
                                        switches[hop]['hport'],
                                        vlan,
                                        fiter))
            flows.append(make_json_flow(hop,
                                        hosts[dst]['mac'],
                                        hosts[src]['mac'],
                                        switches[hop]['hport'],
                                        paths[dst][src]['linkp'],
                                        vlan,
                                        fiter+1))
        # we're some hop in the middle
        else:
            flows.append(make_json_flow(hop,
                                        hosts[src]['mac'],
                                        hosts[dst]['mac'],
                                        paths[hop][src]['linkp'],
                                        paths[hop][dst]['linkp'],
                                        vlan,
                                        fiter))
            flows.append(make_json_flow(hop,
                                        hosts[dst]['mac'],
                                        hosts[src]['mac'],
                                        paths[hop][dst]['linkp'],
                                        paths[hop][src]['linkp'],
                                        vlan,
                                        fiter+1))


        fiter+=2
        hopc+=1
            
    return flows


usage_desc = """
nddi_paths.py {add|del} src dst [vlan] ...
"""

parser = argparse.ArgumentParser(description='process args', usage=usage_desc, epilog='foo bar help')
parser.add_argument('--ip', default='localhost')
parser.add_argument('--port', default=8080)
parser.add_argument('cmd')
parser.add_argument('src')
parser.add_argument('dst')
parser.add_argument('vlan', nargs='?')
parser.add_argument('otherargs', nargs='*')
args = parser.parse_args()

#print "Called with:", args
cmd = args.cmd

# handle to Floodlight REST API
rest = RestApi(args.ip, args.port)

# get list of flow entries to push
flows = make_entries(args.src, args.dst, args.vlan, args.otherargs)

#flows = [
#    {'switch': '00:00:ac:4b:c8:41:ef:c0',
#     'name': 'flow-mod-01',
#     'active': 'true',
#     'ingress-port': 59066,
#     'vlan-id': 4000,
#     'actions': 'output=59590'
#     }
#    ]

for f in flows:
    if (cmd=='add'):
        print "Adding flow:", f
        rest.set(f)
    if (cmd=='del'):
        print "Deleting flow:", f
        rest.remove(f)
            


