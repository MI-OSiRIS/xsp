#!/usr/bin/python

import sys
import argparse
import httplib
import json


#       PC2                  PC1
#      (674)               (59066)
#   (2) SW1 (676) -- (59590) SW2 (59491) 
#     \                    /
#       --  (2) SW3 (674) --
#

hosts = {}
hosts['pc1'] = {'mac': 'ff:ff:ff:ff:ff:ff', 'ip': '10.200.200.1', 'swport': '59066'}
hosts['pc1_alt'] = {'mac': 'ff:ff:ff:ff:ff:ff', 'ip': '10.200.200.1', 'swport': '59066'}
hosts['pc2'] = {'mac': 'ee:ee:ee:ee:ee:ee', 'ip': '10.200.200.2', 'swport': '674'}
hosts['pc2_alt'] = {'mac': 'ee:ee:ee:ee:ee:ee', 'ip': '10.200.200.2', 'swport': '674'}

switches = {}
switches['sw1'] = {'dpid': '00:00:cc:4e:24:0c:08:00'}
switches['sw2'] = {'dpid': '00:00:ac:4b:c8:41:ef:c0'}
switches['sw3'] = {'dpid': '00:00:cc:4e:24:0c:0c:00'}

paths = {}
paths['pc1'] = {}
paths['pc1']['pc2'] = {'route': ['sw2', 'sw1']}
paths['pc1']['pc2_alt'] = {'route': ['sw2', 'sw3', 'sw1']}

paths['pc2'] = {}
paths['pc2']['pc1'] = {'route': ['sw1', 'sw2']}
paths['pc2']['pc1_alt'] = {'route': ['sw1', 'sw3', 'sw2']}

nhops = {}
nhops['sw1'] = {}
nhops['sw1']['sw2'] = 676
nhops['sw1']['pc1'] = 676
nhops['sw1']['pc2'] = 674
nhops['sw1']['sw3'] = 2

nhops['sw2'] = {}
nhops['sw2']['sw1'] = 59590
nhops['sw2']['pc1'] = 59066
nhops['sw2']['pc2'] = 59590
nhops['sw2']['sw3'] = 59491

nhops['sw3'] = {}
nhops['sw3']['sw2'] = 674
nhops['sw3']['pc1'] = 674
nhops['sw3']['pc2'] = 2
nhops['sw3']['sw1'] = 2

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
    route = paths[src][dst]['route']
    plen = len(route)

    for i in range(0, plen):
        # source
        if (i==0):
            flows.append(make_json_flow(route[i],
                                        hosts[src]['mac'],
                                        hosts[dst]['mac'],
                                        hosts[src]['swport'],
                                        nhops[route[i]][route[i+1]],
                                        vlan,
                                        fiter))
            flows.append(make_json_flow(route[i],
                                        hosts[dst]['mac'],
                                        hosts[src]['mac'],
                                        nhops[route[i]][route[i+1]],
                                        hosts[src]['swport'],
                                        vlan,
                                        fiter+1))
        # destination
        elif (i==(plen-1)):
            flows.append(make_json_flow(route[i],
                                        hosts[src]['mac'],
                                        hosts[dst]['mac'],
                                        hosts[dst]['swport'],
                                        nhops[route[i]][route[i-1]],
                                        vlan,
                                        fiter))
            flows.append(make_json_flow(route[i],
                                        hosts[dst]['mac'],
                                        hosts[src]['mac'],
                                        nhops[route[i]][route[i-1]],
                                        hosts[dst]['swport'],
                                        vlan,
                                        fiter+1))
        # we're some hop in the middle
        else:
            flows.append(make_json_flow(route[i],
                                        hosts[src]['mac'],
                                        hosts[dst]['mac'],
                                        nhops[route[i]][route[i-1]],
                                        nhops[route[i]][route[i+1]],
                                        vlan,
                                        fiter))
            flows.append(make_json_flow(route[i],
                                        hosts[dst]['mac'],
                                        hosts[src]['mac'],
                                        nhops[route[i]][route[i+1]],
                                        nhops[route[i]][route[i-1]],
                                        vlan,
                                        fiter+1))


        fiter+=2
            
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
#
#flows = [
#    {'switch': '00:00:cc:4e:24:0c:0c:00',
#     'name': 'flow-mod-97',
#     'active': 'true',
#     'ingress-port': 678,
#     'vlan-id': 4000,
#     'actions': 'output=676'
#     }
#    ]

for f in flows:
    if (cmd=='add'):
        print "Adding flow:", f
        rest.set(f)
    if (cmd=='del'):
        print "Deleting flow:", f
        rest.remove(f)
            


