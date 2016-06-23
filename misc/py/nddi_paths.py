# =============================================================================
#  DAMSL (xsp)
#
#  Copyright (c) 2010-2016, Trustees of Indiana University,
#  All rights reserved.
#
#  This software may be modified and distributed under the terms of the BSD
#  license.  See the COPYING file for details.
#
#  This software was created at the Indiana University Center for Research in
#  Extreme Scale Technologies (CREST).
# =============================================================================
#!/usr/bin/python

import sys
import argparse
import httplib
import json

#
#      SEAT (18) -- (18) CHIC (17) -- (18) NEWY
#   (17)                                    (17)
#     |                                     /
#   (18)                                   /
#      LOSA (17)  ---------  (18) WASH (17)
#

hosts = {}
hosts['chic'] = {'mac': '78:2B:CB:48:FC:28', 'ip': '10.20.2.10'}
hosts['losa'] = {'mac': '78:2B:CB:49:82:B3', 'ip': '10.20.2.20'}
hosts['newy'] = {'mac': '78:2B:CB:48:FF:44', 'ip': '10.20.2.30'}
hosts['seat'] = {'mac': '78:2B:CB:5E:CB:CD', 'ip': '10.20.2.40'}
hosts['wash'] = {'mac': '78:2B:CB:48:FB:10', 'ip': '10.20.2.50'}

switches = {}
switches['chic'] = {'dpid': '00:64:34:40:b5:03:06:00', 'hport': '63'}
switches['losa'] = {'dpid': '00:64:34:40:b5:09:7c:00', 'hport': '63'}
switches['newy'] = {'dpid': '00:64:34:40:b5:03:21:00', 'hport': '63'}
switches['seat'] = {'dpid': '00:64:34:40:b5:09:a1:00', 'hport': '64'}
switches['wash'] = {'dpid': '00:64:34:40:b5:03:17:00', 'hport': '63'}

paths = {}
paths['chic'] = {}
paths['chic']['losa'] = {'route': ['chic', 'seat', 'losa'], 'linkp': '18'}
paths['chic']['newy'] = {'route': ['chic', 'newy'], 'linkp': '17'}
paths['chic']['seat'] = {'route': ['chic', 'seat'], 'linkp': '18'}
paths['chic']['wash'] = {'route': ['chic', 'newy', 'wash'], 'linkp': '17'}

paths['losa'] ={}
paths['losa']['chic'] = {'route': ['losa', 'seat', 'chic'], 'linkp': '18'}
paths['losa']['newy'] = {'route': ['losa', 'wash', 'newy'], 'linkp': '17'}
paths['losa']['seat'] = {'route': ['losa', 'seat'], 'linkp': '18'}
paths['losa']['wash'] = {'route': ['losa', 'wash'], 'linkp': '17'}

paths['newy'] ={}
paths['newy']['chic'] = {'route': ['newy', 'chic'], 'linkp': '18'}
paths['newy']['losa'] = {'route': ['newy', 'wash', 'losa'], 'linkp': '17'}
paths['newy']['seat'] = {'route': ['newy', 'chic', 'seat'], 'linkp': '18'}
paths['newy']['wash'] = {'route': ['newy', 'wash'], 'linkp': '17'}

paths['seat'] ={}
paths['seat']['chic'] = {'route': ['seat', 'chic'], 'linkp': '18'}
paths['seat']['losa'] = {'route': ['seat', 'losa'], 'linkp': '17'}
paths['seat']['newy'] = {'route': ['seat', 'chic', 'newy'], 'linkp': '18'}
paths['seat']['wash'] = {'route': ['seat', 'losa', 'wash'], 'linkp': '17'}

paths['wash'] ={}
paths['wash']['chic'] = {'route': ['wash', 'newy', 'chic'], 'linkp': '17'}
paths['wash']['losa'] = {'route': ['wash', 'losa'], 'linkp': '18'}
paths['wash']['newy'] = {'route': ['wash', 'newy'], 'linkp': '17'}
paths['wash']['seat'] = {'route': ['wash', 'losa', 'seat'], 'linkp': '18'}


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
            'src-mac': srcm,
            'dst-mac': dstm,
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

for f in flows:
    if (cmd=='add'):
        print "Adding flow:", f
        rest.set(f)
    if (cmd=='del'):
        print "Deleting flow:", f
        rest.remove(f)
            


