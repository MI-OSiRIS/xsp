#!/usr/bin/python

import sys
import argparse
import httplib
import json

hosts = {}
hosts['b001'] = {'mac': '00:02:C9:4B:1C:9C', 'ip': '10.1.20.10', 'port':'2', 'sw':'srs'}
hosts['b002'] = {'mac': '00:02:C9:35:03:50', 'ip': '10.1.20.20', 'port':'3', 'sw':'srs'}
hosts['b003'] = {'mac': '00:02:C9:17:C5:D1', 'ip': '10.1.20.30', 'port':'4', 'sw':'srs'}
hosts['b004'] = {'mac': '00:02:C9:18:07:01', 'ip': '10.1.20.40', 'port':'5', 'sw':'srs'}

switches = {}
switches['srs'] = {'dpid': '00:01:00:01:e8:8b:1e:32'}

paths = {}

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

def make_redirect_entries(src, dst, ip, l4_port):
    flows = []
    f = {'switch': switches[hosts[src]['sw']]['dpid'],
         'name': 'redirect-'+src+'-'+dst+'-'+l4_port,
         'src-ip': ip,
         'src-port': l4_port,
         'ingress-port': hosts[src]['port'],
         'ether-type': 2048,
         'protocol': 6,
         'active': 'true',
         'priority':10000,
         'actions': 'set-dst-mac='+hosts[dst]['mac']+',output='+hosts[dst]['port']
         }
    flows.append(f)
    return flows

def make_mesh_entries():
    flows = []
    for ha in hosts:
        for hb in hosts:
            if ha==hb:
                continue

            f = {'switch': switches[hosts[ha]['sw']]['dpid'],
                 'name': 'mesh-'+ha+'-'+hb,
                 'src-mac': hosts[ha]['mac'],
                 'dst-mac': hosts[hb]['mac'],
                 'ingress-port': hosts[ha]['port'],
                 'active': 'true',
                 'priority': 0,
                 'actions': 'output='+hosts[hb]['port']
                 }
            flows.append(f)

    return flows


usage_desc = """
srs_paths.py add|del [mesh] [redir src dst ip port] ...
"""

parser = argparse.ArgumentParser(description='process args', usage=usage_desc, epilog='foo bar help')
parser.add_argument('--ip', default='localhost')
parser.add_argument('--port', default=8080)
parser.add_argument('cmd')
parser.add_argument('subcmd')
parser.add_argument('rshost', nargs='?')
parser.add_argument('rdhost', nargs='?')
parser.add_argument('rip', nargs='?')
parser.add_argument('rport', nargs='?')
parser.add_argument('otherargs', nargs='*')
args = parser.parse_args()

#print "Called with:", args
cmd = args.cmd
subcmd = args.subcmd

# handle to Floodlight REST API
rest = RestApi(args.ip, args.port)

if subcmd == 'mesh':
    flows = make_mesh_entries();
elif subcmd == 'redir' and len(sys.argv) == 7:
    flows = make_redirect_entries(args.rshost, args.rdhost, args.rip, args.rport) 
else:
    print usage_desc
    exit(1)

# get list of flow entries to push


for f in flows:
    if (cmd=='add'):
        print "Adding flow:", f
        rest.set(f)
    if (cmd=='del'):
        print "Deleting flow:", f
        rest.remove(f)
            


