#!/usr/bin/env python
    
"""
fwdiff.py

Copyright: Arthur Clune 2011
License: GNU GPLv3

This code diffs firewall rules in fwdoc format 
See http://www.wyae.de/software/fwdoc/     

It should run as either a svn diff-cmd or as a simple diff, based
on the number of arguments given. 

"""


import sys
import json       
                    
def _diffArray(a1, a2):
    """diff two arrays of nat or access rule"""
    newitems = [x for x in a2 if x not in a1]
    deleteditems = [x for x in a1 if x not in a2]
    r = []
    for i in newitems:    
        r.append('+' + str(i))
    for i in deleteditems:
        r.append('-' + str(i))
    r.sort(cmp = lambda x,y: cmp(x[1:], y[1:]))
    print "\n".join(r)

def _diffDict(d1, d2):
    """diff two dicts"""
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    added   = d2_keys.difference(d1_keys)
    deleted = d1_keys.difference(d2_keys)
    if added:
        for k in added:  
            print '+', d2[k]
    if deleted:
        for k in deleted:
            print '-', d1[k] 
    for k in d1_keys.intersection(d2_keys):    
        if d1[k] != d2[k]:
            print '-', d1[k]
            print '+', d2[k]
            
def _flatten(o):
    """flatten an object consisting of nested arrays and/or dicts to a string"""    
    if type(o) == type(None):
        return ''
    if type(o) == type(u'') or type(o) == type(''):
        return o
    if type(o) == type([]):     
        return ','.join([_flatten(e) for e in o])
    if type(o) == type({}):
        return ','.join([_flatten(v) for v in o.values()])
    

class ThreadDecoder(json.JSONDecoder):
    def decode (self, json_string):
        # use json's generic decode capability to parse the serialized string
        # into a python dictionary.
        d = json.loads(json_string)     
        return Ruleset(d['accessrules'], d['firewall'], d['objects'], d['layer7filter'],
                       d['natrules'], d['services'])
       
class FWBase(object):
    """base object for fw ruleset objects"""
    def __init__(self, d):
        for f in self.fields:
            setattr(self, f, d.get(f))        
              
    def __str__(self):
        s = ''
        for f in self.fields:   
            v = getattr(self, f)
            if f == 'name' or f == 'number':
                s += '%s' % v
            elif v:  
                s += '/%s %s' % (f, _flatten(v))
        return s
        
    def __cmp__(self, other):
        """compare two rules, but ignore differences where only the number has changed"""
        for f in self.fields:
            if getattr(self, f) != getattr(other, f):
                return cmp(getattr(self, f), getattr(other, f))
            return 0        

class AccessRule(FWBase):
    """AccessRule"""
    fields = ["number", "name", "enabled", "from_interfaces", "from", "from_inverted", 
                "to_interfaces", "to", "to_inverted", "via_vpn", "header", "services", "services_inverted", 
                "action", "action_qualifier", "log", "time", "install_on", "comment"]

    def __init__(self, d):
        """d is an dict parsed from json"""
        super(AccessRule, self).__init__(d)  
        
    def __cmp__(self, other):
        """compare two rules, but ignore differences where only the number has changed"""
        for f in [ x for x in self.fields if x != "number"]:
            if getattr(self, f) != getattr(other, f):
                return cmp(getattr(self, f), getattr(other, f))
        return 0
        

class Firewall(FWBase):
    """Represent general details about the firewall"""  
    fields = ["brand", "type", "version", "date", "identifier", "filter", "comment"]
    
    def __init__(self, d):
        super(Firewall, self).__init__(d)             

class FWObject(FWBase):
    """
    Represent a FW object or group
    """ 
    fields = ["name", "type", "groupmembers", "ipaddr", "on-interface",  "Gateways", "comment"]

    def __init__(self, d):    
        super(FWObject, self).__init__(d)
        
class Layer7Filter(FWBase):
    """Layer7Filter""" 
    fields = ["name", "protocol", "comment"]

    def __init__(self, d):
        super(Layer7Filter, self).__init__(d)
        
class NatRule(FWBase):
    """NatRule"""   
    fields = ["enabled", "orig_from", "orig_to", "orig_service", "nat_type", "nat_from", 
              "nat_to", "nat_service", "install_on", "comment"]

    def __init__(self, d):
        super(NatRule, self).__init__(d)

    def __cmp__(self, other):
        """compare two rules, but ignore differences where only the number has changed"""   
        for f in [ x for x in self.fields if x != "number"]:    
            if getattr(self, f) != getattr(other, f):
                return cmp(getattr(self, f), getattr(other, f))
        return 0

class Service(FWBase):
    """FW1 Services"""
    fields = ["name", "type", "timeout", "groupmembers", "sourceport", "destinationport", 
              "layer7filter", "comment"]
    def __init__(self, d):
        super(Service, self).__init__(d)  
        
   
class Ruleset(object):
    """Hold a fw1 ruleset"""
    def __init__(self, accessrules, firewall, fwobjects, layer7filters, natrules, services): 
        self.firewall = Firewall(firewall)                        
        self.accessrules = [AccessRule(r) for r in accessrules]
        self.natrules = [NatRule(r) for r in natrules]        
        self.fwobjects = {}
        for (k,v) in fwobjects.iteritems():
            self.fwobjects[k] = FWObject(v)
        self.layer7filters = {}
        for (k, v) in layer7filters.iteritems():
            self.layer7filters[k] = Layer7Filter(v) 
        self.services = {}    
        for (k, v) in services.iteritems():
            self.services[k] = Service(v)
               
    def __str__(self):
        """__str__"""
        s = 'Firewall details:'             
        s += str(self.firewall)
        s += "\n"
        for r in self.accessrules:
            s += 'Rule: ' + str(r) + "\n" 
        for r in self.natrules:
            s += 'Natrule: ' + str(r) + "\n"
        for k in sorted(self.fwobjects.keys()):
            s += 'Object: ' + str(self.fwobjects[k]) + "\n"
        for k in sorted(self.layer7filters.keys()):
            s += 'Layer7Filter: ' + str(self.layer7filters[k]) + "\n"
        for k in sorted(self.services.keys()):
            s += 'Service: ' + str(self.services[k]) + "\n"
        return s    
    
    def diff(self, r2):
        """diff two rulesets, ignoring the 'firewall' section and changes to rules that are rule number changes only"""
        for d in ['fwobjects', 'services', 'layer7filters']:
            _diffDict(getattr(self, d), getattr(r2, d))
        for d in ['natrules', 'accessrules', 'natrules']:
            _diffArray(getattr(self, d), getattr(r2, d))         

if __name__ == '__main__':  
    if len(sys.argv)  < 3:
        print "Usage: %s <file1> <file2>" % sys.argv[0]
        sys.exit(1)
    if len(sys.argv) == 3:
        (left, right) = (sys.argv[1], sys.argv[2])
    if len(sys.argv) > 3:
        # maybe running as a subversion diff command?
        left = "";
        right = "";
        sys.argv.pop(0)
        while sys.argv:
            arg = sys.argv.pop(0)
            if arg == "-u":
                pass
            elif arg == "-L":
                sys.argv.pop(0)
            elif left == "":
                left = arg
            else:
                right = arg  
    if left == "" or right == "":
        print "Usage: %s <file1> <file2>" % sys.argv[0]
        sys.exit(1)
    try:
         ruleset1 = json.load(open(left), cls=ThreadDecoder)   
         ruleset2 = json.load(open(right), cls=ThreadDecoder)
    except Exception, e:       
         print "Error: couldn't load or parse rulebase: %s" % e
         sys.exit(1)  
    ruleset1.diff(ruleset2)
