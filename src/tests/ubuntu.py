#!/usr/bin/python3
# -*- coding: utf-8

import sys
import os

tests = [["ubuntu", 10.04, "lucid"],
            ["ubuntu", 12.04, "precise"],
            ["ubuntu", 13.04, "raring"],
            ["ubuntu", 13.10, "saucy"],
            ["ubuntu-cloud", 10.04, "lucid"],
            ["ubuntu-cloud", 12.04, "precise"],
            ["ubuntu-cloud", 13.04, "raring"],
            ["ubuntu-cloud", 13.10, "saucy"]]

# we are lxc/src/tests/lxc-test-ubuntu.py, check for module under
# lxc/src/python-lxc.
d=os.path.split(os.path.realpath(__file__))[0]
pd=os.path.split(d)[0]
if os.path.split(d)[1] == "tests":
    ldpath=os.path.join(pd, "lxc")
    os.environ['LD_LIBRARY_PATH'] = ldpath
    print("ldpath is %s" % ldpath)
    mp=os.path.join(pd, "python-lxc")
    sys.path.insert(0, mp)
import time
time.sleep(30)
import lxc

assert(os.getuid() == 0)

os.system("brctl addbr lxcT1")
os.system("ifconfig lxcT1 10.99.99.1 up")
lxctestconf = """
lxc.network.type = veth
lxc.network.link = lxcT1
lxc.network.flags = up
"""
TEST_CONFIG = "/etc/lxc-test.conf"
f=open(TEST_CONFIG, "w")
f.write(lxctestconf)
f.close()

for (t, relnum, r) in tests:
    c = lxc.Container("lxc-m-test1")
    assert(c != None)
    if c.defined:
        c.destroy()
        c = lxc.Container("lxc-m-test1")
        assert(c != None)

    # should probably do all the tests that src/python-lxc/examples/apitest.py
    # does here.
    c.load_config(TEST_CONFIG)
    c.save_config()
    c.create(t, "r=%s" % r)
    assert(container.defined)
    c.start()
    c.wait("RUNNING", 1)
    assert(container.running)
    c.stop()
    c.wait("STOPPED", 5)
    assert(not container.running)

    c.destroy()

print("Success")
