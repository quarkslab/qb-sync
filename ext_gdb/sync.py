#
# Copyright (C) 2012-2013, Quarkslab.
#
# This file is part of qb-sync.
#
# qb-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import socket
import base64
import tempfile
from os import path
import gdb
import ConfigParser

VERBOSE = 0

HOST = "localhost"
PORT = 9100


#------------------------------------------------------------------------------
# functions gdb_execute, get_pid and get_maps courtesy of StalkR
#------------------------------------------------------------------------------

if path.exists("/usr/compat/linux/proc/self/cmdline"):
    # FreeBSD
    SLASH_PROC = "/usr/compat/linux/proc"
else:
    # Linux
    SLASH_PROC = "/proc"


# Wrapper when gdb.execute(cmd, to_string=True) does not work
def gdb_execute(cmd):
    f = tempfile.NamedTemporaryFile()
    gdb.execute("set logging file %s" % f.name)
    gdb.execute("set logging redirect on")
    gdb.execute("set logging overwrite")
    gdb.execute("set logging on")
    try:
        gdb.execute(cmd)
    except Exception, e:
        gdb.execute("set logging off")
        f.close()
        raise e
    gdb.execute("set logging off")
    s = open(f.name, "r").read()
    f.close()
    return s


def get_pid():
    info_program = gdb.execute("info program", to_string=True)
    if 'not being run' in info_program:
        return False
    elif 'child process' in info_program:
        return re.search("child process ([0-9]+)", info_program).group(1)
    elif 'child Thread' in info_program:
        if gdb.VERSION > 7.2:
            info_inferiors = gdb.execute("info inferiors", to_string=True)
        else:  # bug in gdb <= 7.2, result printed to ui_out
            info_inferiors = gdb_execute("info inferiors")
        return re.search("\* 1 *process ([0-9]+)", info_inferiors).group(1)
    else:
        raise Exception("get_pid(): don't know how to understand 'info program'")


def get_maps(verbose=True):
    "Return list of maps (start, end, permissions, file name) via /proc"
    pid = get_pid()
    if pid is False:
        if verbose:
            print "Program not started"
        return []
    maps = []
    # Linux
    # address                   perms offset  dev   inode   file
    # 7ffff6e2d000-7ffff6e31000 r-xp 00000000 fd:03 7064550 /lib/libattr.so.1.1.0
    if path.exists(SLASH_PROC + "/%s/maps" % pid):  # Linux
        for line in open(SLASH_PROC + "/%s/maps" % pid, "r"):
            e = filter(lambda x: x != '', line.strip().split(' '))  # avoid multiple spaces
            if not e:
                continue
            elif len(e) == 5:
                e += ['']  # no file name
            startend, perms, offset, dev, inode, file = e
            start, end = startend.split('-')
            maps += [(int(start, 16), int(end, 16), perms, file)]
    # FreeBSD
    # start end resident privateresident obj perms ref_count shadow_count flags cow copy type file
    # 0x8048000 0x804a000 2 0 0xc2ed3cc0 r-x 1 0 0x1000 COW NC vnode /bin/cat NCH -1
    elif path.exists(SLASH_PROC + "/%s/map" % pid):
        for line in open(SLASH_PROC + "/%s/map" % pid, "r"):
            e = filter(lambda x: x != '', line.strip().split(' '))  # avoid multiple spaces
            if not e:
                continue
            start, end, perms, file = e[0], e[1], e[5], e[12]
            maps += [(int(start, 16), int(end, 16), perms, file)]
    # FreeBSD
    # start end resident privateresident obj perms ref_count shadow_count flags cow copy type file
    # 0x8048000 0x804a000 2 0 0xc2ed3cc0 r-x 1 0 0x1000 COW NC vnode /bin/cat NCH -1
    elif path.exists(SLASH_PROC + "/%s/map" % pid):
        for line in open(SLASH_PROC + "/%s/map" % pid, "r"):
            e = filter(lambda x: x != '', line.strip().split(' '))  # avoid multiple spaces
            if not e:
                continue
            start, end, perms, file = e[0], e[1], e[5], e[12]
            maps += [(int(start, 16), int(end, 16), perms, file)]
    else:
        raise Exception("get_maps(): cannot find a /proc/%s/map{,s} file" % pid)
    return maps

#------------------------------------------------------------------------------


def get_pc():
    try:
        pc_str = str(gdb.parse_and_eval("$pc"))
    except Exception as e:
        # debugger may not be running: 'No registers':
        return None

    return int((pc_str.split(" ")[0]), 16)


class Tunnel():

    def __init__(self, host):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, PORT))
        except socket.error, msg:
            self.sock.close()
            self.sock = None
            self.sync = False
            print "[sync] Tunnel initialization  error: %s" % msg
            return None

        self.sync = True

    def is_up(self):
        return (self.sock != None and self.sync == True)

    def send(self, msg):
        if not self.sock:
            print "[sync] tunnel_send: tunnel is unavailable (did you forget to sync ?)"
            return

        try:
            self.sock.send(msg)
        except socket.error, msg:
            self.sync = False
            self.close()

            print "[sync] tunnel_send error: %s" % msg

    def close(self):
        if self.is_up():
            self.send("[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n")

        if self.sock:
            try:
                self.sock.close()
            except socket.error, msg:
                print "[sync] tunnel_close error: %s" % msg

        self.sync = False
        self.sock = None


class Sync(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, "sync", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.pid = None
        self.maps = None
        self.base = None
        self.offset = None
        self.tunnel = None
        gdb.events.exited.connect(self.exit_handler)
        gdb.events.stop.connect(self.stop_handler)
        print "[sync] commands added"

    def identity(self):
        f = tempfile.NamedTemporaryFile()
        gdb.execute("shell uname -svm > %s" % f.name)
        id = open(f.name, 'r').read()
        f.close()
        return id.strip()

    def mod_info(self, addr):
        if not self.maps:
            self.maps = get_maps()
            if not self.maps:
                print "[sync] failed to get maps"
                return None

        for mod in self.maps:
            if (addr > mod[0]) and (addr < mod[1]):
                return [mod[0], mod[3]]
        return None

    def locate(self):
        offset = get_pc()
        if not offset:
            print "<not running>"
            return

        self.offset = offset
        mod = self.mod_info(self.offset)
        if mod:
            if VERBOSE >= 2:
                print "[sync] mod found"
                print mod

            base = mod[0]
            sym = mod[1]

            if self.base != base:
                self.tunnel.send("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n" % sym)
                self.base = base

            self.tunnel.send("[sync]{\"type\":\"loc\",\"base\":%d,\"offset\":%d}\n" % (self.base, self.offset))
        else:
            print "[sync] unknown module at 0x%x" % self.offset
            self.base = None
            self.offset = None

    def stop_handler(self, event):
        if VERBOSE >= 2:
            print "[sync] stop_handler"

        if not self.tunnel:
            return

        if not self.pid:
            self.pid = get_pid()
            if not self.pid:
                print "[sync] failed to get pid"
                return
            else:
                print "[sync] pid: %s" % self.pid

        self.locate()

    def exit_handler(self, event):
        self.reset_state()
        print "[sync] exit, sync finished"

    def reset_state(self):
        if self.tunnel:
            self.tunnel.close()
            self.tunnel = None

        self.pid = None
        self.maps = None
        self.base = None
        self.offset = None

    def invoke(self, arg, from_tty):
        if not self.tunnel:
            if arg == "":
                arg = HOST

            self.tunnel = Tunnel(arg)
            if not self.tunnel.is_up():
                print "[sync] sync failed"
                return

            id = self.identity()
            self.tunnel.send("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\"}\n" % id)
            print "[sync] sync is now enabled with host %s" % arg
        else:
            print '(update)'

        self.locate()


class Syncoff(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "syncoff", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        self.sync.reset_state()
        print "[sync] sync is now disabled"


class Cmt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "cmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print "[sync] process is not running, command is dropped"
            return

        if arg == "":
            print "[sync] usage: cmt [-a 0xBADF00D] <cmt to add>"
            return

        self.sync.tunnel.send("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" % (arg, self.sync.base, self.sync.offset))


class Fcmt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "fcmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print "[sync] process is not running, command is dropped"
            return

        self.sync.tunnel.send("[sync]{\"type\":\"fcmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" % (arg, self.sync.base, self.sync.offset))


class Rcmt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "rcmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print "[sync] process is not running, command is dropped"
            return

        self.sync.tunnel.send("[sync]{\"type\":\"rcmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" % (arg, self.sync.base, self.sync.offset))


class Bc(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "bc", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print "[sync] process is not running, command is dropped"
            return

        if arg == "":
            arg = "oneshot"

        if not (arg in ["on", "off", "oneshot"]):
            print "[sync] usage: bc <|on|off>"
            return

        self.sync.tunnel.send("[sync]{\"type\":\"bc\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" % (arg, self.sync.base, self.sync.offset))


class Cmd(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "cmd", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print "[sync] process is not running, command is dropped"
            return

        if arg == "":
            print "[sync] usage: cmd <command to execute and dump>"

        cmd_output = gdb_execute(arg)
        b64_output = base64.b64encode(cmd_output)
        self.sync.tunnel.send("[sync] {\"type\":\"cmd\",\"msg\":\"%s\", \"base\":%d,\"offset\":%d}\n" % (b64_output, self.sync.base, self.sync.offset))
        print "[sync] command output:\n%s" % cmd_output.strip()


class Help(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, "synchelp", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        print (
"""[sync] extension commands help:
 > sync <host>                   = synchronize with <host> or the default value
 > syncoff                       = stop synchronization
 > cmt [-a address] <string>     = add comment at current eip (or [addr]) in IDA
 > rcmt [-a address] <string>    = reset comments at current eip (or [addr]) in IDA
 > fcmt [-a address] <string>    = add a function comment for 'f = get_func(eip)' (or [addr]) in IDA
 > cmd <string>                  = execute command <string> and add its output as comment at current eip in IDA
 > bc <on|off|>                  = enable/disable path coloring in IDA
                                    color a single instruction at current eip if called without argument\n""")

if __name__ == "__main__":

    locations = [os.path.join(os.path.realpath(os.path.dirname(__file__)), ".sync"),
                 os.path.join(os.environ['HOME'], ".sync")]

    for confpath in locations:
        if os.path.exists(confpath):
            config = ConfigParser.SafeConfigParser({'host': HOST, 'port': PORT})
            config.read(confpath)
            HOST = config.get("INTERFACE", 'host')
            PORT = config.getint("INTERFACE", 'port')
            print "[sync] configuration file loaded %s:%s" % (HOST, PORT)
            break

    sync = Sync()
    Syncoff(sync)
    Cmt(sync)
    Rcmt(sync)
    Fcmt(sync)
    Bc(sync)
    Cmd(sync)
    Help()

