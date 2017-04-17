#!/usr/bin/env python
# -*- coding: utf8 -*-

from __future__ import print_function
import sys
import os
import stat
import grp
import pwd

__author__ = "Thomas Langé"
__copyright__ = "(c) 2016 T. Lange"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "prototype"


class PermissionChecker():

    def __init__(self, user, path, printmode, doacl=False, verbose=False):
        self.user = user
        self.path = os.path.normpath(path)
        self.verbose = verbose
        self.doacl = doacl
        self.printmode = printmode
        self._ImportUserData()
        if self.doacl:
            try:
                import posix1e
                self.posix1e = posix1e
            except ImportError:
                self.error("checkperms needs python ACL support 'posix1e'")
                self.doacl = False

    def error(self, msg):
        print('\033[91mError : ' + str(msg) + '\033[0m', file=sys.stderr)
        sys.exit(1)

    def log(self, msg):
        if self.verbose:
            print('\033[94mLog : ' + str(msg) + '\033[0m')

    def info(self, msg, mode, path):
        print(str(msg) + " " + str(mode) + " " + str(path))

    def _CheckNode(self, path, mode):
        stats = os.stat(path)
        perms = stats.st_mode

        if (perms & stat.S_IRWXO) & mode == mode:
            self.log(self.user + " has " + str(mode) + " acces to " +
                     path + " thanks to other setup " + str(perms & stat.S_IRWXO))
            return True
        else:
            self.log(self.user + " has no " + str(mode) + " access to " +
                     path + " because of other mode : " + str(perms & stat.S_IRWXO))

        if stats.st_uid in self.groups and (perms & stat.S_IRWXG) & mode == mode:
            self.log(self.user + " has acces to " + path +
                     " thanks to group setup " + str(perms & stat.S_IRWXG))
            return True
        else:
            self.log(self.user + " has no " + str(mode) + " access to " + path +
                     " because of in no group or mode to strict: " + str(perms & stat.S_IRWXO))
        if stats.st_uid == self.userid:
            if (perms & stat.S_IRWXU) & mode == mode:
                self.log(self.user + " has acces to " + path +
                         " thanks to user setup " + str(perms & stat.S_IRWXU))
            else:
                self.log(
                    self.user + " owns and thus can give himself access to " + path)
            return True

        if self.userid == 0:
            self.log(self.user + " can do anything... sooooo...")
            return True

        if self.doacl:
            if self._aclCheck(path, mode):
                return True
        self.log("Access Denied in " + path)
        return False

    def _CheckFile(self, path, mode):
        granted = self._CheckNode(path, mode)
        if granted and (self.printmode == 'y' or self.printmode == 'a'):
            self.info("GRANTED", mode, path)
        if not granted and (self.printmode == 'n' or self.printmode == 'a'):
            self.info("DENIED", mode, path)
        return granted

    def _acltoperms(self, acl):
        r = 0
        if acl.permset.read:
            r += 4
        if acl.permset.write:
            r += 2
        if acl.permset.execute:
            r += 1
        return r

    def _aclCheck(self, path, mode):
        if self.posix1e.has_extended(path):
            acl = self.posix1e.ACL(file=path)
            for entry in acl:
                if entry.tag_type == self.posix1e.ACL_USER and entry.qualifier == self.userid:
                    if self._acltoperms(entry) & mode == mode:
                        return True
                if entry.tag_type == self.posix1e.ACL_GROUP and entry.qualifier in self.groups:
                    if self._acltoperms(entry) & mode == mode:
                        return True
                if entry.tag_type == self.posix1e.ACL_OTHER:
                    if self._acltoperms(entry) & mode == mode:
                        return True
        return False

    def _rList(self, path, mode, depth):
        if depth == 0:
            return None
        if not self._CheckNode(path, 4):
            print("Cannot list directory. Abort tree from here : " + path)
            return None
        for f in os.listdir(path):
            f = os.path.join(path, f)
            self._CheckFile(f, mode)
            if os.path.isdir(f):
                self._rList(f, mode, depth - 1)

    def _rCheck(self, path):
        (head, tail) = os.path.split(path)

        if head != '' and tail != '':
            return self._rCheck(head) and self._CheckNode(path, 1)

        return self._CheckNode(path, 1)

    def _ImportUserData(self):
        self.userid = pwd.getpwnam(self.user).pw_uid
        self.groups = [
            g.gr_gid for g in grp.getgrall() if self.user in g.gr_mem]
        self.groups.append(pwd.getpwnam(self.user).pw_gid)
        self.log("Userid : " + str(self.userid))
        self.log("Groups : " + str(self.groups))

    def SimpleCheck(self, mode):
        head, tail = os.path.split(self.path)
        if head != '' and tail != '':
            pathok = self._rCheck(head)
        else:
            pathok = True
        return pathok and self._CheckFile(self.path, mode)

    def ListCheck(self, mode, depth=-1):
        if not self.SimpleCheck(1):
            self.error("Target user can't access this folder")
        if os.path.isdir(self.path):
            self._rList(self.path, mode, depth)
        else:
            self.error("This option needs a directory, not a file")

