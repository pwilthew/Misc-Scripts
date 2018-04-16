#!/usr/bin/python3.6

import config

import logging

import os

import pymysql

import subprocess

import sys

from contextlib import contextmanager



def get_db_and_cursor():
    """Return a database and cursor objects for inventory
    database."""
    user, db_name, passw = config.DB_CREDS
    db = pymysql.connect(user=user, db=db_name, passwd=passw)
    cursor = db.cursor()

    return db, cursor


def run_command(cmd_args):
    """Wrapper to run a command in subprocess."""
    proc = subprocess.Popen(cmd_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return proc.returncode, out, err

if __name__ == '__main__':
    main()
