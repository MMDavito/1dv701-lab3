#!/usr/bin/env python3

import test_tftp as test

@pytest.fixture
def Shitt(client):
    cell.make_full()
    return cell


t_Cli = test.client()
test.test_PMB3Blks(t_Cli)
test.test_GMBFail1stAck(t_Cli)
"""
just run from cmd line
py.test -s -v test_tftp.py
"""