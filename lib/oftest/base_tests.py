"""
Base classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import logging
import unittest
import os

import oftest
import florence
from florence import config
import oftest.controller as controller
import oftest.dataplane as dataplane
import ofp
from oftest.testutils import *

class BaseTest(unittest.TestCase):
    def __str__(self):
        return self.id().replace('.runTest', '')

    def setUp(self):
        florence.setup.open_logfile(str(self))
        logging.info("** START TEST CASE " + str(self))

    def tearDown(self):
        logging.info("** END TEST CASE " + str(self))

class SimpleProtocol(BaseTest):
    """
    Root class for setting up the controller
    """

    def setUp(self):
        BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.start()

        try:
            #@todo Add an option to wait for a pkt transaction to ensure version
            # compatibilty?
            self.controller.connect(timeout=20)

            # By default, respond to echo requests
            self.controller.keep_alive = True

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
            request = ofp.message.features_request()
            reply, pkt = self.controller.transact(request)
            self.assertTrue(reply is not None,
                            "Did not complete features_request for handshake")
            if reply.version == 1:
                self.supported_actions = reply.actions
                logging.info("Supported actions: " + hex(self.supported_actions))
        except:
            self.controller.kill()
            del self.controller
            raise

    def inheritSetup(self, parent):
        """
        Inherit the setup of a parent

        This allows running at test from within another test.  Do the
        following:

        sub_test = SomeTestClass()  # Create an instance of the test class
        sub_test.inheritSetup(self) # Inherit setup of parent
        sub_test.runTest()          # Run the test

        Normally, only the parent's setUp and tearDown are called and
        the state after the sub_test is run must be taken into account
        by subsequent operations.
        """
        logging.info("** Setup " + str(self) + " inheriting from "
                          + str(parent))
        self.controller = parent.controller
        self.supported_actions = parent.supported_actions

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        BaseTest.tearDown(self)

    def assertTrue(self, cond, msg):
        if not cond:
            logging.error("** FAILED ASSERTION: " + msg)
        unittest.TestCase.assertTrue(self, cond, msg)

class SimpleDataPlane(SimpleProtocol):
    """
    Root class that sets up the controller and dataplane
    """
    def setUp(self):
        SimpleProtocol.setUp(self)
        self.dataplane = oftest.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def inheritSetup(self, parent):
        """
        Inherit the setup of a parent

        See SimpleProtocol.inheritSetup
        """
        SimpleProtocol.inheritSetup(self, parent)
        self.dataplane = parent.dataplane

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        SimpleProtocol.tearDown(self)

class DataPlaneOnly(BaseTest):
    """
    Root class that sets up only the dataplane
    """

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = oftest.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        BaseTest.tearDown(self)

class Handshake(BaseTest):
    """
    Base handshake case to set up controller, but do not send hello.
    """

    def controllerSetup(self, host, port):
        con = controller.Controller(host=host,port=port)

        # clean_shutdown should be set to False to force quit app
        self.clean_shutdown = True
        # disable initial hello so hello is under control of test
        con.initial_hello = False

        con.start()
        self.controllers.append(con)

    def setUp(self):
        logging.info("** START TEST CASE " + str(self))

        self.controllers = []
        self.default_timeout = test_param_get('default_timeout',
                                              default=2)

    def tearDown(self):
        logging.info("** END TEST CASE " + str(self))
        for con in self.controllers:
            con.shutdown()
            if self.clean_shutdown:
                con.join()

    def runTest(self):
        # do nothing in the base case
        pass

    def assertTrue(self, cond, msg):
        if not cond:
            logging.error("** FAILED ASSERTION: " + msg)
        unittest.TestCase.assertTrue(self, cond, msg)

class SecureChannel(BaseTest):
    """
    Root class for setting up a secure connection with DUT.
    """

    def setUp(self):
        BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.start()

        try:
            self.controller.secure_connect(config["key"],
                                           config["cert"],
                                           config["ca_certs"],
                                           timeout=20)

            # Wrap connection with SSL options

            # By default, respond to echo requests
            self.controller.keep_alive = True

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
            request = ofp.message.features_request()
            reply, pkt = self.controller.transact(request)
            self.assertTrue(reply is not None,
                            "Did not complete features_request for handshake")
            if reply.version == 1:
                self.supported_actions = reply.actions
                logging.info("Supported actions: " + hex(self.supported_actions))
        except:
            self.controller.kill()
            del self.controller
            raise
