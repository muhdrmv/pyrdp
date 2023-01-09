#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from logging import LoggerAdapter

from pyrdp.layer import TwistedTCPLayer
from pyrdp.logging.StatCounter import StatCounter
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu.player import PlayerConnectionClosePDU
from pyrdp.recording import Recorder
from pyrdp.mitm.config import MITMConfig
import json;
import datetime;

class TCPMITM:
    """
    MITM component for the TCP layer.
    """

    # Marvi 
        # Add MitmConfig ->config
    # Marvi 
    def __init__(self, client: TwistedTCPLayer, server: TwistedTCPLayer, attacker: TwistedTCPLayer, log: LoggerAdapter,
                 state: RDPMITMState, recorder: Recorder, statCounter: StatCounter, config: MITMConfig):
        """
        :param client: TCP layer for the client side
        :param server: TCP layer for the server side
        :param attacker: TCP layer for the attacker side
        :param log: logger for this component
        :param recorder: recorder for this connection
        """

        self.statCounter = statCounter
        # To keep track of useful statistics for the connection.
        self.client = client
        self.server = None
        self.attacker = attacker
        self.log = log
        self.state = state
        self.recorder = recorder
        self.config = config
        # Marvi 
        self.sessionID = config.sessionId
        # Marvi 

        # Allows a lower layer to raise error tagged with the correct sessionID
        self.client.log = log

        self.clientObserver = self.client.createObserver(
            onConnection = self.onClientConnection,
            onDisconnection = self.onClientDisconnection,
        )

        self.attacker.createObserver(
            onConnection = self.onAttackerConnection,
            onDisconnection = self.onAttackerDisconnection,
        )

        self.serverObserver = None
        self.setServer(server)

    def setServer(self, server: TwistedTCPLayer):
        if self.server is not None:
            self.server.removeObserver(self.serverObserver)
            self.server.disconnect(True)

        self.server = server
        self.server.log = self.log
        self.serverObserver = self.server.createObserver(
            onConnection=self.onServerConnection,
            onDisconnection=self.onServerDisconnection,
        )

    def detach(self):
        """
        Remove the observers from the layers.
        """

        self.client.removeObserver(self.clientObserver)
        self.server.removeObserver(self.serverObserver)

    def onClientConnection(self):
        """
        Log the fact that a new client has connected.
        """
        
        # Statistics
        self.statCounter.start()        

        ip = self.client.transport.client[0]
        port = self.client.transport.client[1]
        self.state.clientIp = ip
        self.log.extra['clientIp'] = ip
        self.log.info("New client connected from %(clientIp)s:%(clientPort)i",
                      {"clientIp": ip, "clientPort": port})

        ct = datetime.datetime.now()
        new_data = {   
                "action":"Server connected",
                "session_id": self.sessionID,
                "time": ct.timestamp()
            }
        
        with open('/store/transparent/logs/connected_servers.json','r+') as file:
            # First we load existing data into a dict.
            file_data = json.load(file)
            # Join new_data with file_data inside emp_details
            file_data["data"].append(new_data)
            # Sets file's current position at offset.
            file.seek(0)
            # convert back to json.
            json.dump(file_data, file, indent = 4)
            # Marvi

    def onClientDisconnection(self, reason):
        """
        Disconnect all the parts of the connection.
        :param reason: reason for disconnection
        """

        self.statCounter.stop(self.config)
        self.recordConnectionClose()
        self.log.info("Client connection closed. %(reason)s", {"reason": reason.value})
        if self.recorder.recordFilename:
            self.statCounter.logReport(self.log, {"replayFilename":
                                                  self.recorder.recordFilename})
        else:
            self.statCounter.logReport(self.log)

        self.recorder.finalize()
        self.server.disconnect(True)
        self.state.clientIp = None

        # For the attacker, we want to make sure we don't abort the connection to make sure that the close event is sent
        self.attacker.disconnect()
        self.detach()

    def onServerConnection(self):
        """
        Log the fact that a connection to the server was established.
        """
        self.log.info("Server connected")
        # Marvi
        #    Create json file to like {"data": [ {"a": "a","b":1}, {"a":"A", "b": 2} ]}
        # Start from here , We have SessionID

    def onServerDisconnection(self, reason):
        """
        Disconnect all the parts of the connection.
        :param reason: reason for disconnection
        """

        self.recordConnectionClose()
        self.recorder.finalize()
        self.log.info("Server connection closed. %(reason)s", {"reason": reason.value})
        self.client.disconnect(True)

        # For the attacker, we want to make sure we don't abort the connection to make sure that the close event is sent
        self.attacker.disconnect()
        self.detach()

    def onAttackerConnection(self):
        """
        Log the fact that a connection to the attacker was established.
        """
        self.log.info("Attacker connected")

    def onAttackerDisconnection(self, reason):
        """
        Log the disconnection from the attacker side.
        """
        self.state.forwardInput = True
        self.state.forwardOutput = True
        self.log.info("Attacker connection closed. %(reason)s", {"reason": reason.value})

    def recordConnectionClose(self):
        pdu = PlayerConnectionClosePDU(self.recorder.getCurrentTimeStamp())
        self.recorder.record(pdu, pdu.header)
