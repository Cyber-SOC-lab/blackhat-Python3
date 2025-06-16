from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.util import List, ArrayList
import random

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        return

    def getGeneratorName(self):
        return "BHP Payload Generator"

    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)

class BHPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payloads = 10
        self.num_iterations = 0
        return

    def hasMorePayloads(self):
        return self.num_iterations < self.max_payloads

    def getNextPayload(self, current_payload):
        try:
            # Convert byte array to string
            payload = bytes(current_payload).decode('utf-8', errors='ignore')
            # Mutate the payload
            payload = self.mutate_payload(payload)
            # Increment iteration count
            self.num_iterations += 1
            # Convert string back to byte array
            return payload.encode('utf-8')
        except Exception as e:
            print("Error in getNextPayload: {}".format(e))
            self.num_iterations = self.max_payloads #prevent infinite loop
            return "".encode('utf-8')

    def reset(self):
        self.num_iterations = 0
        return

    def mutate_payload(self, original_payload):
        try:
            picker = random.randint(1, 3)
            offset = random.randint(0, len(original_payload) - 1)
            payload = original_payload[:offset]

            if picker == 1:
                payload += "'"
            elif picker == 2:
                payload += "<script>alert('BHP!');</script>"
            elif picker == 3:
                chunk_length = random.randint(1, len(original_payload) - offset)
                repeater = random.randint(1, 10)
                for i in range(repeater):
                    payload += original_payload[offset:offset + chunk_length]

            payload += original_payload[offset:]
            return payload
        except Exception as e:
            print("Error in mutate_payload: {}".format(e)) #changed line
            return original_payload
