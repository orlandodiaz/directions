import socket
import binascii
import random
from log import log
import re
import sys


class Response(object):
    """ This response object has all the response information received from the DNS server"""

    def __init__(self, hex_resp, hex2b):
        self.ip = None
        self.msg = {}
        self.raw_msg = None
        self.code = None

        # Responses
        self.raw_resp = None
        self.hex_resp = hex_resp
        self.hex2b = hex2b

        self.header = None
        self.header_query = None
        self.header_flags = None

        self.dns_packet = {'header': dict()}

        self.parse_response(self.hex_resp)
        self.parse_ip(self.hex_resp)

    def __repr__(self):
        return "<Response [{}]>".format(self.dns_packet['header']['flags']['RCODE'])

    def parse_response(self, hex_resp):

        header_str = hex_resp[:24]
        header_query_str = header_str[:4]
        header_flags_str = header_str[4:8]

        flags_binary = ''
        for hex in header_flags_str:
            flags_binary += "{0:04b}".format(int(hex, 16))

        self.dns_packet['header']['raw_header'] = self.hex_resp[:24]
        self.dns_packet['header']['QUERY_ID'] = header_str[:4]

        self.dns_packet['header']['flags'] = {}
        self.dns_packet['queries'] = {}
        self.dns_packet['answers'] = {}
        self.dns_packet['aa_nameservers'] = {}
        self.dns_packet['additional_records'] = {}

        # print(flags_binary[6])
        # print(len(flags_binary))
        self.dns_packet['header']['flags']['QUERY_TYPE'] = 'Response' if bool(int(flags_binary[0])) else 'Query'
        self.dns_packet['header']['flags']['OPCODE'] = flags_binary[1:5]
        self.dns_packet['header']['flags']['AA'] = bool(int(flags_binary[5]))
        self.dns_packet['header']['flags']['TC'] = bool(int(flags_binary[6]))
        self.dns_packet['header']['flags']['RD'] = bool(int(flags_binary[7]))
        self.dns_packet['header']['flags']['RA'] = bool(int(flags_binary[8]))
        self.dns_packet['header']['flags']['Z'] = int(flags_binary[9])
        self.dns_packet['header']['flags']['AD'] = bool(int(flags_binary[10]))
        self.dns_packet['header']['flags']['CD'] = bool(int(flags_binary[11]))
        if flags_binary[12:] == '0000':
            self.dns_packet['header']['flags']['RCODE'] = 'NoError'
        elif flags_binary[12:] == '0001':
            self.dns_packet['header']['flags']['RCODE'] = 'FormError'
        elif flags_binary[12:] == '0010':
            self.dns_packet['header']['flags']['RCODE'] = 'ServFail'
        elif flags_binary[12:] == '0011':
            self.dns_packet['header']['flags']['RCODE'] = 'NXDomain'
        elif flags_binary[12:] == '0100':
            self.dns_packet['header']['flags']['RCODE'] = 'NotImp'
        elif flags_binary[12:] == '0101':
            self.dns_packet['header']['flags']['RCODE'] = 'Refused'

        if self.dns_packet['header']['flags']['RCODE'] != 'NoError':
            pass
        else:

            self.dns_packet['header']['QDCCOUNT'] = int(header_str[8:12], 16)
            self.dns_packet['header']['ANCOUNT'] = int(header_str[12:16], 16)
            self.dns_packet['header']['NSCOUNT'] = int(header_str[16:20], 16)
            self.dns_packet['header']['ARCOUNT'] = int(header_str[20:24], 16)

            # Question is a variable length not fixed!
            question = hex_resp[24:]
            # answer = hex_resp[58:]

            # Parse question
            # 1 byte = 8 bits
            # Each hex digit is 4 bits
            # Ex A is 4 bits
            # Ex AA is 1 byte or 8 bits
            # Ex C0 0C is 16 bits or 2 bytes

            hex_bytes = []
            for i in range(0, len(question), 2):
                hex_bytes.append("{}{}".format(question[i],question[i+1]))

            # print hex_bytes

            # First hex tells us the length
            question_len = int(hex_bytes[0], 16)
            # print question_len
            domain = ''
            for i in range(1, question_len+1):
                domain += unichr(int(hex_bytes[i], 16))

            # print "Domain: {}".format(domain)

            # print hex_bytes[question_len+2]

            tld_len = int(hex_bytes[question_len+1], 16)
            # print tld_len

            tld = ''
            qtype_pos = '' # QTYPE position
            for i in range(question_len + 2, question_len + 2 + tld_len):
                tld += unichr(int(hex_bytes[i], 16))
                qtype_pos = i+1


            # print "TLD: {}".format(tld)
            # print "QTYPE: {}".format(int(hex_bytes[qtype_pos+2], 16))
            # print "QCLASSE: {}".format(int(hex_bytes[qtype_pos+4], 16))


            # We are skipping the name part for now
            answer_section = hex_bytes[qtype_pos+5+2:]
            # print answer_section

            url = domain+"."+tld
            # Initialize domain dictioanry
            self.dns_packet['answers'][url] = {}

            self.dns_packet['answers'][url]['name'] = domain+"."+tld
            self.dns_packet['answers'][url]['TYPE'] = int(answer_section[1],16)
            self.dns_packet['answers'][url]['CLASS'] = int(answer_section[3],16)
            # print answer_section[4:7]
            self.dns_packet['answers'][url]['TTL'] = int("".join(answer_section[4:8]), 16)
            self.dns_packet['answers'][url]['RDLENGTH'] = int(answer_section[9],16)
            rdlen = self.dns_packet['answers'][url]['RDLENGTH']
            self.dns_packet['answers'][url]['RDATA'] = self.parse_ip("".join(answer_section[10:14]))

    def parse_ip(self, hex_resp):
        """Parses ip from complete plain hex response (not binary)"""
        ip_hex = hex_resp[-8:]
        ip_nums = []

        for i in range(0, len(ip_hex), 2):
            ip_nums.append(int(ip_hex[i:i + 2:], 16))

        ip = "{}.{}.{}.{}".format(ip_nums[0], ip_nums[1], ip_nums[2], ip_nums[3])
        self.ip = ip

        return ip


class Directions(object):
    def __init__(self):

        self.is_connected = False
        self.sock = None
        self.msg = None
        self.addr = ('', 8888)

        # Address for the DNS server
        # self.dns_server_addr = ('74.40.74.40', 53)

        self.dns_server_addr = ('8.8.8.8', 53)

    def build_packet(self, url):
        """Builds binary packet from hexadecimal values to send to DNS server"""

        msg = ""

        # Constructs a random query for the DNS query
        query = '{:x}{:x}'.format(random.randint(16, 255), random.randint(16, 255))

        # Default flags after query

        # 01 00 This is a query
        # 00 01 Query params
        # 00 00 0 answers
        # 00 00 0 authorit records
        # 00 00 0 additional records

        flags = "01 00 00 01 00 00 00 00 00 00"

        # Quetion and answer
        message_p3 = "00 00 01 00 01"

        # We are assuming the user is typing a url of the form domain.tld
        url = url.split('.')
        domain = url[0]
        tld = url[1]
        domain_len = len(domain)
        tld_len = len(tld)

        msg = query + flags + '0{:x}'.format(domain_len)

        for char in domain:
            msg += binascii.hexlify(char)

        msg += '0{:x}'.format(tld_len)

        for char in tld:
            msg += binascii.hexlify(char)

        msg += message_p3
        self.msg = msg

        return msg

    @staticmethod
    def build_hex_2bytes(self, hex_resp):
        """ Hex List separted after every 16 bits (2 bytes)"""
        hex2b = []

        hex2b = re.findall(r'.{2,4}', hex_resp)

        return hex2b

    def connect(self):
        """Establish connection to DNS Servers"""

        log.info("Connection being established")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Opens up port for listening to message
        log.info('Binding to port {}'.format(self.addr[1]))
        self.sock.bind(self.addr)

        self.is_connected = True

    def convert_to_binary(self, msg):
        """ Converts plain hex strings to python binary"""

        # Unhexlify doesnt like spaces
        msg = msg.replace(" ", "").replace("\n", "")

        msg = binascii.unhexlify(msg)
        self.msg = msg

        return msg

    @staticmethod
    def convert_to_hex(self, response):
        """ Converts binary to plain hex. Used for decoding response"""

        response = binascii.hexlify(response).decode("utf-8")
        return response

    def send_msg(self, msg):
        log.info('Sending message to DNS server')
        msg = self.convert_to_binary(msg)
        resp = None
        try:
            self.sock.sendto(msg, self.dns_server_addr)
            resp, _ = self.sock.recvfrom(4096)
        except Exception as ex:
            log.error(ex)
            raise Exception
        else:
            log.info("Message was successfully received")
            return resp
        finally:
            self.sock.close()
            self.is_connected = False
            self.raw_resp = resp

    def to(self, url):
        """ Sends message and returns DNS response object"""
        if not self.is_connected:
            self.connect()
        elif self.is_connected:
            self.sock.close()
            self.connect()

        self.msg = self.build_packet(url)

        raw_resp = self.send_msg(self.msg)

        # Read and save response
        hex_resp = self.convert_to_hex(raw_resp)
        hex2b = self.build_hex_2bytes(hex_resp)
        self.hex_resp = hex_resp

        # log.info("Hex to bytes: {}".format(hex2b))
        # print("Hex response: {}".format(self.hex_resp))

        return Response(self.hex_resp, hex2b)


if __name__ == '__main__':
    directions = Directions()






