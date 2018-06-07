import socket
import binascii
import random
from log import log


class Response(object):
    """ This response object has all the response information received from the DNS server"""

    def __init__(self, hex_resp):
        self.ip = None
        self.msg = {}
        self.raw_msg = None
        self.code = None
        self.raw_resp = None
        self.hex_resp = hex_resp
        # self.dns_packet['header']['flags'] =

        self.header = None
        self.header_query = None
        self.header_flags = None

        self.dns_packet = {'header': dict()}

        self.parse_response(self.hex_resp)
        self.parse_ip(self.hex_resp)
        self.hex2b = None

        # print self.__repr__()

    def __repr__(self):
        return "<Response [{}]>".format(self.dns_packet['header']['flags']['RCODE'])

    def parse_response(self, hex_resp):





        # self.header_str = hex_resp[:24]
        # self.header_query_str = self.header_str[:4]
        # self.header_flags_str = self.header_str[4:8]
        #
        # flags_binary = ''
        # for hex in self.header_flags_str:
        #     flags_binary += "{0:04b}".format(int(hex, 16))
        #
        # self.dns_packet['header']['raw_header'] = self.hex_resp[:24]
        # self.dns_packet['header']['QUERY_ID'] = self.header_str[:4]
        #
        # self.dns_packet['header']['flags'] = {}
        # self.dns_packet['queries'] = {}
        # self.dns_packet['answers'] = {}
        # self.dns_packet['aa_nameservers'] = {}
        # self.dns_packet['additional_records'] = {}
        #
        # # print(flags_binary[6])
        # # print(len(flags_binary))
        # self.dns_packet['header']['flags']['QUERY_TYPE'] = 'Response' if bool(int(flags_binary[0])) else 'Query'
        # self.dns_packet['header']['flags']['OPCODE'] = flags_binary[1:5]
        # self.dns_packet['header']['flags']['AA'] = bool(int(flags_binary[5]))
        # self.dns_packet['header']['flags']['TC'] = bool(int(flags_binary[6]))
        # self.dns_packet['header']['flags']['RD'] = bool(int(flags_binary[7]))
        # self.dns_packet['header']['flags']['RA'] = bool(int(flags_binary[8]))
        # self.dns_packet['header']['flags']['Z'] = int(flags_binary[9])
        # self.dns_packet['header']['flags']['AD'] = bool(int(flags_binary[10]))
        # self.dns_packet['header']['flags']['CD'] = bool(int(flags_binary[11]))
        # if flags_binary[12:] == '0000':
        #     self.dns_packet['header']['flags']['RCODE'] = 'NoError'
        # elif flags_binary[12:] == '0001':
        #     self.dns_packet['header']['flags']['RCODE'] = 'FormError'
        # elif flags_binary[12:] == '0010':
        #     self.dns_packet['header']['flags']['RCODE'] = 'ServFail'
        # elif flags_binary[12:] == '0011':
        #     self.dns_packet['header']['flags']['RCODE'] = 'NXDomain'
        # elif flags_binary[12:] == '0100':
        #     self.dns_packet['header']['flags']['RCODE'] = 'NotImp'
        # elif flags_binary[12:] == '0101':
        #     self.dns_packet['header']['flags']['RCODE'] = 'Refused'
        #
        # self.dns_packet['header']['QDCCOUNT'] = int(self.header_str[8:12], 16)
        # self.dns_packet['header']['ANCOUNT'] = int(self.header_str[12:16], 16)
        # self.dns_packet['header']['NSCOUNT'] = int(self.header_str[16:20], 16)
        # self.dns_packet['header']['ARCOUNT'] = int(self.header_str[20:24], 16)
        #
        # question = hex_resp[24:58]
        # answer = hex_resp[58:]
        #
        # # Parse question
        #
        #
        # # 1 byte = 8 bits
        # # Each hex digit is 4 bits
        # # So C0 0C is 16 bits or 2 bytes
        #
        # hex_bytes = []
        # for i in range(0, len(question), 2):
        #     hex_bytes.append("{}{}".format(question[i],question[i+1]))
        #
        # print hex_bytes
        #
        # # First hex tells us the length
        # question_len = int(hex_bytes[0], 16)
        #
        # domain = ''
        # for i in range(1, question_len+1):
        #     domain += unichr(int(hex_bytes[i], 16))
        #
        # print "Domain: {}".format(domain)
        #
        # answer_len = int(hex_bytes[question_len+2], 16)
        #
        # tld = ''
        # for i in range(question_len + 2, question_len + 5):
        #     tld += unichr(int(hex_bytes[i], 16))
        #
        # print "TLD: {}".format(tld)
        #
        # # Hence we iterate
        #
        # # Parse answer

    def parse_ip(self, hex_resp):
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

        msg = ""

        # Constructs a random query for the DNS query
        query = '{:x}{:x}'.format(random.randint(16, 255), random.randint(16, 255))

        # Default flags
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

        # print(msg)

        raw_resp = self.send_msg(msg)
        # print resp.__repr__()
        hex_resp = self.convert_to_hex(raw_resp)
        self.hex_resp = hex_resp

        return hex_resp

    def build_hex_2bytes(self, hex_resp):
        """ Hex List separted after every 16 bits"""
        hex2b = []

        for i in range(0, len(hex_resp), 4):
            hex2b.append("{}{}{}{}".format(hex_resp[i], hex_resp[i + 1]
                                           , hex_resp[i+2], hex_resp[i+3]))

        return hex2b


    def connect(self):
        # Establish an UDP connection
        log.info("Connection being established")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Opens up port for listening to message
        log.info('Binding to port {}'.format(self.addr[1]))
        self.sock.bind(self.addr)

        self.is_connected = True

    def convert_to_binary(self, msg):
        """ Converts hex to python binary"""

        # Unhexlify doesnt like spaces
        msg = msg.replace(" ", "").replace("\n", "")

        msg = binascii.unhexlify(msg)
        self.msg = msg

        return msg

    def convert_to_hex(self, response):
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
        if not self.is_connected:
            print('connecting again')
            self.connect()

        self.hex_resp = self.build_packet(url)
        hex2b = self.build_hex_2bytes(self.hex_resp)

        log.info("Hex to bytes: {}".format(hex2b))
        # print("Hex response: {}".format(self.hex_resp))

        return Response(self.hex_resp)


if __name__ == '__main__':
    directions = Directions()






