import struct
from iputils import *

IPV4_HEADER_DEF_SIZE = 20

def disable_nbits(orig_data, nbits):
    strBits = bin(orig_data)[2:]
    newLista = [int(bit) if i < len(strBits) - nbits else 0 for i, bit in enumerate(strBits)]
    return int(''.join(map(str, newLista)), 2)

def get_checksum(header):
    return struct.pack("!H", calc_checksum(header))

def icmp_header(seg):
    header_struct = struct.pack('!BBHII', 11, 0, 0, 0, 0)  
    dados = bytearray(header_struct)
    dados[8:12] = seg
    dados[2:4] = get_checksum(dados)
    return bytes(dados)

def ipv4_header(seg, id_, protocol, src, dst):
    def get_int_from_addr(addr):
        intLista = str2addr(addr)
        return int.from_bytes(intLista, byteorder='big')

    header = struct.pack(
        "!BBHHHBBHII",
        (4 << 4) | 5, 0, IPV4_HEADER_DEF_SIZE + len(seg),
        int(id_), 0, 64, protocol, 0,
        get_int_from_addr(src), get_int_from_addr(dst)
    )

    dados = bytearray(header)
    dados[10:12] = get_checksum(dados)
    return bytes(dados) + seg

class IP:
    def __init__(self, enlace):
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self._count = -1

    @property
    def count(self):
        self._count += 1
        return self._count

    def __raw_recv(self, dadosa):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(dadosa)
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            if ttl < 2:
                seg = icmp_header(dadosa)
                dados = ipv4_header(seg, self.count, IPPROTO_ICMP, self.meu_endereco, src_addr)
                return self.enlace.enviar(dados, next_hop)
            else:
                nw_dados = bytearray(dadosa)
                ttl -= 1
                nw_dados[8] = ttl
                nw_dados[10:12] = [0, 0]
                nw_dados[10:12] = get_checksum(nw_dados[:IPV4_HEADER_DEF_SIZE])
                self.enlace.enviar(bytes(nw_dados), next_hop)

    def _next_hop(self, dest_addr):
        hop = 0
        max_prefix = 0

        for cidr, next_hop in self.tabela_hash.items():
            net, prefix = cidr.split('/')
            var_bits = 32 - int(prefix)
            (net_,) = struct.unpack("!I", str2addr(net))
            (dest_,) = struct.unpack("!I", str2addr(dest_addr))

            if (disable_nbits(net_, var_bits) == disable_nbits(dest_, var_bits)) and int(prefix) >= int(max_prefix):
                max_prefix = prefix
                hop = next_hop

        return hop if hop != 0 else None

    def definir_endereco_host(self, meu_endereco):
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela = [{'cidr': item[0], 'next_hop': item[1]} for item in tabela]
        self.tabela_hash = {item[0]: item[1] for item in tabela}

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        next_hop = self._next_hop(dest_addr)
        self.enlace.enviar(
            ipv4_header(
                seg=segmento,
                id_=self.count,
                protocol=IPPROTO_TCP,
                src=self.meu_endereco,
                dst=dest_addr
            ),
            next_hop
        )
