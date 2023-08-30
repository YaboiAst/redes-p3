from iputils import *

IPV4_HEADER_DEF_SIZE = 20

class ChatIP:
    def __init__(self, enlace):
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.meu_endereco = None
        self.tabela_hash = {}

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            if ttl < 2:
                seg = icmp_header(datagrama)
                datagram = ipv4_header(seg, self.count, IPPROTO_ICMP, self.meu_endereco, src_addr)
                return self.enlace.enviar(datagram, next_hop)
            else:
                nw_datagram = bytearray(datagrama)
                ttl -= 1
                nw_datagram[8] = ttl
                nw_datagram[10:12] = [0, 0]
                nw_datagram[10:12] = get_checksum(nw_datagram[:IPV4_HEADER_DEF_SIZE])
                self.enlace.enviar(bytes(nw_datagram), next_hop)

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

if __name__ == "__main__":
    chat_ip = ChatIP(enlace)
    chat_ip.definir_endereco_host('192.168.88.235')
    chat_ip.definir_tabela_encaminhamento([
        ('192.168.88.231/32', '192.168.88.231'),
        ('0.0.0.0/0', '192.168.88.1')
    ])
    chat_ip.registrar_recebedor(callback_function)
