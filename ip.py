from iputils import *
import ipaddress

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # (ainda não tratamos TTL no passo 1)
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr_str):
        if not self.tabela_encaminhamento:
            return None
        try:
            dest_addr_ip_obj = ipaddress.ip_address(dest_addr_str)
        except ValueError:
            return None

        for network_obj, _prefix_len, next_hop_ip in self.tabela_encaminhamento:
            if dest_addr_ip_obj in network_obj:
                return next_hop_ip
        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]
        """
        self.tabela_encaminhamento = []
        if tabela is None:
            return
        for cidr_str, next_hop_ip_str in tabela:
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                self.tabela_encaminhamento.append((network, network.prefixlen, next_hop_ip_str))
            except ValueError:
                pass
        self.tabela_encaminhamento.sort(key=lambda item: item[1], reverse=True)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # (não implementado ainda no Passo 1)
        self.enlace.enviar(segmento, next_hop)
