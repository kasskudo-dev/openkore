#!/usr/bin/env python3
"""
ROla Packet Analyzer
Analisa logs de pacotes capturados e sugere entradas para recvpackets.txt

Uso:
    python packet_analyzer.py session.json
    python packet_analyzer.py --compare recvpackets.txt session.json
"""

import json
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime
import re

class PacketAnalyzer:
    def __init__(self):
        self.packet_stats = defaultdict(list)
        self.unknown_packets = set()
        self.variable_packets = set()
        
    def load_existing_recvpackets(self, recvpackets_file):
        """Carrega arquivo recvpackets.txt existente"""
        known_packets = set()
        
        try:
            with open(recvpackets_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 1:
                            # Converte hex para int se necessário
                            opcode = parts[0].upper()
                            if len(opcode) == 4:  # Formato XXXX
                                known_packets.add(int(opcode, 16))
                            
        except FileNotFoundError:
            print(f"Arquivo {recvpackets_file} não encontrado")
            
        return known_packets
    
    def analyze_session(self, session_file):
        """Analisa arquivo de sessão JSON"""
        try:
            with open(session_file, 'r') as f:
                data = json.load(f)
                
            packets = data.get('packets', [])
            print(f"Analisando {len(packets)} pacotes...")
            
            for packet in packets:
                opcode = packet.get('opcode', 0)
                size = packet.get('size', 0)
                direction = packet.get('direction', 'UNKNOWN')
                
                # Só analisa pacotes recebidos (RECV)
                if direction == 'RECV':
                    self.packet_stats[opcode].append(size)
                    
        except FileNotFoundError:
            print(f"Arquivo {session_file} não encontrado")
            return False
        except json.JSONDecodeError:
            print(f"Erro ao decodificar JSON em {session_file}")
            return False
            
        return True
    
    def generate_recvpackets_entries(self, known_packets=None):
        """Gera entradas sugeridas para recvpackets.txt"""
        if known_packets is None:
            known_packets = set()
            
        suggestions = []
        
        for opcode, sizes in self.packet_stats.items():
            if opcode in known_packets:
                continue
                
            # Estatísticas do packet
            size_counter = Counter(sizes)
            unique_sizes = list(size_counter.keys())
            min_size = min(sizes)
            max_size = max(sizes)
            avg_size = sum(sizes) / len(sizes)
            
            # Determina se é fixo ou variável
            if len(unique_sizes) == 1:
                # Tamanho fixo
                packet_type = "FIXO"
                suggested_min = min_size
                suggested_max = max_size
                flags = 0
            else:
                # Tamanho variável
                packet_type = "VARIÁVEL"
                suggested_min = -1
                suggested_max = min_size  # Tamanho mínimo conhecido
                flags = 0
                self.variable_packets.add(opcode)
            
            self.unknown_packets.add(opcode)
            
            suggestions.append({
                'opcode': opcode,
                'hex': f"{opcode:04X}",
                'type': packet_type,
                'min_size': suggested_min,
                'max_size': suggested_max,
                'flags': flags,
                'count': len(sizes),
                'sizes': unique_sizes[:5],  # Primeiros 5 tamanhos únicos
                'avg_size': avg_size
            })
        
        return sorted(suggestions, key=lambda x: x['opcode'])
    
    def print_analysis_report(self, suggestions, show_details=True):
        """Imprime relatório de análise"""
        print("\n" + "="*80)
        print("📊 RELATÓRIO DE ANÁLISE DE PACOTES")
        print("="*80)
        
        print(f"\n📈 Estatísticas Gerais:")
        print(f"   • Total de opcodes únicos: {len(self.packet_stats)}")
        print(f"   • Pacotes com tamanho fixo: {len(suggestions) - len(self.variable_packets)}")
        print(f"   • Pacotes com tamanho variável: {len(self.variable_packets)}")
        
        if not suggestions:
            print("\n✅ Todos os pacotes já estão no recvpackets.txt!")
            return
            
        print(f"\n🆕 Novos pacotes encontrados: {len(suggestions)}")
        print("\n" + "-"*80)
        print("ENTRADAS SUGERIDAS PARA recvpackets.txt:")
        print("-"*80)
        
        for suggestion in suggestions:
            hex_code = suggestion['hex']
            min_size = suggestion['min_size']
            max_size = suggestion['max_size']
            flags = suggestion['flags']
            packet_type = suggestion['type']
            count = suggestion['count']
            
            print(f"{hex_code} {min_size} {max_size} {flags}")
            
            if show_details:
                print(f"   # {packet_type} - {count} ocorrências")
                if suggestion['sizes']:
                    sizes_str = ', '.join(map(str, suggestion['sizes']))
                    print(f"   # Tamanhos: {sizes_str}")
                print()
        
        print("-"*80)
        print("💡 DICAS:")
        print("   • Copie as linhas acima para seu recvpackets.txt")
        print("   • Pacotes VARIÁVEIS (-1) precisam de análise manual")
        print("   • Teste com o OpenKore antes de usar em produção")
        
    def analyze_packet_patterns(self, session_file, opcode_hex):
        """Analisa padrões de um packet específico"""
        opcode = int(opcode_hex, 16)
        
        try:
            with open(session_file, 'r') as f:
                data = json.load(f)
                
            packets = data.get('packets', [])
            matching_packets = [p for p in packets if p.get('opcode') == opcode and p.get('direction') == 'RECV']
            
            if not matching_packets:
                print(f"Nenhum packet {opcode_hex} encontrado")
                return
                
            print(f"\n🔍 ANÁLISE DETALHADA DO PACKET {opcode_hex.upper()}")
            print("="*60)
            print(f"Total de ocorrências: {len(matching_packets)}")
            
            # Mostra primeiros 3 packets
            for i, packet in enumerate(matching_packets[:3]):
                print(f"\n--- Packet {i+1} ---")
                print(f"Timestamp: {packet.get('timestamp', 'N/A')}")
                print(f"Tamanho: {packet.get('size', 0)} bytes")
                
                # Dump hex dos primeiros 64 bytes
                data_hex = packet.get('data', '')
                if data_hex:
                    self.print_hex_dump(bytes.fromhex(data_hex)[:64])
                    
        except Exception as e:
            print(f"Erro ao analisar packet: {e}")
    
    def print_hex_dump(self, data):
        """Imprime dump hexadecimal formatado"""
        for i in range(0, len(data), 16):
            # Offset
            offset = f"{i:04X}:"
            
            # Bytes em hex
            hex_part = ""
            ascii_part = ""
            
            for j in range(16):
                if i + j < len(data):
                    byte_val = data[i + j]
                    hex_part += f"{byte_val:02X} "
                    
                    # Parte ASCII
                    if 32 <= byte_val <= 126:
                        ascii_part += chr(byte_val)
                    else:
                        ascii_part += "."
                else:
                    hex_part += "   "
                    ascii_part += " "
                    
                # Espaço extra no meio
                if j == 7:
                    hex_part += " "
            
            print(f"{offset:<6}{hex_part} | {ascii_part}")

def main():
    parser = argparse.ArgumentParser(description='ROla Packet Analyzer')
    parser.add_argument('session_file', help='Arquivo JSON de sessão capturada')
    parser.add_argument('--compare', '-c', help='Arquivo recvpackets.txt para comparar')
    parser.add_argument('--analyze', '-a', help='Analisar packet específico (hex, ex: 0C26)')
    parser.add_argument('--output', '-o', help='Arquivo de saída para as sugestões')
    parser.add_argument('--details', '-d', action='store_true', help='Mostrar detalhes dos packets')
    
    args = parser.parse_args()
    
    analyzer = PacketAnalyzer()
    
    # Analisa packet específico
    if args.analyze:
        analyzer.analyze_packet_patterns(args.session_file, args.analyze)
        return
    
    # Carrega sessão
    if not analyzer.analyze_session(args.session_file):
        return
    
    # Carrega recvpackets existente se fornecido
    known_packets = set()
    if args.compare:
        known_packets = analyzer.load_existing_recvpackets(args.compare)
        print(f"Carregados {len(known_packets)} pacotes conhecidos de {args.compare}")
    
    # Gera sugestões
    suggestions = analyzer.generate_recvpackets_entries(known_packets)
    
    # Imprime relatório
    analyzer.print_analysis_report(suggestions, args.details)
    
    # Salva arquivo de saída se solicitado
    if args.output and suggestions:
        with open(args.output, 'w') as f:
            f.write("# Entradas sugeridas para recvpackets.txt\n")
            f.write(f"# Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Fonte: {args.session_file}\n\n")
            
            for suggestion in suggestions:
                hex_code = suggestion['hex']
                min_size = suggestion['min_size']
                max_size = suggestion['max_size']
                flags = suggestion['flags']
                packet_type = suggestion['type']
                count = suggestion['count']
                
                f.write(f"# {packet_type} - {count} ocorrências\n")
                f.write(f"{hex_code} {min_size} {max_size} {flags}\n\n")
        
        print(f"\n💾 Sugestões salvas em: {args.output}")

if __name__ == '__main__':
    main() 