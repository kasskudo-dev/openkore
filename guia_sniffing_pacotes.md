# 🎯 Guia Completo: Sniffing de Pacotes ROla com OpenKore

> **Aviso: Conteúdo Gerado por IA**
>
> ⚠️ Este documento foi gerado com o auxílio de Inteligência Artificial. O conteúdo pode conter imprecisões ou estar incompleto. Recomenda-se verificar as informações antes de aplicá-las.

## 📋 **Visão Geral**

Este guia explica como usar as ferramentas do OpenKore para capturar pacotes do Ragnarok Online e gerar estruturas para o arquivo `recvpackets.txt`.

## 🛠️ **Ferramentas Disponíveis**

### **1. Python Packet Sniffer** (Mais Fácil)
- **Localização**: `tools/Packet Sniffer PY/`
- **Vantagem**: Captura direta do tráfego de rede
- **Uso**: Ideal para descobrir novos packets

### **2. Poseidon Server** (Intermediário)
- **Localização**: `src/Poseidon/`
- **Vantagem**: Emula servidor RO completo
- **Uso**: Para testar packets específicos

### **3. ASI Plugin** (Avançado)
- **Localização**: `recv.asi`
- **Vantagem**: Hook direto na função recv()
- **Uso**: Engenharia reversa profunda

## 🚀 **Método 1: Python Packet Sniffer (Recomendado)**

### **Passo 1: Configuração Inicial**

```bash
# 1. Instalar dependências
cd "tools/Packet Sniffer PY"
pip install -r requirements.txt

# 2. Windows: Instalar Npcap como Administrador
# Baixar: https://npcap.com/dist/npcap-1.79.exe

# 3. Executar terminal como Administrador
```

### **Passo 2: Descobrir Interface de Rede**

```bash
# Listar interfaces disponíveis
python packet_sniffer.py --list-interfaces
```

**Saída Exemplo:**
```
Interfaces de rede disponíveis:

 1. Wi-Fi - Microsoft Wi-Fi Direct Virtual Adapter
    Nome técnico: \Device\NPF_{7BB8E731-9A60-441E-AF44-2E033ECD64D2}

 2. Ethernet - Realtek PCIe GbE Family Controller
    Nome técnico: \Device\NPF_{99D7525F-6F6E-49F7-88EA-FD2B047D7237}
```

### **Passo 3: Capturar Pacotes em Tempo Real**

```bash
# Exemplo para servidor ROla
python packet_logger.py 172.65.200.86 6900 -i 2 -o session_rola.json

# Parâmetros:
# - 172.65.200.86: IP do servidor
# - 6900: Porta do servidor
# - -i 2: Interface de rede (número da lista)
# - -o: Arquivo de saída em JSON
```

### **Passo 4: Analisar Dados Capturados**

```bash
# Analisar arquivo salvo
python packet_logger.py --analyze session_rola.json
```

## 🔧 **Método 2: Poseidon Server**

### **Passo 1: Configurar Poseidon**

```bash
# Executar Poseidon
start-poseidon.exe
```

### **Passo 2: Configurar Cliente RO**

1. **Editar servers.txt do cliente RO:**
```
127.0.0.1:6901:ROla Test Server
```

2. **Configurar cliente para conectar no localhost**

### **Passo 3: Capturar Packets**

O Poseidon captura automaticamente os packets e os salva nos logs.

## 📊 **Analisando os Dados Capturados**

### **Estrutura dos Packets Descobertos**

Exemplo de packet capturado:
```
[14:30:25.123] RECV Opcode: 0x0C26 | Size: 94 bytes
0000: 26 0C 47 52 4F 00 75 73  65 72 6E 61 6D 65 00 00 | &.GRO.username..
0010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 | ................
...
```

### **Convertendo para recvpackets.txt**

**Formato atual no arquivo:**
```
0C26 94 94 0
```

**Significado:**
- `0C26`: ID do packet (opcode)
- `94`: Tamanho mínimo
- `94`: Tamanho máximo
- `0`: Flags

### **Criando Template Perl**

Com base na análise, você define o template:

```perl
'0C26' => [
    'master_login',                                   # nome da função
    'a4 Z51 a32 a5',                                  # template (92 bytes de dados)
    [qw(game_code username password_rijndael flag)]   # nomes dos campos
]
```

## 🎯 **Workflow Completo de Análise**

### **1. Capturar Packets**
```bash
python packet_logger.py [IP_SERVIDOR] [PORTA] -i [INTERFACE] -o nova_sessao.json
```

### **2. Identificar Packets Desconhecidos**
- Compare opcodes capturados com `recvpackets.txt` existente
- Identifique packets com tamanho `-1` (variável)

### **3. Análise Manual**
Para cada packet novo:

1. **Determinar Tamanho:**
   - Fixo: mesmo tamanho sempre
   - Variável: tamanho muda (-1)

2. **Analisar Estrutura:**
   - Examine o dump hex
   - Identifique campos (strings, números, flags)

3. **Criar Template:**
   ```perl
   # Exemplo para packet 0x1234 com 20 bytes
   'a4 Z16'  # 4 bytes + string de 16 bytes
   ```

### **4. Atualizar Arquivos**

**1. Adicionar em `recvpackets.txt`:**
```
1234 20 20 0
```

**2. Adicionar template no código Perl (se necessário)**

## 🔍 **Exemplo Prático: Descobrindo Packet 0x0C26**

### **Dados Capturados:**
```
Raw: 26 0C 47 52 4F 00 75 73 65 72 6E 61 6D 65 00 ...
```

### **Análise:**
1. **Opcode**: `0C26` (bytes 0-1)
2. **game_code**: `47 52 4F 00` = "GRO\0" (bytes 2-5)
3. **username**: `75 73 65 72 6E 61 6D 65 00` = "username\0" (bytes 6-56)
4. **password**: 32 bytes criptografados (bytes 57-88)
5. **flags**: 5 bytes finais (bytes 89-93)

### **Template Resultante:**
```perl
'0C26' => [
    'master_login',
    'a4 Z51 a32 a5',  # 4+51+32+5 = 92 bytes
    [qw(game_code username password_rijndael flag)]
]
```

## 🎛️ **Ferramentas Auxiliares**

### **Conversão IDA Python**
Use `export_convert_recvpackets.py` para extrair packets do executável via IDA Pro.

### **Visualização Hex**
```python
def visualize_packet(data):
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16])
        print(f"{i:04X}: {hex_part:<48} | {ascii_part}")
```

## 📈 **Dicas Avançadas**

### **1. Identificar Packets Variáveis**
- Monitore o mesmo packet em sessões diferentes
- Se o tamanho muda, use `-1` no recvpackets.txt

### **2. Criptografia**
- Alguns servers usam criptografia
- O Poseidon já tem suporte a descriptografia

### **3. Debugging**
- Use modo debug no Poseidon: `debug 1`
- Salve logs detalhados para análise posterior

## 🚨 **Problemas Comuns**

### **Nenhum Packet Capturado**
1. Verificar interface de rede correta
2. Executar como Administrador
3. Verificar IP e porta do servidor

### **Packets Criptografados**
1. Usar Poseidon com descriptografia
2. Verificar chaves de criptografia no código

### **Templates Incorretos**
1. Contar bytes manualmente
2. Testar com dados reais
3. Verificar endianness (little/big endian)

---

**🎯 Próximos Passos:**
1. Execute o packet sniffer
2. Capture uma sessão completa
3. Analise packets desconhecidos
4. Atualize o recvpackets.txt
5. Teste com o OpenKore
