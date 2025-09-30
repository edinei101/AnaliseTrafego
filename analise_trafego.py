#!/usr/bin/env python3
"""
analise_trafego.py - Windows / TShark ready

Le o trafego.txt gerado pelo TShark,
conta eventos por IP de origem e detecta portscan
(mais de 10 portas distintas num intervalo de 60 segundos).

Gera relatorio.csv com colunas:
IP, Total_Eventos, Detectado_PortScan (Sim/Nao)
"""

import csv
from collections import defaultdict, deque

# Configuracoes
INPUT = r"trafego.txt"
OUTPUT = r"relatorio.csv"
WINDOW = 60.0
PORTSCAN_THRESHOLD = 10

events_by_src = defaultdict(list)
total_count = defaultdict(int)

# Leitura do arquivo - funciona com output do TShark no Windows
with open(INPUT, 'r') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) < 5:
            continue
        try:
            ts = float(parts[0])          # timestamp relativo
            src_ip = parts[1]             # IP de origem
            dst_port = int(parts[4])      # porta de destino
        except:
            continue
        events_by_src[src_ip].append((ts, dst_port))
        total_count[src_ip] += 1

# Funcao de deteccao de portscan
def detect_portscan(events):
    events.sort()
    dq = deque()
    ports_in_window = defaultdict(int)
    unique_ports = set()
    for ts, dport in events:
        dq.append((ts, dport))
        ports_in_window[dport] += 1
        unique_ports.add(dport)
        while dq and (ts - dq[0][0] > WINDOW):
            old_ts, old_port = dq.popleft()
            ports_in_window[old_port] -= 1
            if ports_in_window[old_port] == 0:
                unique_ports.discard(old_port)
        if len(unique_ports) > PORTSCAN_THRESHOLD:
            return True
    return False

# Monta relatorio
rows = []
for src, evs in events_by_src.items():
    total = total_count.get(src, 0)
    ps = detect_portscan(evs)
    rows.append([src, total, "Sim" if ps else "Nao"])

# Salva CSV
with open(OUTPUT, 'w', newline='') as csvf:
    writer = csv.writer(csvf)
    writer.writerow(["IP", "Total_Eventos", "Detectado_PortScan"])
    for r in rows:
        writer.writerow(r)

print(f"Relatorio gerado em {OUTPUT}")
