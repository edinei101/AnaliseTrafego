# README – A5: Automação de Análise de Tráfego de Rede (Windows)

## 1. Objetivo

Capturar pacotes IP da rede, contar eventos por IP de origem e detectar port scan (mais de 10 portas distintas em 60 segundos). O resultado é salvo em **relatorio.csv**.

## 2. Captura de tráfego

1. Instale o **Wireshark/TShark** no Windows.
2. Identifique sua interface de rede:

```cmd
tshark -D
```

3. Capture pacotes IP por 60 segundos e salve em texto:

```cmd
tshark -i 2 -f "ip" -a duration:60 -T fields -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport > trafego.txt
```

> Substitua `-i 2` pelo número da interface correta.

## 3. Execução do script Python

1. Coloque `analise_trafego.py` e `trafego.txt` no mesmo diretório.
2. Execute:

```cmd
python analise_trafego.py
```

3. Será gerado **relatorio.csv**.

## 4. Interpretação do CSV

| Coluna                 | Descrição                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------ |
| **IP**                 | Endereço IP de origem do pacote                                                      |
| **Total_Eventos**      | Número total de pacotes enviados por este IP                                         |
| **Detectado_PortScan** | "Sim" se o IP tentou acessar mais de 10 portas distintas em 60 segundos, senão "Nao" |

## 5. Limitações

* Depende do formato da saída do TShark. Se o arquivo `trafego.txt` estiver em formato diferente, o script pode não ler corretamente.
* Falsos positivos podem ocorrer se um serviço legítimo abrir várias portas rapidamente.
* Falsos negativos se o tráfego for muito baixo ou distribuído no tempo.
* O limiar de portas e o intervalo podem ser ajustados no script (`PORTSCAN_THRESHOLD` e `WINDOW`).
