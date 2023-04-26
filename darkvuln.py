import nmap
import os

# Cria um objeto de scanner Nmap
scanner = nmap.PortScanner()

# Define o endereço IP ou intervalo de IP a ser escaneado
ip = '192.168.0.1/24'

# Realiza o scan de todos os portas abertas no IP especificado
scanner.scan(ip, arguments='-p-')

# Lista de vulnerabilidades identificadas
vulnerabilidades = []

# Itera sobre todos os hosts escaneados
for host in scanner.all_hosts():
    print('Host : %s (%s)' % (host, scanner[host].hostname()))
    print('Estado : %s' % scanner[host].state())
    
    # Itera sobre todos os protocolos escaneados para o host atual
    for proto in scanner[host].all_protocols():
        print('Protocolo : %s' % proto)

        # Itera sobre todas as portas abertas para o protocolo atual
        for port in scanner[host][proto].keys():
            print('Porta : %s\tEstado : %s' % (port, scanner[host][proto][port]['state']))
            
            # Verifica vulnerabilidades na porta atual
            if scanner[host]['tcp'][port]['state'] == 'open':
                cmd = 'sudo openvasmd --progress --check-setup'
                os.system(cmd)

                cmd = 'sudo omp -u admin -w admin -G 0 -T'
                output = os.popen(cmd).read()
                results = output.split('\n')[2:-2]

                for result in results:
                    cols = result.split('|')
                    if cols[2] == port:
                        vulnerabilidades.append({'host': host, 'port': port, 'name': cols[1], 'severity': cols[4]})

# Imprime vulnerabilidades identificadas
if len(vulnerabilidades) > 0:
    print('Vulnerabilidades encontradas:')
    for v in vulnerabilidades:
        print('Host : %s Porta : %s Nome : %s Severidade : %s' % (v['host'], v['port'], v['name'], v['severity']))
else:
    print('Nenhuma vulnerabilidade encontrada.')
