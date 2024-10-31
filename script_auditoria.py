import nmap
import vulners
import socket
import json
from datetime import datetime

# Función para escanear los hosts activos en la red
def escanear_red(rango_ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=rango_ip, arguments='-sn')
    except Exception as e:
        print(f"Error escaneando la red: {e}")
        return []
    return nm.all_hosts()

# Función para escanear todos los puertos y detectar servicios/vulnerabilidades
def escanear_puertos(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-p- -sV -O --script vulners')
    except Exception as e:
        print(f"Error escaneando puertos en {ip}: {e}")
        return None
    return nm[ip]

# Función para obtener vulnerabilidades de un servicio a través de Vulners
def obtener_vulnerabilidades(servicio, version, id_vulnerabilidad):
    try:
        vulners_api = vulners.Vulners(api_key='')  # Asegúrate de agregar tu API key
        resultados = vulners_api.searchExploit(f"{servicio} {version}")
        vulnerabilidades = []
        if resultados:
            print(f"Vulnerabilidades encontradas para {servicio} {version}: {len(resultados)}")
            for resultado in resultados:
                nombre_vulnerabilidad = resultado.get('title', 'N/A')
                id_vulnerabilidad = resultado.get('id', 'N/A')
                if id_vulnerabilidad == id_vulnerabilidad:
                    print(f"ID: {id_vulnerabilidad}, Título: {nombre_vulnerabilidad}")
                    vulnerabilidades.append({
                        'id': id_vulnerabilidad,
                        'titulo': nombre_vulnerabilidad
                    })
            return vulnerabilidades
    except Exception as e:
        print(f"Error obteniendo vulnerabilidades para {servicio} {version}: {e}")
        return []


# Función para generar un informe en formato JSON
def generar_informe(resultados):
    informe = {
        'fecha_escaneo': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'hosts': resultados,
        'vuln_total': sum(len(host['puertos']) for host in resultados)
    }
    
    # Nombre del archivo basado en la fecha y hora
    nombre_archivo = f"informe_auditoria_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(nombre_archivo, 'w', encoding='utf-8') as f:
            json.dump(informe, f, indent=4, ensure_ascii=False)
        print(f"Informe generado: {nombre_archivo}")
    except Exception as e:
        print(f"Error guardando el informe: {e}")

# Función principal que orquesta el escaneo de la red y puertos
def main():
    rango_ip = input("Introduce el rango de IP a escanear (ejemplo: 192.168.1.0/24): ")
    print(f"Escaneando la red {rango_ip}...")
    
    hosts_activos = escanear_red(rango_ip)
    if not hosts_activos:
        print("No se encontraron hosts activos o ocurrió un error.")
        return
    
    print(f"Se encontraron {len(hosts_activos)} hosts activos.")
    
    resultados = []
    
    for ip in hosts_activos:
        print(f"\nEscaneando {ip}...")
        info_host = escanear_puertos(ip)
        if not info_host:
            print(f"Error escaneando {ip}, saltando al siguiente host.")
            continue
        
        datos_host = {
            'ip': ip,
            'hostname': socket.getfqdn(ip),
            'estado': info_host['status']['state'],
            'sistema_operativo': info_host.get('osmatch', [{'name':'Desconocido'}])[0]['name'],
            'puertos': []
        }
        
        for protocolo in ['tcp', 'udp']:
            if protocolo in info_host:
                for puerto, info_puerto in info_host[protocolo].items():
                    servicio = info_puerto['name']
                    version = info_puerto['version']
                    
                    print(f"  - Escaneando puerto {puerto}/{protocolo.upper()} ({servicio} {version})")
                    vulnerabilidades = obtener_vulnerabilidades(servicio, version, id_vulnerabilidad=any)
                    
                    datos_puerto = {
                        'numero': puerto,
                        'protocolo': protocolo.upper(),
                        'estado': info_puerto['state'],
                        'servicio': servicio,
                        'version': version,
                        'vulnerabilidades': vulnerabilidades
                    }
                    
                    datos_host['puertos'].append(datos_puerto)
            else:
                print(f"No se encontraron puertos {protocolo.upper()} abiertos en {ip}")
        
        resultados.append(datos_host)
    
    generar_informe(resultados)
    print("\nEscaneo completado. Revisa el informe generado para más detalles.")
    
    # Imprimir un resumen de la información recopilada
    print("\nResumen del escaneo:")
    for host in resultados:
        print(f"IP: {host['ip']}")
        print(f"Hostname: {host['hostname']}")
        print(f"Estado: {host['estado']}")
        print(f"Sistema Operativo: {host['sistema_operativo']}")
        print(f"Puertos abiertos: {len(host['puertos'])}")
        for puerto in host['puertos']:
            print(f"  - Puerto {puerto['numero']} ({puerto['protocolo']}): {puerto['servicio']} {puerto['version']}")
        print()

if __name__ == "__main__":
    main()