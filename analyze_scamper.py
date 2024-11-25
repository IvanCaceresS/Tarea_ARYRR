import os
import re
import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from openpyxl import Workbook

# Directorio donde están los archivos .txt generados por Scamper
results_dir = "./results"

# Función para extraer hops desde un archivo de Scamper
def parse_scamper_file(file_path):
    hops = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if re.match(r"^\d+", line):  # Solo líneas que inician con un número
                parts = line.split()
                ip = parts[1] if len(parts) > 1 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]) else None
                if ip:
                    hops.append(ip)
    return hops

# Función para extraer hops desde un archivo de tracelb
def parse_tracelb_file(file_path):
    hops = set()  # Usamos un conjunto para evitar duplicados
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if "->" in line:  # Solo líneas con enlaces de nodos
                # Extraer las IPs de cada hop
                matches = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
                hops.update(matches)  # Añadir al conjunto
    return list(hops)

# Función para obtener el AS asociado a una IP utilizando bgp.he.net
def get_as_number(ip):
    url = f"https://bgp.he.net/ip/{ip}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar el AS en la sección "Announced By" (tabla "Origin AS")
            asn_link = soup.select_one('#ipinfo table tbody tr td a')
            if asn_link:
                return asn_link.text.strip()
            
            # Si no se encuentra en la tabla, intentar buscar en el texto
            aut_num_match = re.search(r"aut-num:\s*(AS\d+)", response.text)
            if aut_num_match:
                return aut_num_match.group(1)
    except requests.RequestException as e:
        print(f"Error al obtener el AS para {ip}: {e}")
    return "AS desconocido"

# Procesar archivos y organizar por método y IP destino
def process_results():
    results = defaultdict(lambda: defaultdict(list))
    for file_name in os.listdir(results_dir):
        if file_name.endswith(".txt") and "trace" in file_name:
            file_path = os.path.join(results_dir, file_name)
            try:
                parts = file_name.split("_")
                method = parts[0].lower()
                ip = ".".join(parts[2:]).replace(".txt", "").replace("_", ".")
                
                if method == "tracelb":
                    hops = parse_tracelb_file(file_path)
                else:
                    hops = parse_scamper_file(file_path)
                
                results[ip][method] = hops
            except IndexError:
                print(f"Archivo ignorado: {file_name}")
    return results

# Exportar los datos a un archivo .xlsx
def export_to_excel(results, as_info, output_file="scamper_analysis.xlsx"):
    wb = Workbook()
    ws = wb.active
    ws.title = "Scamper Analysis"

    # Escribir encabezados
    ws.append(["IP DESTINO", "METODO", "HOP-N°", "HOP-NODO", "AS"])

    # Escribir datos
    for ip, methods in results.items():
        for method, hops in methods.items():
            for hop_index, hop in enumerate(hops, 1):
                as_number = as_info.get(hop, "AS desconocido")
                ws.append([ip, method.upper(), hop_index, hop, as_number])

    # Guardar el archivo
    wb.save(output_file)
    print(f"Datos exportados a {output_file}")

# Programa principal
def main():
    print("Procesando resultados de Scamper...")
    results = process_results()
    
    print("Obteniendo información de AS para cada IP...")
    all_ips = {ip for methods in results.values() for hops in methods.values() for ip in hops}
    as_info = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(get_as_number, ip): ip for ip in all_ips}
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                as_info[ip] = future.result()
                #print(f"AS obtenido: {as_info[ip]} para {ip}")
            except Exception as e:
                #print(f"Error al obtener AS para {ip}: {e}")
                as_info[ip] = "AS desconocido"
    
    print("Exportando resultados a Excel...")
    export_to_excel(results, as_info)

if __name__ == "__main__":
    main()
