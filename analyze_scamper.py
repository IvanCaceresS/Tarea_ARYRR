import os
import re
import requests
from bs4 import BeautifulSoup
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

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
                hops = parse_scamper_file(file_path)
                results[ip][method] = hops
            except IndexError:
                print(f"Archivo ignorado: {file_name}")
    return results

# Identificar nodos problemáticos
def identify_problematic_nodes(results):
    problematic_nodes = defaultdict(lambda: defaultdict(list))
    for ip, methods in results.items():
        all_nodes = set()
        for method, hops in methods.items():
            all_nodes.update(hops)
        
        for method, hops in methods.items():
            missing_nodes = all_nodes - set(hops)
            for node in missing_nodes:
                problematic_nodes[node][method].append(ip)
    return problematic_nodes

# Comparar resultados entre métodos y con tracelb
def compare_methods(results):
    comparison = {}
    tracelb_results = {}
    for ip, methods in results.items():
        comparison[ip] = {}
        tracelb_results[ip] = methods.get("tracelb", [])
        for method, hops in methods.items():
            if method != "tracelb":
                comparison[ip][method] = len(hops)
    return comparison, tracelb_results

# Comparar tracelb con métodos estándar
def compare_with_tracelb(tracelb_results, results):
    tracelb_comparison = {}
    for ip, tracelb_hops in tracelb_results.items():
        tracelb_nodes = set(tracelb_hops)
        tracelb_comparison[ip] = {}
        for method, hops in results[ip].items():
            if method != "tracelb":
                method_nodes = set(hops)
                tracelb_comparison[ip][method] = {
                    "nodes_in_tracelb": len(tracelb_nodes),
                    "nodes_in_method": len(method_nodes),
                    "unique_to_tracelb": tracelb_nodes - method_nodes,
                    "unique_to_method": method_nodes - tracelb_nodes,
                }
    return tracelb_comparison

# Generar informe
def generate_report(results, problematic_nodes, comparison, as_info, tracelb_comparison):
    report_file = "scamper_analysis_report.txt"
    with open(report_file, "w") as f:
        f.write("IPs obtenidas por método y hop, con AS asociado:\n")
        for ip, methods in results.items():
            f.write(f"\nIP destino: {ip}\n")
            for method, hops in methods.items():
                f.write(f"  Método {method}:\n")
                for hop_index, hop in enumerate(hops, 1):
                    as_number = as_info.get(hop, "AS desconocido")
                    f.write(f"    Hop {hop_index}: {hop} (AS: {as_number})\n")
        
        f.write("\nComparación de métodos:\n")
        for ip, methods in comparison.items():
            f.write(f"\nIP destino: {ip}\n")
            for method, count in methods.items():
                f.write(f"  Método {method}: {count} saltos detectados\n")

        f.write("\nNodos problemáticos:\n")
        for node, methods in problematic_nodes.items():
            f.write(f"\nNodo: {node}\n")
            for method, ips in methods.items():
                f.write(f"  No responde al método {method}, afecta a las IPs destino: {', '.join(ips)}\n")
        
        f.write("\nComparación de tracelb con métodos estándar:\n")
        for ip, methods in tracelb_comparison.items():
            f.write(f"\nIP destino: {ip}\n")
            for method, data in methods.items():
                f.write(f"  Método {method}:\n")
                f.write(f"    Nodos en tracelb: {data['nodes_in_tracelb']}\n")
                f.write(f"    Nodos en método: {data['nodes_in_method']}\n")
                f.write(f"    Nodos únicos en tracelb: {', '.join(data['unique_to_tracelb'])}\n")
                f.write(f"    Nodos únicos en método: {', '.join(data['unique_to_method'])}\n")
    print(f"Informe generado: {report_file}")

# Programa principal
def main():
    print("Procesando resultados de Scamper...")
    results = process_results()
    
    print("Identificando nodos problemáticos...")
    problematic_nodes = identify_problematic_nodes(results)
    
    print("Comparando métodos y procesando tracelb...")
    comparison, tracelb_results = compare_methods(results)
    tracelb_comparison = compare_with_tracelb(tracelb_results, results)
    
    print("Obteniendo información de AS para cada IP...")
    all_ips = {ip for methods in results.values() for hops in methods.values() for ip in hops}
    as_info = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(get_as_number, ip): ip for ip in all_ips}
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                as_info[ip] = future.result()
                print(f"AS obtenido: {as_info[ip]} para {ip}")
            except Exception as e:
                print(f"Error al obtener AS para {ip}: {e}")
                as_info[ip] = "AS desconocido"
    
    print("Generando informe...")
    generate_report(results, problematic_nodes, comparison, as_info, tracelb_comparison)

if __name__ == "__main__":
    main()
