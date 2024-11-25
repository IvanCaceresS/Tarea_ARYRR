import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Lista de IPs de destino
destination_ips = [
    "185.131.204.20",
    "5.161.76.19",
    "80.77.4.60",
    "130.104.228.159"
]

# Métodos disponibles en Scamper
methods = ["UDP", "ICMP", "UDP-Paris", "ICMP-Paris", "TCP", "TCP-ACK"]

# Directorio para guardar los resultados
results_dir = "./results"

# Verificar si el directorio existe, si no, crearlo
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

def run_scamper(ip, method):
    output_file = os.path.join(results_dir, f"{method.lower()}_trace_{ip.replace('.', '_')}.txt")
    command = f"sudo scamper -I \"trace -P {method} {ip}\" -O text -o {output_file}"
    print(f"Ejecutando: {command}")
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Salida guardada en: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")

def run_tracelb(ip):
    output_file = os.path.join(results_dir, f"tracelb_trace_{ip.replace('.', '_')}.txt")
    command = f"sudo scamper -I \"tracelb {ip}\" -O text -o {output_file}"
    print(f"Ejecutando: {command}")
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Salida guardada en: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar tracelb: {e}")

def generate_tasks():
    tasks = []
    for ip in destination_ips:
        for method in methods:
            tasks.append((ip, method))
    return tasks

def main():
    print(f"Guardando resultados en el directorio: {results_dir}")
    tasks = generate_tasks()
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(run_scamper, ip, method) for ip, method in tasks]
        for future in futures:
            future.result()
        tracelb_futures = [executor.submit(run_tracelb, ip) for ip in destination_ips]
        for future in tracelb_futures:
            future.result()

if __name__ == "__main__":
    main()
