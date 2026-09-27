import os
import sys

def audit_cisco(filepath):
    print(f"\n[+] Auditando configuración CISCO IOS: {filepath}")
    print("=" * 60)
    
    findings = []
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
        
    content = "".join(lines)
    
    # Regla 1: Servicio de cifrado de contraseñas desactivado
    if "no service password-encryption" in content:
        findings.append({
            "severity": "ALTA",
            "issue": "Servicio 'service password-encryption' desactivado.",
            "recommendation": "Añade 'service password-encryption' para evitar contraseñas en texto plano."
        })

    # Regla 2: Uso de contraseñas débiles o sin cifrar
    for i, line in enumerate(lines, 1):
        if "password 7 " in line or "password 0 " in line:
            findings.append({
                "severity": "CRÍTICA",
                "issue": f"Línea {i}: Contraseña cifrada en Type 7 o texto plano detectada.",
                "recommendation": "Utiliza algoritmos de cifrado fuertes (Type 8 o Type 9 con 'enable secret')."
            })
        
        # Regla 3: Servidor HTTP no seguro habilitado
        if "ip http server" in line:
            findings.append({
                "severity": "ALTA",
                "issue": f"Línea {i}: Servidor web HTTP sin cifrar activo ('ip http server').",
                "recommendation": "Desactiva el servidor HTTP no seguro con 'no ip http server'."
            })

        # Regla 4: Uso de Telnet en líneas VTY
        if "transport input" in line and "telnet" in line:
            findings.append({
                "severity": "CRÍTICA",
                "issue": f"Línea {i}: Acceso por Telnet permitido en líneas VTY.",
                "recommendation": "Restringe la gestión únicamente a SSH ('transport input ssh')."
            })

    return findings


def audit_fortinet(filepath):
    print(f"\n[+] Auditando configuración FORTINET (FortiOS): {filepath}")
    print("=" * 60)
    
    findings = []
    
    with open(filepath, 'r') as f:
        lines = f.readlines()

    current_section = None
    
    for i, line in enumerate(lines, 1):
        clean_line = line.strip()
        
        if clean_line.startswith("config "):
            current_section = clean_line
            
        # Regla 1: Protocolos inseguros permitidos en interfaces de red (HTTP/Telnet)
        if "set allowaccess" in clean_line:
            if "http" in clean_line or "telnet" in clean_line:
                findings.append({
                    "severity": "CRÍTICA",
                    "issue": f"Línea {i}: Gestión insegura (HTTP/Telnet) habilitada en interfaz.",
                    "recommendation": "Elimina 'http' y 'telnet' de la directiva 'set allowaccess'."
                })
                
        # Regla 2: Reglas de Firewall muy permisivas sin perfiles UTM/Inspection
        if "set action accept" in clean_line:
            # Comprobar si en las líneas cercanas hay reglas de inspección activa
            findings.append({
                "severity": "MEDIA",
                "issue": f"Línea {i}: Regla de tráfico permitida detectada.",
                "recommendation": "Verifica que la regla aplique perfiles UTM (Antivirus, IPS, Web Filter, Deep SSL Inspection)."
            })

    return findings


def print_report(findings):
    if not findings:
        print(" [✓] No se han encontrado vulnerabilidades de configuración críticas.")
        return

    for item in findings:
        badge = f"[{item['severity']}]"
        print(f"{badge:<10} {item['issue']}")
        print(f"           Solución: {item['recommendation']}\n")


if __name__ == "__main__":
    cisco_file = os.path.join("samples", "cisco_sample.cfg")
    fortinet_file = os.path.join("samples", "fortigate_sample.conf")
    
    if os.path.exists(cisco_file):
        cisco_results = audit_cisco(cisco_file)
        print_report(cisco_results)
        
    if os.path.exists(fortinet_file):
        fortinet_results = audit_fortinet(fortinet_file)
        print_report(fortinet_results)