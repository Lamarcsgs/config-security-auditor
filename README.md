#  Network Configuration Security Auditor (Cisco & Fortinet)

Herramienta de **Análisis Estático de Seguridad (SAST para Infraestructura)** desarrollada en Python. Audita automáticamente volcados de configuración (*running-config* y *backups*) de dispositivos **Cisco IOS** y **Fortinet (FortiOS)** para identificar fallos de *hardening*, protocolos inseguros y debilidades de cifrado según estándares de la industria (como CIS Benchmarks).

##  Características
- **Auditoría Multi-Vendor:** Parser dedicado para sintaxis de Cisco IOS y FortiOS.
- **Detección de Riesgos Críticos:**
  - Contraseñas en texto plano o cifrados débiles (Cisco Type 7).
  - Servicios de administración inseguros activos (Telnet, HTTP sin TLS).
  - Interfaces expuestas sin restricciones de acceso adecuadas.
  - Reglas de firewall permisivas sin inspección UTM/SSL.
- **Trazabilidad Mapeada:** Identifica la línea exacta del archivo afectada y genera la recomendación técnica de remediación.
- **Zero External Dependencies:** Desarrollado íntegramente con la librería estándar de Python para máxima portabilidad y consumo nulo de recursos.

##  Requisitos
- Python 3.8 o superior

##  Instalación y Uso

1. Clona el repositorio:
   ```bash
   git clone [https://github.com/TU_USUARIO/config-security-auditor.git](https://github.com/TU_USUARIO/config-security-auditor.git)
   cd config-security-auditor

2. Ejecuta la auditoría sobre las muestras de prueba:

Bash
python main.py

Estructura del Proyecto
Plaintext
config-security-auditor/
├── main.py                 # Motor principal de auditoría y reglas SAST
├── samples/                # Muestras de configuración de prueba (Cisco / Fortinet)
│   ├── cisco_sample.cfg
│   └── fortigate_sample.conf
├── requirements.txt        # Dependencias del proyecto
└── README.md               # Documentación