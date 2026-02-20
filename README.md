# Audit Network Tool

Una aplicación de auditoría IP con GUI en Python que permite conectar, validar y extraer información de dispositivos de red Switch y Router mediante SSH/Telnet, procesando listados desde un archivo XLS y generando resultados en archivos organizados por fabricante.

## Características
- Interfaz gráfica con Tkinter.
- Lectura automática de archivos `.xls` y conversión a `.xlsx`.
- Conexión SSH/Telnet a múltiples fabricantes: RuggedCom, Fortinet, Cisco y ZIV (uSysCom).
- Extracción de configuraciones: VLAN, interfaces, ARP, puertos, estadísticas, etc.
- Soporte para credenciales de servidores de autenticacion centralizada.
- Gestión de logs opcional.
- Generación automática de carpetas y archivos organizados.

## Requisitos
- Python 3.8+
- Librerías: `paramiko`, `ping3`, `openpyxl`, `pandas`, `tkinter` y estándar de Python.

## Instalación
```bash
pip install paramiko ping3 openpyxl pandas
```
Tkinter suele venir preinstalado con Python.

## Uso
1. Ejecutar el script:
```bash
python auditoria_ip.py
```
2. Seleccionar un archivo `.xls`.
3. Introducir credenciales cuando se solicite.
4. Esperar a que finalice el proceso y revisar la carpeta generada.

## Estructura generada
- Carpeta con nombre definido por el usuario.
- Dentro, archivos de texto por dispositivo con la configuración extraída.

## Funcionalidades adicionales
- Validación de sesión TACACS+ / RADIUS.
- Conteo de errores y sesiones correctas.
- Panel con barra de progreso.

## Licencia
Este proyecto puede usarse y modificarse libremente para auditoría y automatización.
