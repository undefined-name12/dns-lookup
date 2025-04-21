# Domain Scanner Tool

## Descripción

Este es un script Python diseñado para realizar un **análisis exhaustivo** de dominios web. Utilizando varias bibliotecas y herramientas, realiza diversas tareas como escaneo de registros DNS, obtención de información de IP, análisis de subdominios, puertos abiertos, encabezados HTTP, WHOIS, y mucho más.

Es una herramienta muy útil para tareas de **reconocimiento**, **pentesting** o simplemente para obtener más información sobre un dominio web.

## Características

- **Escaneo de registros DNS:** Detecta más de 40 tipos de registros DNS como `A`, `MX`, `NS`, `TXT`, entre otros.
- **Obtención de información de IP:** Incluye la IP del dominio y hace un reverse DNS lookup (PTR).
- **Escaneo de subdominios comunes:** Detecta subdominios como `www`, `ftp`, `mail`, `api`, etc.
- **Escaneo de puertos abiertos:** Escanea puertos comunes (21, 22, 23, 80, 443, etc.) para verificar servicios activos.
- **Análisis de encabezados HTTP:** Obtiene los encabezados HTTP del servidor y detecta cookies.
- **Consulta WHOIS del dominio:** Extrae detalles como el nombre del registrador, fechas de creación y expiración, servidores de nombres y más.
- **Detección de tecnología con UltraTech:** Identifica tecnologías web como `React.js`, `Vue.js`, `Angular`, y otros mediante herramientas como `Wappalyzer`.
- **Exploración de rutas comunes:** Detecta rutas comunes en la web como `/admin`, `/login`, `/wp-admin`, etc.
- **Descubrimiento de archivos:** Analiza la estructura de archivos y carpetas en el dominio.
- **Escaneo de CNAME para detectar CDN:** Detecta si el dominio está utilizando servicios de CDN como `Cloudflare`, `Akamai`, o `AWS`.

## Requisitos

Asegúrate de tener las siguientes dependencias instaladas:

- Python 3.x
- `requests`
- `beautifulsoup4`
- `dnspython`
- `ipwhois`
- `whois`
- `http.client`
- `urllib3`
- `wappalyzer` (si deseas usar la detección de tecnología UltraTech)
- `subprocess`

Puedes instalar las dependencias necesarias utilizando `pip`:

```bash
pip install requests beautifulsoup4 dnspython ipwhois whois urllib3
