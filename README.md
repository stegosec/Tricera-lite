<!-- HERO -->
<div align="center">
  <h1>🦕 TriceraAudit Lite</h1>
  <p><em>Auditoría offline de configuraciones Fortinet (.conf)</em></p>

  <!-- Badges -->
  <p>
    <img alt="Status" src="https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge">
    <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-0db7ed?style=for-the-badge&logo=docker&logoColor=white">
  </p>
</div>

---

# 🦕 TriceraAudit Lite  

**TriceraAudit Lite** es una herramienta ligera de **auditoría offline** para respaldos de configuración **Fortinet (.conf)**.  
Su propósito es brindar una validación rápida y básica de archivos de configuración, directamente en tu equipo y sin necesidad de exponer datos en la nube.  

---

## 📦 Requisitos  

- **Docker** y **Docker Compose** instalados.  
- Archivo de configuración Fortinet (`.conf`) exportado como backup.  
- Navegador web moderno (Chrome, Edge o Firefox).  

---

## 🚀 Funciones actuales  

- 📂 **Carga de archivos `.conf`** → análisis de configuraciones Fortinet desde backups locales.  
- 🛡️ **Reglas baseline** → validaciones básicas de configuración (ejemplo: políticas por defecto, servicios abiertos).  
- 📢 **PSIRT Lite** → muestra avisos públicos de seguridad de Fortinet asociados a la versión detectada.  
- 🌐 **Interfaz web simple** → subir un archivo y obtener un **resumen de hallazgos** en pantalla.  
- 💻 **Modo consola** → logs en CLI con detalle de análisis y hallazgos detectados.  

---

## ⚡ Instalación y uso  

1. Clonar el repositorio:  
   ```bash
   git clone https://github.com/stegosec/Tricera-lite.git
   cd Tricera-lite

2. Construir y levantar los servicios:

docker compose build
docker compose up -d


3. Abrir en el navegador:
👉 http://localhost:8000

4. Subir un archivo .conf de Fortinet y revisar el resumen en pantalla.

📊 Ejemplo de ejecución en consola
git clone https://github.com/stegosec/Tricera-lite.git
cd Tricera-lite
docker compose up -d


Salida típica:

[scanner] Detected Fortinet .conf file
[scanner] Running baseline checks...
[scanner] 2 warnings found

🔧 Comandos útiles

Detener servicios

docker compose down


Ver logs en tiempo real

docker compose logs -f


Reconstruir desde cero

docker compose build --no-cache

🛣️ Roadmap (Lite)

✅ Auditoría básica de .conf Fortinet

✅ Validaciones baseline iniciales

✅ PSIRT Lite con avisos generales de Fortinet

🔜 Exportar hallazgos a PDF/CSV

🔜 Nuevas reglas de validación basadas en CIS/NIST

🔜 Dashboard mejorado con visualización de riesgos

🔜 Soporte multi-vendor (Cisco, Palo Alto, Juniper) → versión Pro
