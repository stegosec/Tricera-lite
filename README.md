<!-- HERO -->
<div align="center">
  <h1>🦕 TriceraAudit Lite</h1>
  <p><em>Auditoría offline de configuraciones Fortinet (.conf)</em></p>

  <p>
    <img alt="Status" src="https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge">
    <img alt="Docker" src="https://img.shields.io/badge/Docker-ready-0db7ed?style=for-the-badge&logo=docker&logoColor=white">
  </p>
</div>

---

## 📦 Requisitos  

- 🐳 **Docker** y **Docker Compose** instalados.  
- 📂 Archivo de configuración **Fortinet (`.conf`)** exportado como backup.  
- 🌐 Navegador web moderno (Chrome, Edge o Firefox).  

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

