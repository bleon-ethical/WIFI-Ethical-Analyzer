**WIFI Analyzer**



WIFI Analyzer es una herramienta de ciberseguridad avanzada, modular y de código abierto diseñada para auditar redes. Proporciona una suite completa de funcionalidades que van desde el análisis de tráfico hasta la detección de vulnerabilidades y la creación de payloads avanzados con inteligencia artificial.



Características Principales

GUI Amigable: Una interfaz de usuario moderna y fácil de usar construida con customtkinter.



Gestión de Interfaz: Configura y restaura interfaces de red al modo monitor o gestionado.



Análisis de Red: Analiza el tráfico de red, captura y procesa paquetes para obtener información detallada.



Escáner de Puertos y Vulnerabilidades: Utiliza Nmap para escanear puertos abiertos, detectar versiones de servicios e identificar vulnerabilidades conocidas.



Generador de Paquetes Avanzado: Crea y envía paquetes raw (TCP, UDP, ICMP) con payloads personalizados, incluso generados por IA.



Ataques de Red: Módulos para ataques de fuerza bruta, desautenticación y otros métodos ofensivos.



Defensa: Herramientas para la detección de intrusos (IDS) y análisis de comportamiento de entidades (EBA).



Reportes: Genera reportes detallados en formato PDF con los resultados de las auditorías.



Requerimientos

La aplicación requiere las siguientes dependencias de Python y herramientas externas para funcionar correctamente.



Herramientas Externas

Nmap: Necesario para el escáner de puertos y vulnerabilidades.



Dependencias de Python

Para instalar todas las dependencias de Python, usa el archivo requirements.txt proporcionado:



pip install -r requirements.txt



Estructura del Proyecto

El proyecto está organizado en una estructura modular para facilitar la gestión y la adición de nuevas herramientas:



.

├── core/

│   ├── analyzer.py

│   ├── database\_manager.py

│   └── report\_generator.py

├── modules/

│   ├── offense/

│   │   ├── brute\_force.py

│   │   ├── deauth\_attack.py

│   │   ├── evil\_twin\_mitigator.py

│   │   ├── handshake\_analyzer.py

│   │   ├── packet\_crafter.py

│   │   ├── port\_scanner.py

│   │   ├── service\_brute\_force.py

│   │   └── vulnerability\_scanner.py

│   ├── defense/

│   │   ├── eba.py

│   │   └── ids.py

│   ├── interface\_manager.py

│   ├── network\_mapper.py

│   └── packet\_analyzer.py

├── utils/

│   └── logger.py

├── gui.py

├── LICENSE.md

└── README.md



Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE.md para más detalles.

