# -*- coding: utf-8 -*-
import customtkinter as ctk
import threading
import logging
import json
import base64
import time
import os

# Importar los módulos de seguridad
from modules.offense.packet_crafter import PacketCrafter
from modules.offense.port_scanner import PortScanner
from modules.offense.service_brute_force import ServiceBruteForce
from modules.offense.vulnerability_scanner import VulnerabilityScanner
from modules.offense.deauth_attack import DeauthAttack
from modules.offense.evil_twin_mitigator import EvilTwinMitigator
from modules.offense.brute_force import BruteForce
from modules.offense.handshake_analyzer import HandshakeAnalyzer
from modules.packet_analyzer import PacketAnalyzer
from modules.network_mapper import NetworkMapper
from modules.interface_manager import InterfaceManager
from modules.defense.ids import IDS
from modules.defense.eba import EBA
from core.database_manager import DatabaseManager
from core.report_generator import ReportGenerator

# Configuración del logger para mostrar mensajes en la GUI
class GUILogger(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.insert(ctk.END, msg + "\n")
        self.text_widget.see(ctk.END)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WIFI Analyzer - Herramienta de Ciberseguridad")
        self.geometry("1024x768")

        # Configurar el grid principal
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Variables de la aplicación
        self.current_tab = "Herramientas"

        # Crear los frames
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.main_content_frame = ctk.CTkFrame(self, corner_radius=0)
        self.main_content_frame.grid(row=0, column=1, sticky="nsew")

        # Configurar el sidebar
        self.sidebar_frame.grid_rowconfigure(7, weight=1)
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="WIFI Analyzer", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Botones de navegación
        self.tools_button = ctk.CTkButton(self.sidebar_frame, text="Herramientas", command=lambda: self.show_page("Herramientas"))
        self.tools_button.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.mapping_pentest_button = ctk.CTkButton(self.sidebar_frame, text="Mapeo y Pentest", command=lambda: self.show_page("Mapeo y Pentest"))
        self.mapping_pentest_button.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.offense_button = ctk.CTkButton(self.sidebar_frame, text="Ataque", command=lambda: self.show_page("Ataque"))
        self.offense_button.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        self.defense_button = ctk.CTkButton(self.sidebar_frame, text="Defensa", command=lambda: self.show_page("Defensa"))
        self.defense_button.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

        self.reports_button = ctk.CTkButton(self.sidebar_frame, text="Reportes", command=lambda: self.show_page("Reportes"))
        self.reports_button.grid(row=5, column=0, padx=20, pady=10, sticky="ew")

        # Frame para el logger
        self.logger_frame = ctk.CTkFrame(self.main_content_frame, corner_radius=0)
        self.logger_frame.pack(side=ctk.BOTTOM, fill=ctk.BOTH, expand=True, padx=10, pady=10)
        self.logger_label = ctk.CTkLabel(self.logger_frame, text="Registro de Eventos")
        self.logger_label.pack(pady=(10, 0))
        self.logger_text = ctk.CTkTextbox(self.logger_frame, corner_radius=10)
        self.logger_text.pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)

        # Instanciar los módulos
        self.packet_crafter = PacketCrafter()
        self.port_scanner = PortScanner()
        self.service_brute_force = ServiceBruteForce()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.deauth_attack = DeauthAttack()
        self.evil_twin_mitigator = EvilTwinMitigator()
        self.brute_force = BruteForce()
        self.handshake_analyzer = HandshakeAnalyzer()
        self.packet_analyzer = PacketAnalyzer()
        self.network_mapper = NetworkMapper()
        self.interface_manager = InterfaceManager()
        self.ids = IDS()
        self.eba = EBA()
        self.database_manager = DatabaseManager()
        self.report_generator = ReportGenerator()
        
        # Configurar el logger
        self.gui_logger_handler = GUILogger(self.logger_text)
        logging.getLogger().addHandler(self.gui_logger_handler)
        logging.getLogger().setLevel(logging.INFO)
        
        # Crear los frames de las páginas
        self.pages = {}
        self.create_tools_page()
        self.create_mapping_pentest_page()
        self.create_offense_page()
        self.create_defense_page()
        self.create_reports_page()

        self.show_page("Herramientas")

    def show_page(self, page_name):
        for page in self.pages.values():
            page.pack_forget()
        
        if page_name in self.pages:
            self.pages[page_name].pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)
            self.current_tab = page_name

    def create_tools_page(self):
        page = ctk.CTkFrame(self.main_content_frame)
        self.pages["Herramientas"] = page

        # Frame para la gestión de la interfaz
        interface_frame = ctk.CTkFrame(page)
        interface_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(interface_frame, text="Gestión de Interfaz", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.interface_entry = ctk.CTkEntry(interface_frame, placeholder_text="Nombre de la interfaz (ej. wlan0)")
        self.interface_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(interface_frame, text="Configurar Modo Monitor", command=lambda: threading.Thread(target=self.interface_manager.set_monitor_mode, args=(self.interface_entry.get(),)).start()).pack(pady=5, padx=10)
        ctk.CTkButton(interface_frame, text="Restaurar Modo Gestionado", command=lambda: threading.Thread(target=self.interface_manager.set_managed_mode, args=(self.interface_entry.get(),)).start()).pack(pady=5, padx=10)
        
        # Frame para el generador de paquetes
        packet_crafter_frame = ctk.CTkFrame(page)
        packet_crafter_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(packet_crafter_frame, text="Generador de Paquetes", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.ip_entry = ctk.CTkEntry(packet_crafter_frame, placeholder_text="IP del Destino")
        self.ip_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.port_entry = ctk.CTkEntry(packet_crafter_frame, placeholder_text="Puerto del Destino")
        self.port_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.message_entry = ctk.CTkEntry(packet_crafter_frame, placeholder_text="Mensaje del Payload")
        self.message_entry.pack(pady=5, padx=10, fill=ctk.X)
        
        ctk.CTkButton(packet_crafter_frame, text="Enviar Paquete TCP", command=lambda: threading.Thread(target=self.packet_crafter.send_tcp_packet, args=(self.ip_entry.get(), int(self.port_entry.get()), self.message_entry.get(),)).start()).pack(pady=5, padx=10)
        ctk.CTkButton(packet_crafter_frame, text="Enviar Paquete UDP", command=lambda: threading.Thread(target=self.packet_crafter.send_udp_packet, args=(self.ip_entry.get(), int(self.port_entry.get()), self.message_entry.get(),)).start()).pack(pady=5, padx=10)
        ctk.CTkButton(packet_crafter_frame, text="Enviar Paquete ICMP (Ping)", command=lambda: threading.Thread(target=self.packet_crafter.send_icmp_packet, args=(self.ip_entry.get(),)).start()).pack(pady=5, padx=10)
        
        # Frame para la generación de paquetes con IA
        ai_crafter_frame = ctk.CTkFrame(page)
        ai_crafter_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(ai_crafter_frame, text="Generación de Paquetes con IA", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.ai_prompt_entry = ctk.CTkEntry(ai_crafter_frame, placeholder_text="Instrucción para el payload de IA (ej. 'Generar payload para overflow de buffer')", height=50)
        self.ai_prompt_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(ai_crafter_frame, text="Generar y Enviar Payload con IA", command=self.send_ai_packet).pack(pady=5, padx=10)

        # Frame para el analizador de handshake
        handshake_frame = ctk.CTkFrame(page)
        handshake_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(handshake_frame, text="Análisis de Handshake de WiFi", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.handshake_file_entry = ctk.CTkEntry(handshake_frame, placeholder_text="Ruta del archivo .pcap")
        self.handshake_file_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(handshake_frame, text="Analizar Handshake", command=lambda: threading.Thread(target=self.handshake_analyzer.analyze_handshake, args=(self.handshake_file_entry.get(),)).start()).pack(pady=5, padx=10)


    def create_mapping_pentest_page(self):
        page = ctk.CTkFrame(self.main_content_frame)
        self.pages["Mapeo y Pentest"] = page
        
        # Frame para el mapeo de red
        mapping_frame = ctk.CTkFrame(page)
        mapping_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(mapping_frame, text="Mapeo de Red", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.mapping_interface_entry = ctk.CTkEntry(mapping_frame, placeholder_text="Interfaz (ej. wlan0mon)")
        self.mapping_interface_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(mapping_frame, text="Mapear Red", command=lambda: threading.Thread(target=self.network_mapper.map_network, args=(self.mapping_interface_entry.get(),)).start()).pack(pady=5, padx=10)
        
        # Frame para el escáner de puertos
        port_scanner_frame = ctk.CTkFrame(page)
        port_scanner_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(port_scanner_frame, text="Escáner de Puertos", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.port_scanner_ip_entry = ctk.CTkEntry(port_scanner_frame, placeholder_text="IP del Host")
        self.port_scanner_ip_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.port_scanner_range_entry = ctk.CTkEntry(port_scanner_frame, placeholder_text="Rango de Puertos (ej. 1-100)")
        self.port_scanner_range_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(port_scanner_frame, text="Escanear Puertos", command=lambda: threading.Thread(target=self.port_scanner.scan_ports, args=(self.port_scanner_ip_entry.get(), self.port_scanner_range_entry.get(),)).start()).pack(pady=5, padx=10)

        # Frame para el escáner de vulnerabilidades
        vuln_scanner_frame = ctk.CTkFrame(page)
        vuln_scanner_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(vuln_scanner_frame, text="Escáner de Vulnerabilidades (Nmap)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.vuln_scanner_ip_entry = ctk.CTkEntry(vuln_scanner_frame, placeholder_text="IP del Host")
        self.vuln_scanner_ip_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.vuln_scanner_range_entry = ctk.CTkEntry(vuln_scanner_frame, placeholder_text="Rango de Puertos (ej. 1-100)")
        self.vuln_scanner_range_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(vuln_scanner_frame, text="Escanear Vulnerabilidades", command=lambda: threading.Thread(target=self.vulnerability_scanner.scan_vulnerabilities, args=(self.vuln_scanner_ip_entry.get(), self.vuln_scanner_range_entry.get(),)).start()).pack(pady=5, padx=10)

    def create_offense_page(self):
        page = ctk.CTkFrame(self.main_content_frame)
        self.pages["Ataque"] = page
        
        # Frame para la fuerza bruta de servicio
        service_brute_force_frame = ctk.CTkFrame(page)
        service_brute_force_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(service_brute_force_frame, text="Ataque de Fuerza Bruta de Servicio", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.sbf_ip_entry = ctk.CTkEntry(service_brute_force_frame, placeholder_text="IP del Host")
        self.sbf_ip_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.sbf_port_entry = ctk.CTkEntry(service_brute_force_frame, placeholder_text="Puerto")
        self.sbf_port_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.sbf_wordlist_entry = ctk.CTkEntry(service_brute_force_frame, placeholder_text="Ruta del diccionario")
        self.sbf_wordlist_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(service_brute_force_frame, text="Atacar Servicio", command=lambda: threading.Thread(target=self.service_brute_force.run_attack, args=(self.sbf_ip_entry.get(), self.sbf_port_entry.get(), self.sbf_wordlist_entry.get(),)).start()).pack(pady=5, padx=10)
        
        # Frame para el ataque de desautenticación
        deauth_frame = ctk.CTkFrame(page)
        deauth_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(deauth_frame, text="Ataque de Desautenticación", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.deauth_iface_entry = ctk.CTkEntry(deauth_frame, placeholder_text="Interfaz (ej. wlan0mon)")
        self.deauth_iface_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.deauth_target_mac_entry = ctk.CTkEntry(deauth_frame, placeholder_text="MAC del Objetivo")
        self.deauth_target_mac_entry.pack(pady=5, padx=10, fill=ctk.X)
        self.deauth_ap_mac_entry = ctk.CTkEntry(deauth_frame, placeholder_text="MAC del AP")
        self.deauth_ap_mac_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(deauth_frame, text="Lanzar Ataque", command=lambda: threading.Thread(target=self.deauth_attack.run_attack, args=(self.deauth_iface_entry.get(), self.deauth_target_mac_entry.get(), self.deauth_ap_mac_entry.get(),)).start()).pack(pady=5, padx=10)

    def create_defense_page(self):
        page = ctk.CTkFrame(self.main_content_frame)
        self.pages["Defensa"] = page

        # Frame para el IDS
        ids_frame = ctk.CTkFrame(page)
        ids_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(ids_frame, text="Sistema de Detección de Intrusos (IDS)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.ids_iface_entry = ctk.CTkEntry(ids_frame, placeholder_text="Interfaz (ej. wlan0mon)")
        self.ids_iface_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(ids_frame, text="Iniciar Detección", command=lambda: threading.Thread(target=self.ids.start_detection, args=(self.ids_iface_entry.get(),)).start()).pack(pady=5, padx=10)
        
        # Frame para el EBA
        eba_frame = ctk.CTkFrame(page)
        eba_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(eba_frame, text="Análisis de Comportamiento de Entidades (EBA)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.eba_iface_entry = ctk.CTkEntry(eba_frame, placeholder_text="Interfaz (ej. wlan0mon)")
        self.eba_iface_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(eba_frame, text="Iniciar EBA", command=lambda: threading.Thread(target=self.eba.start_analysis, args=(self.eba_iface_entry.get(),)).start()).pack(pady=5, padx=10)

    def create_reports_page(self):
        page = ctk.CTkFrame(self.main_content_frame)
        self.pages["Reportes"] = page
        
        # Frame para los reportes
        reports_frame = ctk.CTkFrame(page)
        reports_frame.pack(fill=ctk.X, padx=10, pady=10)
        ctk.CTkLabel(reports_frame, text="Generador de Reportes", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.report_file_entry = ctk.CTkEntry(reports_frame, placeholder_text="Nombre del archivo de reporte (ej. mi_auditoria.pdf)")
        self.report_file_entry.pack(pady=5, padx=10, fill=ctk.X)
        ctk.CTkButton(reports_frame, text="Generar Reporte", command=lambda: threading.Thread(target=self.generate_report_from_db, args=(self.report_file_entry.get(),)).start()).pack(pady=5, padx=10)

    def generate_report_from_db(self, filename):
        # La generación de datos ahora es gestionada por el DatabaseManager
        data = self.database_manager.get_all_data()
        self.report_generator.generate_pdf_report(filename, data)
        logging.info(f"Reporte generado: {filename}")
        
    def send_ai_packet(self):
        # Maneja la llamada a la IA de forma asíncrona para no bloquear la GUI
        prompt = self.ai_prompt_entry.get()
        if not prompt:
            logging.warning("Por favor, ingresa una instrucción para la IA.")
            return

        logging.info(f"Generando payload con IA para la instrucción: '{prompt}'...")
        
        def run_ai_and_send():
            try:
                payload = self._generate_payload_with_ai(prompt)
                if payload:
                    logging.info("Payload generado por la IA. Enviando paquete...")
                    target_ip = self.ip_entry.get()
                    target_port = int(self.port_entry.get()) if self.port_entry.get() else 80
                    self.packet_crafter.send_tcp_packet(target_ip, target_port, payload)
            except Exception as e:
                logging.error(f"Error en el proceso de IA y envío: {e}")

        threading.Thread(target=run_ai_and_send).start()

    def _generate_payload_with_ai(self, prompt):
        # Esta función está configurada para recibir el payload de una llamada API externa.
        # La lógica de la llamada API y la respuesta se gestiona en la plataforma.
        api_payload = {
            "contents": [
                {
                    "parts": [
                        {"text": "Genera un payload técnico para un paquete de red basado en la siguiente instrucción. No incluyas explicaciones, solo el payload puro y crudo. La instrucción es: " + prompt}
                    ]
                }
            ],
            "tools": [{"google_search": {}}],
            "systemInstruction": {
                "parts": [
                    {"text": "Actúa como un experto en ciberseguridad. Genera un payload de red con fines de prueba de penetración."}
                ]
            }
        }
        
        return None
        
if __name__ == "__main__":
    app = App()
    app.mainloop()
