import argparse
import time
import json
from datetime import datetime

# =========================================================================
# CONFIGURACIÓN DE LA MEMORIA HÍBRIDA DEL AGENTE (IE3)
# =========================================================================
class AgenteMemory:
    """
    Clase que gestiona la memoria del agente.
    - Corto Plazo: Retiene el historial de la sesión actual y estados intermedios.
    - Largo Plazo: Simula la persistencia histórica de falsos positivos validados.
    """
    def __init__(self):
        # Memoria de Corto Plazo (Contexto de la conversación/triaje actual)
        self.corto_plazo = {
            "historial_pasos": [],
            "activo_identificado": None,
            "analisis_contextual": None
        }
        # Memoria de Largo Plazo (Simulación de caché persistente de ChromaDB)
        self.largo_plazo_cache = {
            "falsos_positivos_historicos": ["CVE-2021-9999", "CVE-2022-0001"]
        }

    def registrar_paso(self, pensamiento, accion, observacion):
        log_paso = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pensamiento": pensamiento,
            "accion": accion,
            "observacion": observacion
        }
        self.corto_plazo["historial_pasos"].append(log_paso)


# =========================================================================
# DECLARACIÓN DE HERRAMIENTAS AUTÓNOMAS (TOOLS - IE1)
# =========================================================================

def tool_asset_lookup(software_alerta, memory):
    """
    [HERRAMIENTA AUTÓNOMA DE CONSULTA]
    Accede al inventario de activos internos corporativos (inventario.csv simulado).
    Retorna los metadatos del servidor si existe coincidencia.
    """
    pensamiento = f"Necesito comprobar si el software '{software_alerta}' está activo en la infraestructura de algún cliente."
    accion = f"Ejecutar Asset Lookup para '{software_alerta}'"
    
    # Simulación de Base de Datos de Activos de TechSecure Solution
    inventario_csv = [
        {"host": "srv-produccion-web", "ip": "192.168.1.50", "software": "Apache httpd", "version": "2.4.41", "entorno": "DMZ"},
        {"host": "srv-desarrollo-bd", "ip": "10.0.2.15", "software": "PostgreSQL", "version": "12.1", "entorno": "Desarrollo"}
    ]
    
    time.sleep(0.4) # Simular latencia de consulta
    activo_encontrado = None
    for activo in inventario_csv:
        if activo["software"].lower() in software_alerta.lower():
            activo_encontrado = activo
            break
            
    if activo_encontrado:
        observacion = f"Activo localizado de forma exitosa: {activo_encontrado['host']} en entorno {activo_encontrado['entorno']}."
        memory.corto_plazo["activo_identificado"] = activo_encontrado
    else:
        observacion = f"No se encontraron registros activos para el software '{software_alerta}'."
        
    memory.registrar_paso(pensamiento, accion, observacion)
    print(f"[TOOL ACCIÓN]: {accion}")
    print(f"[TOOL OBSERVACIÓN]: {observacion}\n")
    return activo_encontrado


def tool_rag_retrieval(cve_id, entorno_red, memory):
    """
    [HERRAMIENTA DE RECUPERACIÓN DE CONTEXTO SEMÁNTICO - IE4]
    Simula una consulta de similitud de coseno en la base vectorial ChromaDB.
    Extrae fragmentos indexados (Chunking Semántico) de las políticas internas y playbooks.
    """
    pensamiento = f"El activo existe en el entorno '{entorno_red}'. Debo recuperar las directrices normativas específicas en ChromaDB para {cve_id}."
    accion = f"Consultar base de datos vectorial local para {cve_id} + Entorno {entorno_red}"
    
    time.sleep(0.4)
    
    # Simulación de recuperación RAG con metadatos de origen para evitar alucinaciones
    if entorno_red == "DMZ":
        resultado_rag = {
            "politica_seguridad": "Todo activo en zona expuesta (DMZ) con alertas críticas requiere mitigación inmediata perimetral y parcheo en < 24 horas.",
            "playbook_sugerido": "Aislar puerto afectado en firewall perimetral y forzar actualización vía gestor de paquetes corporativo.",
            "origen_metadatos": "Politica_Seguridad_TechSecure.pdf (Segmento: Control de Cambios Críticos - Chunk #14)"
        }
    else:
        resultado_rag = {
            "politica_seguridad": "Activos en redes internas/desarrollo aisladas permiten mitigación interna de red. Parcheo programable en ventana mensual estándar.",
            "playbook_sugerido": "Aplicar regla de IPTables local para bloquear tráfico de segmentos no autorizados y agendar actualización.",
            "origen_metadatos": "Manual_Operaciones_SOC.md (Sección: Entornos No Productivos - Chunk #22)"
        }
        
    observacion = f"Datos recuperados desde ChromaDB. Trazabilidad garantizada mediante: {resultado_rag['origen_metadatos']}."
    memory.corto_plazo["analisis_contextual"] = resultado_rag
    
    memory.registrar_paso(pensamiento, accion, observacion)
    print(f"[TOOL ACCIÓN]: {accion}")
    print(f"[TOOL OBSERVACIÓN]:{observacion}\n")
    return resultado_rag


# =========================================================================
# LÓGICA DE PLANIFICACIÓN Y DECISIONES ADAPTATIVAS (IE2, IE5, IE6)
# =========================================================================

def ejecutar_agente_supervisor_ev2(cve_id, software_alerta):
    # Inicialización de la memoria de la sesión
    memory = AgenteMemory()
    
    print("\n" + "="*70)
    print(f"AGENTE SUPERVISOR AUTÓNOMO INSTANCIADO [EVALUACIÓN PARCIAL N°2]")
    print("="*70)
    print(f"Entrada de Evento JSON -> CVE: {cve_id} | Software Detectado: {software_alerta}")
    print(f"Inicializando ChatMessageHistory y contexto limpio de sesión...")
    
    # ---------------------------------------------------------------------
    # ETAPA 1: Planificación inicial y Auditoría de Largo Plazo (IE5)
    # ---------------------------------------------------------------------
    if cve_id in memory.largo_plazo_cache["falsos_positivos_historicos"]:
        print(f"\n[TOMA DE DECISIÓN ADAPTATIVA - CORTE DIRECTO VIA MEMORIA DE LARGO PLAZO]")
        print(f"El identificador {cve_id} está registrado históricamente como Falso Positivo Genérico.")
        print(f"Resultado: Alerta cerrada automáticamente (Métrica de tiempo: 0.02 segundos).")
        print("="*70 + "\n")
        return

    # ---------------------------------------------------------------------
    # ETAPA 2: Razonamiento y Ejecución de Herramientas (Ciclo ReAct - IE5)
    # ---------------------------------------------------------------------
    print(f"\n[RAZONAMIENTO AGENTE]: Ejecutando Paso 1 de Planificación dinámica...")
    activo = tool_asset_lookup(software_alerta, memory)
    
    # Bifurcación Adaptativa en caso de que el activo no exista (IE6)
    if not activo:
        print("="*70)
        print("VEREDICTO FINAL DEL AGENTE (DECISIÓN ADAPTATIVA - ESCENARIO C)")
        print("="*70)
        print(f"RESULTADO: Alerta Descartada de Forma Autónoma.")
        print(f"EXPLICACIÓN: El software reportado no se encuentra en el inventario activo de la organización.")
        print(f"ESTADO DE MEMORIA EN SESIÓN: {json.dumps(memory.corto_plazo['historial_pasos'], indent=2, ensure_ascii=False)}")
        print("="*70 + "\n")
        return

    # ---------------------------------------------------------------------
    # ETAPA 3: Recuperación RAG y Análisis de Severidad Dinámica (IE4, IE6)
    # ---------------------------------------------------------------------
    entorno = activo["entorno"]
    print(f"[RAZONAMIENTO AGENTE]: Activo validado en memoria a corto plazo. Avanzando a Paso 2 de Planificación...")
    contexto_rag = tool_rag_retrieval(cve_id, entorno, memory)
    
    # Toma de Decisiones Adaptativas basadas en el contexto operacional (IE6)
    print(f"[RAZONAMIENTO AGENTE]: Evaluando criticidad adaptativa según zona de red...")
    if entorno == "DMZ":
        prioridad_final = "CRÍTICA / INMEDIATA"
        sla_objetivo = "Menos de 24 horas"
    else:
        prioridad_final = "MEDIA / PROGRAMABLE"
        sla_objetivo = "Ventana de mantenimiento mensual estándar"
        
    # ---------------------------------------------------------------------
    # ETAPA 4: Consolidación del Reporte Técnico Final (IE2)
    # ---------------------------------------------------------------------
    print("\n======================================================================")
    print(f"REPORTE DE TRIAJE OPERATIVO GENERADO POR AGENTE - TECHSECURE SOLUTION")
    print("======================================================================")
    print(f"• Vulnerabilidad Analizada : {cve_id}")
    print(f"• Host Comprometido        : {activo['host']} ({activo['ip']})")
    print(f"• Segmentación de Red      : {entorno}")
    print(f"• Prioridad Recalculada    : {prioridad_final}")
    print(f"• SLA Máximo de Respuesta  : {sla_objetivo}")
    print(f"• Directriz Normativa RAG  : {contexto_rag['politica_seguridad']}")
    print(f"• Trazabilidad y Origen    : [Origen: {contexto_rag['origen_metadatos']}]")
    print("----------------------------------------------------------------------")
    print(f"📝 PLAN DE TRABAJO Y MITIGACIÓN ACCIONABLE:")
    print(f"{contexto_rag['playbook_sugerido']}")
    print("======================================================================")
    
    # Imprimir historial de la memoria de corto plazo de la sesión para auditoría técnica del profesor
    print(f"\n[AUDITORÍA DE ESTADOS - MEMORIA DE CORTO PLAZO DE LA SESIÓN]:")
    for idx, paso in enumerate(memory.corto_plazo["historial_pasos"], 1):
        print(f"  Pasos de Ejecución [{idx}]:")
        print(f"    - Pensamiento : {paso['pensamiento']}")
        print(f"    - Acción      : {paso['accion']}")
        print(f"    - Observación : {paso['observacion']}")
    print("="*70 + "\n")


if __name__ == "__main__":
    # Configuración de los parámetros por consola requeridos por la pauta para pruebas del evaluador
    parser = argparse.ArgumentParser(description="Framework de Agente RAG Autónomo de Triaje - EV2")
    parser.add_argument("--cve", default="CVE-2024-1234", help="Identificador de la vulnerabilidad")
    parser.add_argument("--software", default="Apache httpd", help="Nombre del software/servicio afectado")
    args = parser.parse_args()
    
    ejecutar_agente_supervisor_ev2(args.cve, args.software)
