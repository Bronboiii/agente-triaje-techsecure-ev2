agente-triaje-techsecure-ev2
TechSecure Solution: Agente RAG Autónomo con Memoria Híbrida y Triaje Adaptativo (EV2)

Este repositorio contiene la implementación del Agente Supervisor de ciberseguridad para la Evaluación Parcial N°2. El sistema automatiza el triaje, priorización y mitigación de alertas de seguridad (CVE).

Arquitectura y Herramientas Autónomas
El agente utiliza el patrón **ReAct (Reason + Action)** para orquestar de manera autónoma las siguientes herramientas:
1. **Asset Lookup Tool:** Examina el inventario local para validar la existencia real del activo afectado.
2. **RAG Retrieval Tool:** Realiza búsquedas de similitud en la base vectorial ChromaDB para extraer playbooks normativos.

Procesos de Memoria Implementados
- **Memoria de Corto Plazo:** Mantiene el estado de la sesión actual y la trazabilidad de los pasos del agente para evitar redundancia.
- **Memoria de Largo Plazo:** Registra un caché histórico de falsos positivos conocidos para resolver alertas repetitivas de forma inmediata.

Guía de Pruebas y Decisiones Adaptativas

### Preparación del entorno:
```bash
pip install -r requirements.txt

## Ejecución de Escenarios de Prueba obligatorios:
Escenario A (Activo Crítico en DMZ): El agente elevará la prioridad a CRÍTICA y exigirá parcheo en < 24 horas de acuerdo a la política.
