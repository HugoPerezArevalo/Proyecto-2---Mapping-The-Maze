# Mapping the Maze · Auditoría de Red (Gadir Logística, S.L.)

- **Autor:** Hugo Pérez
- **Módulo / Unidad:** UD2 · Mapping the Maze (RA3.b)
- **Alcance autorizado:** [`scope.txt`](./scope.txt) (`172.17.0.0/24`)

## Entregables del proyecto

1. **Cuaderno de trabajo y evidencias:** [`cuadernos/hugo-perez.md`](./cuadernos/hugo-perez.md) — Registro cronológico completo de comandos, salidas y análisis desde el inicio de la auditoría.
2. **Inventario de red y auditoría de activos:** [`inventario.md`](./inventario.md) — Mapeo de los 9 equipos vivos (TCP/UDP), enumeración sin credenciales, cuentas descubiertas, limitaciones y correcciones sobre `inventario-cliente.csv`.
3. **Registro de vulnerabilidades priorizado:** [`registro-vulns.md`](./registro-vulns.md) — Caracterización técnica (CVE, CWE, MITRE ATT&CK, evidencias, limitaciones), priorización justificada con CVSS v3.1, EPSS y CISA KEV, descarte de falsos positivos y evaluación de `CVE-2026-123158` (*sshole*).
4. **Informe ejecutivo para el cliente:** [`informe-cliente.md`](./informe-cliente.md) — Resumen para Gerencia de Gadir Logística, S.L., plan de remediación por plazos y respuesta formal sobre la alerta «sshole».
5. **Agente autónomo (`aap-base`) y comparativa:** Parte 5 completada.
   - [`agentes/hugo-perez/informe.md`](./agentes/hugo-perez/informe.md) — Informe **original y sin editar** generado por el agente (`corsario-1`) contra `172.17.0.0/24`. Sus errores se analizan en `comparativa.md`.
   - [`agentes/hugo-perez/trazas/2026-11-25_083939.jsonl`](./agentes/hugo-perez/trazas/2026-11-25_083939.jsonl) — Traza de la enumeración (`inicio`, 35 llamadas a herramientas con su evidencia `E01`–`E35` y `fin`) e [`interrogatorio.jsonl`](./agentes/hugo-perez/trazas/interrogatorio.jsonl) — tres preguntas de verificación y sus respuestas. Los ficheros XML/JSON de evidencia se generaron en el espacio de trabajo de `aap-base` (`salida/ejecuciones/2026-11-25_083939/`).
   - Pruebas manuales del `scope-guard` (dentro/fuera de alcance y casos mal formados), revisión del prompt con `python3 enumerar.py --ver-prompt` y control de gasto (`--max-tokens`, `--max-pasos`): [`cuadernos/hugo-perez.md`](./cuadernos/hugo-perez.md), §8.
   - [`comparativa.md`](./comparativa.md) — Análisis crítico mano vs. agente, taxonomía de fallos y comparativa entre agentes.