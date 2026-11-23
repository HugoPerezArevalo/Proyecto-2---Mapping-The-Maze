# Mapping the Maze · Auditoría de Red (Gadir Logística, S.L.)

- **Autor:** Hugo Pérez
- **Módulo / Unidad:** UD2 · Mapping the Maze (RA3.b)
- **Alcance autorizado:** [`scope.txt`](./scope.txt) (`172.17.0.0/24`)

## Entregables del proyecto

1. **Cuaderno de trabajo y evidencias:** [`cuadernos/hugo-perez.md`](./cuadernos/hugo-perez.md) — Registro cronológico completo de comandos, salidas y análisis desde el inicio de la auditoría.
2. **Inventario de red y auditoría de activos:** [`inventario.md`](./inventario.md) — Mapeo de los 9 equipos vivos (TCP/UDP), enumeración sin credenciales, cuentas descubiertas, limitaciones y correcciones sobre `inventario-cliente.csv`.
3. **Registro de vulnerabilidades priorizado:** [`registro-vulns.md`](./registro-vulns.md) — Caracterización técnica (CVE, CWE, MITRE ATT&CK, evidencias, limitaciones), priorización justificada con CVSS v3.1, EPSS y CISA KEV, descarte de falsos positivos y evaluación de `CVE-2026-123158` (*sshole*).
4. **Informe ejecutivo para el cliente:** [`informe-cliente.md`](./informe-cliente.md) — Resumen para Gerencia de Gadir Logística, S.L., plan de remediación por plazos y respuesta formal sobre la alerta «sshole».
5. **Agente autónomo (`aap-base`) y comparativa:** *(Pendiente de ejecución en clase — Parte 5)*
   - [`agente/src/`](./agente/src/) — Herramientas `nmap` y `cve_lookup` integradas con `scope-guard`.
   - [`agente/pruebas.md`](./agente/pruebas.md) — Validación manual del `scope-guard` (IP dentro/fuera de alcance) y revisión del prompt (`--ver-prompt`).
   - [`agente/traza.jsonl`](./agente/traza.jsonl) e [`agente/informe.md`](./agente/informe.md) — Ejecución controlada contra `172.17.0.0/24` e informe generado por el agente.
   - [`comparativa.md`](./comparativa.md) — Análisis crítico mano vs. agente.