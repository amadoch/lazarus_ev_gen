#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
SCRIPT DE AUTOMATIZACIÓN FORENSE ROBUSTA (PYTHON 3) - MATRIZ FORENSE LAZARUS
MODIFICACIÓN: Armando Bustamante
Certificación de Informática Forense - Lazarus Venezuela
Versión Objetivo: Windows 10 Pro (Compilación 19045 - 22H2)
=============================================================================
Descripción:
Este script genera de manera reproducible colmenas binarias del Registro de Windows 
(SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT, USRCLASS.DAT) y archivos de registro 
de eventos (.evtx) válidos y correlacionados para simulaciones de laboratorio de peritaje.
Incluye registro de actividad de la aplicación (logger), manejo de errores, validación de rutas,
y generación aleatoria sintética coherente con la Matriz Forense Lazarus (AmCache, ShimCache,
USBSTOR, ShellBags, UserAssist, BAM/DAM y canales EVTX).

Requisitos de Entorno:
- Ejecutable en Debian GNU/Linux (Python 3.10+) y Windows.
- No requiere dependencias externas pesadas de C, empleando estructuras binarias 
  nativas robustas compatibles con herramientas periciales como hivexsh, RegRipper y evtx_dump.
"""
from simlablazarus import artifact, log, hives, evtx

LAB_ROUTE = "/tmp/lab_forense_lazarus"
HIVES = [
    "SAM",
    "SECURITY",
    "SOFTWARE",
    "SYSTEM",
    "NTUSER.DAT",
    "USRCLASS.DAT"
]
EVTX = [
    "Security.evtx", 
    "System.evtx", 
    "Application.evtx", 
    "Microsoft-Windows-Partition_Diagnostic.evtx", 
    "DriverFrameworks-UserMode.evtx"
]

def main():
    logger = log.setup_log("lab_lazarus")
    artMan = artifact.ArtifactManager()
    
    logger.info("LAZARUS VENEZUELA - GENERADOR ROBUSTO DE EVIDENCIA SINTÉTICA FORENSE")
    
    # 1. Crear laboratorio forense
    artMan.create_directory(LAB_ROUTE)
    
    # 2. Generar registros de eventos sinteticos
    evtx.generar_archivo_evtx("Security.evtx", LAB_ROUTE)
    
    # 3. Generar registros de colmenas sinteticos
    hives.generar_colmena_binaria("SAM", LAB_ROUTE)
    
    logger.info(f"Todos los artefactos forenses han sido desplegados en: {LAB_ROUTE}")
    logger.info("Los datos son dinámicos, aleatorios y se sostienen bajo la Matriz Forense Lazarus")
        
if __name__ == "__main__":
    main()