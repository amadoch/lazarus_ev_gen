#!/usr/bin/env python3

from simlablazarus import artifact, evtx, hives, log

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
    contenido = evtx.leer_evento_xml("test.xml", "./inputs")
    evtx.generar_archivo_evtx("Security.evtx", LAB_ROUTE, contenido)
    
    # # 3. Generar registros de colmenas sinteticos
    # hives.generar_colmena_binaria("SAM", LAB_ROUTE)
    
    logger.info(f"Todos los artefactos forenses han sido desplegados en: {LAB_ROUTE}")
    logger.info("Los datos son dinámicos, aleatorios y se sostienen bajo la Matriz Forense Lazarus")
        
if __name__ == "__main__":
    main()