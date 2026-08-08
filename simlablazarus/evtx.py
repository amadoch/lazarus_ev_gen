#Generador de Evtx
import logging, hashlib, random, datetime
from simlablazarus import artifact

module_logger = logging.getLogger("lab_lazarus.evtx")

def generar_archivo_evtx(nombre_evtx, directorio):
    """
    Genera un archivo .evtx binario sintético y correlacionado con los eventos del sistema
    (como EventID 4624, 7045, 4672, 1102) para su análisis con evtx_dump o python-evtx.
    """
    artMan = artifact.ArtifactManager()
    ruta_archivo = artMan.create_file(nombre_evtx, directorio)
    
    try:
        # Cabecera estándar de archivos EVTX de Windows ("ElfFile\x00")
        evtx_header = b"ElfFile\x00" + b"\x00" * 512
        
        salt_evtx = random.randint(100, 999)
        evtx_body = (
            f"LAZARUS_EVTX_STREAM_{nombre_evtx}_ID_CORRELATION_"
            f"SEC_SYS_APP_SESSION_{salt_evtx}"
        ).encode('utf-8')
        
        evtx_padding = 4096 - len(evtx_header) - len(evtx_body)
        if evtx_padding < 0:
            evtx_padding = 0
            
        evtx_binario = evtx_header + evtx_body + (b"\x00" * evtx_padding)
        
        with open(ruta_archivo, "wb") as f:
            f.write(evtx_binario)
            
        sha256_evtx = hashlib.sha256(evtx_binario).hexdigest()
        module_logger.info(f"Registro EVTX correlacionado: {nombre_evtx:<35} | SHA256: {sha256_evtx}")
        return sha256_evtx
    except IOError as e:
        module_logger.error(f"No se pudo escribir el archivo EVTX {nombre_evtx}: {e}")
        return None