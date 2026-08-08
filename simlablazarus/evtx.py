#Generador de Evtx
import logging

from xml2evtx import create_evtx, process_xml_file

from simlablazarus import artifact

module_logger = logging.getLogger("lab_lazarus.evtx")

def generar_archivo_evtx(xml_file, nombre_evtx, directorio):
    """
    Genera un archivo .evtx binario sintético y correlacionado con los eventos del sistema
    (como EventID 4624, 7045, 4672, 1102) para su análisis con evtx_dump o python-evtx.
    """
    artMan = artifact.ArtifactManager()

    # Procesa xml y convierte datos evtx
    total_event_count, total_chunk_count, evtx_chunk = process_xml_file(xml_file)

    # Crea los datos de archivo evtx
    evtx_data = create_evtx(evtx_chunk, total_event_count, total_chunk_count)

    ruta_archivo = artMan.create_file(nombre_evtx, directorio)

    with ruta_archivo.open("wb", encoding="utf-8") as f:
        f.write(evtx_data)

    