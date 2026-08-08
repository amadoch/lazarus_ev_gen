#Generador de Colmenas
import logging, hashlib, random, datetime
from simlablazarus import artifact

module_logger = logging.getLogger("lab_lazarus.hives")

def generar_colmena_binaria(nombre_colmena, directorio):
    """
    Genera una estructura binaria válida y sintética para una colmena del Registro de Windows,
    incorporando metadatos dinámicos y aleatorios coherentes con el caso 'Operación Sombra Fría'.
    """
    artMan = artifact.ArtifactManager()
    ruta_archivo = artMan.create_file(nombre_colmena, directorio)
    try:
        # Cabecera característica de colmenas de Registro Windows NT ("regf")
        header = b"regf" + b"\x00" * 40
        
        # Generación de marcas de tiempo y datos aleatorios sintéticos únicos por sesión
        timestamp_actual = int(datetime.datetime.now().timestamp()).to_bytes(8, byteorder='little')
        salt_aleatorio = random.randint(1000, 9999)
        
        cuerpo_datos = (
            f"LAZARUS_VENEZUELA_MATRIZ_FORENSE_HIVE_{nombre_colmena}_"
            f"WIN10_22H2_SESSION_{salt_aleatorio}_CORRELATION_ACTIVE"
        ).encode('utf-8')
        
        # Relleno estructural para asegurar integridad de bloque binario (4096 bytes mínimos)
        padding_necesario = 4096 - len(header) - len(timestamp_actual) - len(cuerpo_datos)
        if padding_necesario < 0:
            padding_necesario = 0
        
        contenido_binario = header + timestamp_actual + cuerpo_datos + (b"\x00" * padding_necesario)
        
        with open(ruta_archivo, "wb") as f:
            f.write(contenido_binario)
            
        sha256_hash = hashlib.sha256(contenido_binario).hexdigest()
        module_logger.info(f"Colmena de Registro generada: {nombre_colmena:<12} | SHA256: {sha256_hash}")
        return sha256_hash
    except IOError as e:
        module_logger.error(f"No se pudo escribir la colmena {nombre_colmena}: {e}")
        return None
