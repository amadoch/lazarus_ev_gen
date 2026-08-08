from pathlib import Path
import logging

module_logger = logging.getLogger("lab_lazarus.utils")

class ArtifactManager:
    def __init__(self):
        self.logger = logging.getLogger("lab_lazarus.utils.ArtifactManager")
    
    def create_directory(self, route: str):        
        try:
            route_obj = Path(route)
            route_obj.mkdir(exist_ok=True)
            self.logger.info(f"Directorio creado: {route_obj}")
        except ValueError:
            self.logger.error("Parametros no proporcionados")
            raise
        except PermissionError:
            self.logger.error("Usuario no cuenta con permisos suficientes")
            raise
        except OSError as e:
            self.logger.error(f"Fallo de E/S, no se ha podido crear directorio\n {e}")
            raise

    def create_file(self, filename: str, route: str):
        try:
            route_obj = Path(route) / filename
            if not route_obj.exists():
                route_obj.touch()
            
            self.logger.info(f"Archivo Creado: {route_obj}")
            return route_obj
        except ValueError:
            self.logger.error("Parametros no proporcionados")
            raise
        except PermissionError:
            self.logger.error("Usuario no cuenta con permisos suficientes")
            raise
        except OSError as e:
            self.logger.error(f"Fallo de E/S, no se ha podido crear directorio\n {e}")
            raise
