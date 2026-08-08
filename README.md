# lazarus_ev_gen v0.0.1

---

Generador de evidencia sintetica. Practica de Lazarus
Author: Armando bustamante
Disclaimer: El uso responsable de esta herramienta es responsabilidad exclusiva del usuario.

---

SCRIPT DE AUTOMATIZACIÓN FORENSE ROBUSTA (PYTHON 3) - MATRIZ FORENSE LAZARUS
MODIFICACIÓN: Armando Bustamante
Certificación de Informática Forense - Lazarus Venezuela
Versión Objetivo: Windows 10 Pro (Compilación 19045 - 22H2)

Descripción:
Este script genera de manera reproducible colmenas binarias del Registro de Windows
(SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT, USRCLASS.DAT) y archivos de registro
de eventos (.evtx) válidos y correlacionados para simulaciones de laboratorio de peritaje.

Incluye registro de actividad de la aplicación (logger), manejo de errores, validación de rutas,
y generación aleatoria sintética coherente con la Matriz Forense Lazarus (AmCache, ShimCache,
USBSTOR, ShellBags, UserAssist, BAM/DAM y canales EVTX).

Requisitos de Entorno:

- Ejecutable en Debian GNU/Linux (Python 3.10+) y Windows.
- Dependencias: xml2evtx, regipy
- Puede Emplear estructuras binarias nativas robustas compatibles con herramientas periciales como hivexsh, RegRipper y evtx_dump.

## Aviso legal y descargo de responsabilidad

Este proyecto tiene fines exclusivamente educativos y de investigación académica dentro del contexto del curso de Informática Forense - Grupo Lazarus Venezuela.
El autor y los colaboradores de ForensicSuite no se hacen responsables del uso indebido, malas prácticas, daños directos o indirectos, pérdida de información o consecuencias legales derivadas de la utilización de esta herramienta.

### Uso permitido

- Prácticas de laboratorio forense en entornos controlados.
- Análisis de equipos, discos o memorias sobre los que se cuente con autorización expresa.
- Formación académica en informática forense, ciberseguridad y auditoría de sistemas.

### Uso prohibido

- Acceder, examinar o extraer información de dispositivos sin autorización del titular.
- Utilizar la herramienta para ocultar, alterar, destruir o manipular evidencia digital.
- Cualquier actividad que vulnere la legislación vigente, incluyendo la Ley Especial contra Delitos Informáticos de Venezuela y el Código Orgánico Procesal Penal.

## Dependencias

### xml2evtx

---

Author: JPCERTCC
Contact: [info@jpcert.or.jp](info@jpcert.or.jp)
[Repositorio de github](https://github.com/JPCERTCC/xml2evtx/tree/main)

---
