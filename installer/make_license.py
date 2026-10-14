"""Genera License.rtf (texto que muestra el instalador). Uso: python make_license.py"""
from pathlib import Path

TEXT = """DEMIURGE - VERSIÓN BETA

Antes de instalar, leé esto:

1. Qué es Demiurge
Demiurge es una herramienta de VISIBILIDAD: revisa tu PC, te muestra qué programas arrancan solos, qué conexiones hace, qué extensiones tiene tu navegador y cómo está configurada, y te explica en lenguaje simple qué es cada cosa y si parece normal.

2. Qué NO es
Demiurge NO es un antivirus y NO reemplaza a tu antivirus. Seguí usando Microsoft Defender u otro antivirus. Demiurge nunca te va a pedir que lo desactives.

3. Es una versión beta
Puede tener errores. Puede marcar como sospechoso algo que es legítimo (falso positivo) o no detectar algo que sí es malicioso. Ninguna herramienta puede garantizar que una PC esté 100% limpia. Usá los resultados como una segunda opinión, no como verdad absoluta.

4. Acciones
Demiurge puede, sólo si vos lo confirmás, deshabilitar programas del arranque, mover archivos a cuarentena o cambiar configuraciones. Todas guardan una copia y se pueden deshacer desde la sección Actividad, salvo finalizar un programa en ejecución. Si no estás seguro de qué es algo, no actúes: buscá ayuda de alguien de confianza.

5. Permisos y privacidad
Demiurge pide permisos de administrador al abrirse para poder revisar toda la PC. No instala servicios ni deja procesos en segundo plano: cuando cerrás la ventana, no queda nada corriendo.
Descarga listas públicas de amenazas y las compara en tu PC. Las consultas en línea (opcionales, se pueden apagar en Ajustes) envían sólo la huella digital (hash) de algunos archivos, nunca los archivos ni tus datos personales.
Los resultados se guardan en C:\\ProgramData\\Demiurge, protegidos para que sólo los administradores puedan leerlos. Desinstalar Demiurge no borra esa carpeta.

6. Sin garantía
Demiurge se ofrece "tal cual", sin garantías de ningún tipo. Quienes lo desarrollan no son responsables por daños derivados de su uso.

Al continuar con la instalación aceptás estas condiciones.
"""


def rtf_escape(s: str) -> str:
    out = []
    for ch in s:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\par\n")
        elif ord(ch) > 127:
            out.append(f"\\u{ord(ch)}?")
        else:
            out.append(ch)
    return "".join(out)


rtf = "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Segoe UI;}}\\fs18\n" + rtf_escape(TEXT) + "}"
Path(__file__).with_name("License.rtf").write_text(rtf, encoding="ascii")
print("ok")
