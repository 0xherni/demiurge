// Glosario: palabras técnicas que aparecen en las explicaciones, con una definición para alguien que no sabe de
// computadoras. Se muestran al pasar el mouse (o con Tab) sobre la palabra subrayada.

export interface GlossaryEntry { terms: string[]; def: string }

export const GLOSSARY: GlossaryEntry[] = [
  { terms: ["firma digital", "firmado", "firmada", "sin firma", "firma"], def: "Un sello que pone la empresa que hizo el programa. Garantiza quién lo hizo y que nadie lo modificó. Casi todo el software serio viene firmado; el malware casi nunca." },
  { terms: ["proceso", "procesos"], def: "Un programa que está abierto y funcionando en este momento, aunque no tenga ventana." },
  { terms: ["arranque", "arranca solo", "arrancar solo", "arranque automático"], def: "Lugares donde Windows anota qué programas abrir solos al prender la PC. El malware se anota ahí para volver después de cada reinicio." },
  { terms: ["AppData"], def: "Una carpeta oculta dentro de tu usuario donde los programas guardan sus datos. Algunos programas legítimos se instalan ahí, y el malware también, porque no necesita permisos." },
  { terms: ["Temp", "carpeta temporal"], def: "Carpeta de archivos temporales. Los instaladores la usan y se borra sola; un programa que corre desde ahí y sigue activo es raro." },
  { terms: ["registro de Windows"], def: "La base de datos interna donde Windows y los programas guardan su configuración." },
  { terms: ["servicio", "servicios"], def: "Un programa que Windows mantiene funcionando en segundo plano, sin ventana, desde que prende la PC." },
  { terms: ["tarea programada", "tareas programadas"], def: "Una orden para que Windows abra un programa en cierto momento (al iniciar, cada hora, etc.)." },
  { terms: ["extensión", "extensiones"], def: "Un agregado del navegador. Puede ver y cambiar las páginas que visitás, por eso las malas pueden robar datos o meter publicidad." },
  { terms: ["certificado raíz", "certificados raíz", "certificado"], def: "Lo que Windows usa para confiar en los sitios seguros (el candadito). Si alguien agrega uno propio, puede espiar tus conexiones sin que el navegador avise." },
  { terms: ["proxy"], def: "Un intermediario por el que pasa tu conexión a internet. Si lo puso un malware, puede ver o cambiar lo que navegás." },
  { terms: ["archivo hosts"], def: "Un archivo de Windows que decide a qué dirección va cada sitio. Si lo modifican, al escribir la dirección de tu banco podés terminar en una página falsa." },
  { terms: ["DNS"], def: "El servicio que traduce nombres (google.com) a direcciones de internet. Cambiarlo es una forma de mandarte a sitios falsos." },
  { terms: ["Escritorio remoto"], def: "Función de Windows para usar esta PC desde otra a distancia, viendo la pantalla y usando el teclado." },
  { terms: ["control remoto", "acceso remoto"], def: "Programas que permiten manejar esta PC desde otro lugar (AnyDesk, TeamViewer…). Son legítimos, pero son la herramienta preferida de las estafas telefónicas." },
  { terms: ["cuarentena"], def: "Mover un archivo sospechoso a un lugar aislado donde no puede ejecutarse. No se borra: si fue un error, se puede restaurar." },
  { terms: ["exclusión", "exclusiones"], def: "Carpetas o programas que el antivirus tiene orden de NO revisar. El malware se agrega exclusiones para que no lo detecten." },
  { terms: ["PowerShell"], def: "Una herramienta de Windows para dar órdenes escribiendo comandos. Muy útil para técnicos, y muy usada por los ataques porque viene con Windows." },
  { terms: ["Win+R"], def: "La ventanita que aparece al apretar la tecla Windows + R. Sirve para abrir programas escribiendo su nombre; las estafas \"ClickFix\" te piden pegar ahí un comando." },
  { terms: ["comando", "comandos"], def: "Una orden escrita para la computadora. Pegar un comando que no entendés es como firmar algo sin leerlo." },
  { terms: ["ClickFix"], def: "Estafa en la que una página falsa (un \"captcha\" o un \"error\") te pide apretar Win+R y pegar un texto. Ese texto instala un programa que roba contraseñas." },
  { terms: ["hash", "SHA1", "SHA256"], def: "La \"huella digital\" de un archivo: un código único que permite saber si dos archivos son iguales sin mirarlos. Así se reconoce un malware ya conocido." },
  { terms: ["malware", "programa malicioso"], def: "Cualquier programa hecho para dañar, espiar o robar: virus, troyanos, ladrones de contraseñas, etc." },
  { terms: ["ladrón de contraseñas", "ladrones de contraseñas", "ladrones de cuentas", "ladrón de cuentas", "stealer"], def: "Malware que copia las contraseñas guardadas en el navegador, las sesiones abiertas y billeteras cripto, se las manda a alguien y muchas veces se borra solo." },
  { terms: ["sesión", "sesiones", "token"], def: "Lo que hace que una página o app te reconozca sin pedirte la contraseña de nuevo. Quien roba la sesión entra a tu cuenta como si fueras vos." },
  { terms: ["troyano"], def: "Malware que se hace pasar por un programa útil (un crack, un juego, una factura) para que lo abras vos." },
  { terms: ["minero", "minería"], def: "Malware que usa tu procesador o placa de video para fabricar criptomonedas para otro. La PC anda lenta y caliente." },
  { terms: ["firewall"], def: "El portero de las conexiones: decide qué programas pueden recibir o hacer conexiones por la red." },
  { terms: ["puerto", "puertos"], def: "Una \"puerta\" numerada por donde un programa recibe conexiones de la red." },
  { terms: ["controlador", "controladores", "driver"], def: "Software que maneja una parte de la PC (placa de video, sonido…). Corre con el máximo poder dentro de Windows." },
  { terms: ["UAC", "Control de cuentas de usuario"], def: "El cartel de Windows que pregunta \"¿Querés permitir que esta app haga cambios?\". Frena programas que intentan tomar control sin avisar." },
  { terms: ["SmartScreen"], def: "La protección de Windows que avisa antes de abrir programas o sitios peligrosos o desconocidos." },
  { terms: ["BitLocker"], def: "Cifra el disco: si te roban la PC, no pueden leer tus archivos sin tu clave." },
  { terms: ["Secure Boot", "Arranque seguro"], def: "Protección que impide que un programa malicioso se cargue antes que Windows al prender la PC." },
  { terms: ["Defender", "Microsoft Defender"], def: "El antivirus que viene con Windows. Demiurge lo usa como segunda opinión." },
  { terms: ["administrador"], def: "Una cuenta o programa con permiso para cambiar todo en la PC. Por eso conviene que el malware no lo consiga." },
  { terms: ["dirección IP", "IP"], def: "La dirección de una computadora en internet, como un número de teléfono." },
  { terms: ["webhook"], def: "Una dirección para mandar mensajes automáticos a un chat. Los ladrones de cuentas la usan para recibir lo que roban." },
  { terms: ["ofuscado", "código ofuscado"], def: "Código escrito a propósito para que sea ilegible y no se entienda qué hace. Lo legítimo rara vez se esconde así." },
  { terms: ["falso positivo"], def: "Cuando algo parece peligroso pero en realidad es inofensivo." },
  { terms: ["inyección", "inyectado", "inyectó"], def: "Técnica en la que un malware se mete dentro de un programa legítimo que ya está abierto, para esconderse detrás de él." },
  { terms: ["phishing"], def: "Engaño con un mensaje o página falsa (de tu banco, de un correo) para que entregues tus datos." },
  { terms: ["script"], def: "Un archivo con una lista de comandos que la computadora ejecuta uno tras otro." },
];

/** Término (en minúsculas) → definición. */
export const TERM_DEFS = new Map<string, string>(GLOSSARY.flatMap((e) => e.terms.map((t) => [t.toLowerCase(), e.def] as const)));

function escape(s: string) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// Los términos más largos primero ("certificado raíz" antes que "certificado"); palabra completa con letras unicode.
const sorted = [...TERM_DEFS.keys()].sort((a, b) => b.length - a.length);
export const TERM_RX = new RegExp(`(?<![\\p{L}\\p{N}])(${sorted.map(escape).join("|")})(?![\\p{L}\\p{N}])`, "giu");
