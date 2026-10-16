// CA5392: las DLLs de Windows que se llaman por P/Invoke se cargan sólo desde System32, nunca desde la carpeta de la
// app ni del directorio actual (evita que una DLL plantada con el mismo nombre se cargue en el proceso elevado).
[assembly: System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]
