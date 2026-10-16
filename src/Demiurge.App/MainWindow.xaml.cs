using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Interop;
using Demiurge.Core.Ipc;
using Demiurge.Core.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Web.WebView2.Core;

namespace Demiurge.App;

/// <summary>
/// Ventana que hospeda la interfaz (WebView2) y la conecta con el motor, que corre en este mismo proceso.
///
/// La WebView2 corre elevada (la app lo está), así que se la encierra:
///  - Sólo carga la interfaz local, mapeada a https://app.demiurge.example/. Cualquier otra navegación se cancela.
///  - Sin ventanas nuevas, sin devtools (en Release), sin menús contextuales, sin autocompletar.
///  - Los mensajes sólo se aceptan si vienen de la interfaz local, y sólo operaciones del protocolo.
/// </summary>
public partial class MainWindow : Window
{
    private const string Host = "app.demiurge.example";
    private static readonly string Origin = $"https://{Host}/";

    private readonly CancellationTokenSource _cts = new();

    public MainWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => DarkTitleBar();
        Loaded += async (_, _) => await InitWebViewAsync();
        Closing += (_, _) => _cts.Cancel();
    }

    private async Task InitWebViewAsync()
    {
        var ui = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        if (!File.Exists(Path.Combine(ui, "index.html")))
        {
            Loading.Text = "Falta la interfaz (wwwroot). Reinstalá Demiurge.";
            return;
        }

        try
        {
            await StartWebViewAsync(ui);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            Loading.Text = "Falta Microsoft Edge WebView2 Runtime. Instalalo desde Windows Update o desde el sitio de Microsoft y volvé a abrir Demiurge.";
        }
        catch (Exception ex)
        {
            // Nunca quedarse en "Inicializando" sin decir nada.
            App.Log.LogError(ex, "No se pudo iniciar la interfaz");
            Loading.Text = $"No se pudo iniciar la interfaz de Demiurge.\n\n{ex.Message}\n\nCerrá y volvé a abrir la app. Si se repite, el detalle quedó en el log.";
        }
    }

    /// <summary>
    /// Perfil del navegador interno: una carpeta NUEVA en cada apertura (nombre aleatorio) dentro de %LOCALAPPDATA%, y se
    /// borran las de aperturas anteriores. Tiene que estar en una carpeta del usuario porque los procesos internos del
    /// navegador corren con permisos reducidos y no pueden usar una carpeta sólo de administradores. Al ser nueva cada vez,
    /// nada que otro programa deje ahí entre sesiones (por ejemplo, un service worker) llega a cargarse en la interfaz.
    /// </summary>
    private static string NewProfileFolder()
    {
        var parent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Demiurge", "WebView2");
        Directory.CreateDirectory(parent);
        foreach (var old in Directory.EnumerateDirectories(parent, "s-*"))
        {
            try
            {
                // Sólo si la ruta real es exactamente la esperada (sin enlaces en el camino); si no, se deja como está.
                SafeFile.VerifyDirectory(old);
                if (!File.GetAttributes(old).HasFlag(FileAttributes.ReparsePoint)) Directory.Delete(old, recursive: true);
            }
            catch { /* en uso o redirigida: se ignora */ }
        }
        return Path.Combine(parent, "s-" + Guid.NewGuid().ToString("N"));
    }

    private async Task StartWebViewAsync(string ui)
    {
        var env = await CoreWebView2Environment.CreateAsync(null, NewProfileFolder());
        await Web.EnsureCoreWebView2Async(env);
        var core = Web.CoreWebView2;
        var s = core.Settings;
#if DEBUG
        s.AreDevToolsEnabled = true;
#else
        s.AreDevToolsEnabled = false;
        s.AreBrowserAcceleratorKeysEnabled = false;
#endif
        s.AreDefaultContextMenusEnabled = false;
        s.AreDefaultScriptDialogsEnabled = false;
        s.AreHostObjectsAllowed = false;
        s.IsStatusBarEnabled = false;
        s.IsZoomControlEnabled = false;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        s.IsWebMessageEnabled = true;

        core.SetVirtualHostNameToFolderMapping(Host, ui, CoreWebView2HostResourceAccessKind.Deny);
        core.NavigationStarting += (_, e) =>
        {
            if (!e.Uri.StartsWith(Origin, StringComparison.OrdinalIgnoreCase))
            {
                e.Cancel = true;
                App.Log.LogWarning("Navegación bloqueada: {Uri}", e.Uri);
            }
        };
        core.FrameNavigationStarting += (_, e) =>
        {
            if (!e.Uri.StartsWith(Origin, StringComparison.OrdinalIgnoreCase)) e.Cancel = true;
        };
        // Abrir el navegador desde un proceso elevado lo dejaría elevado: no se abren ventanas ni links externos.
        core.NewWindowRequested += (_, e) => e.Handled = true;
        core.DownloadStarting += (_, e) => e.Cancel = true;
        core.PermissionRequested += (_, e) => e.State = CoreWebView2PermissionState.Deny;
        core.WebMessageReceived += OnMessage;
        core.NavigationCompleted += (_, _) =>
        {
            Loading.Visibility = Visibility.Collapsed;
            Web.Visibility = Visibility.Visible;
        };

        App.Engine.Push += OnEnginePush;
        Closed += (_, _) => App.Engine.Push -= OnEnginePush;

        core.Navigate(Origin + "index.html");
    }

    private async void OnMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        if (!e.Source.StartsWith(Origin, StringComparison.OrdinalIgnoreCase)) return;

        IpcRequest? req = null;
        IpcResponse resp;
        try
        {
            req = JsonSerializer.Deserialize<IpcRequest>(e.WebMessageAsJson, Protocol.Json) ?? throw new InvalidOperationException("Pedido vacío");
            var request = req;
            // El motor hace I/O y cálculo pesado: fuera del hilo de la interfaz.
            var data = await Task.Run(() => App.Engine.HandleAsync(request, CallerInfo.Self(), _cts.Token));
            resp = new IpcResponse { Id = req.Id, Ok = true, Data = data };
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !_cts.IsCancellationRequested)
        {
            App.Log.LogWarning("Pedido {Op} falló: {Error}", req?.Op, ex.Message);
            resp = new IpcResponse { Id = req?.Id, Ok = false, Error = ex.Message };
        }
        catch (OperationCanceledException)
        {
            return; // cerrando
        }
        Post(resp);
    }

    private void OnEnginePush(string evt, JsonNode? data) =>
        Dispatcher.InvokeAsync(() => Post(new IpcResponse { Event = evt, Ok = true, Data = data?.DeepClone() }));

    private void Post(IpcResponse resp)
    {
        try { Web.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(resp, Protocol.Json)); }
        catch (Exception ex) { App.Log.LogDebug(ex, "No se pudo enviar el mensaje a la interfaz"); }
    }

    // ---------- Barra de título oscura, a tono con la app ----------

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private void DarkTitleBar()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        int on = 1;
        DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int));          // DWMWA_USE_IMMERSIVE_DARK_MODE
        int caption = 0x0007070A;                                        // #0A0707 en COLORREF (0x00BBGGRR)
        DwmSetWindowAttribute(hwnd, 35, ref caption, sizeof(int));      // DWMWA_CAPTION_COLOR (Windows 11)
        int border = 0x0023232E;                                         // #2E2323
        DwmSetWindowAttribute(hwnd, 34, ref border, sizeof(int));       // DWMWA_BORDER_COLOR (Windows 11)
    }
}
