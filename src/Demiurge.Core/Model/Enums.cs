namespace Demiurge.Core.Model;

public enum Severity
{
    Info = 0,
    Baja = 1,
    Media = 2,
    Alta = 3,
    Critica = 4,
    Pregunta = 5,
}

public enum EntityLevel
{
    Info,
    Revisar,
    Peligroso,
}

public enum GlobalVerdict
{
    Limpio,
    Revisar,
    ProbableInfeccion,
}

public enum ScanType
{
    Completo,
    Vivo,
    Profundo,
}

public enum FindingState
{
    Nuevo,
    Visto,
    Ignorado,
    Resuelto,
}

/// <summary>Tipos de entidad del modelo común (07_Modelo_Datos).</summary>
public enum EntityKind
{
    Binary,
    Process,
    Persistence,
    Connection,
    DnsQuery,
    ModuleLoad,
    Extension,
    BrowserSetting,
    InstalledSoftware,
    Account,
    Certificate,
    SystemSetting,
    Event,
    RecentFile,
    Driver,
}

public enum PersistenceType
{
    RunKey,
    RunOnce,
    Startup,
    Task,
    Service,
    Wmi,
    Ifeo,
    Winlogon,
    AppInit,
    Bits,
    Lsa,
    ComHijack,
    OfficeAddin,
}
