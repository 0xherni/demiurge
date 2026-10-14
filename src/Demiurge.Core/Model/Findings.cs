using System.Text.Json.Nodes;

namespace Demiurge.Core.Model;

public sealed class Finding
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string HeuristicId { get; set; } = "";
    public string HeuristicName { get; set; } = "";
    /// <summary>Entidad que disparó la señal (proceso, persistencia, conexión...).</summary>
    public EntityKind EntityKind { get; set; }
    public string EntityKey { get; set; } = "";
    public string EntityName { get; set; } = "";
    /// <summary>
    /// Entidad de scoring a la que suma: normalmente el binario (así persistencias y conexiones
    /// de un mismo ejecutable se acumulan). Para entidades sin binario es la propia entidad.
    /// </summary>
    public string ScoringKey { get; set; } = "";
    public int Weight { get; set; }
    /// <summary>Peso antes de allowlists / respuestas del usuario (para el detalle técnico).</summary>
    public int BaseWeight { get; set; }
    public Severity Severity { get; set; }
    public string Category { get; set; } = "";
    public List<string> AttackIds { get; set; } = new();
    public string Explanation { get; set; } = "";
    public string RecommendedAction { get; set; } = "";
    public JsonObject RawData { get; set; } = new();
    public FindingState State { get; set; } = FindingState.Nuevo;
    /// <summary>Motivo por el que el peso se redujo (allowlist dura, del usuario, respuesta).</summary>
    public string? Suppression { get; set; }
    /// <summary>Si la heurística requiere preguntarle al usuario (H-17, H-22).</summary>
    public UserQuestion? Question { get; set; }
}

public sealed class UserQuestion
{
    public string QuestionId { get; set; } = "";
    public string Text { get; set; } = "";
    public List<UserQuestionOption> Options { get; set; } = new();
}

public sealed class UserQuestionOption
{
    public string Value { get; set; } = "";
    public string Label { get; set; } = "";
    public int Weight { get; set; }
}

public sealed class UserAnswer
{
    public string EntityKey { get; set; } = "";
    public string QuestionId { get; set; } = "";
    public string Answer { get; set; } = "";
    public DateTimeOffset Date { get; set; }
}

public sealed class AllowlistEntry
{
    public string EntityKey { get; set; } = "";
    public string? DisplayName { get; set; }
    public string? Note { get; set; }
    public DateTimeOffset Date { get; set; }
}

public sealed class EntityScore
{
    public string ScoringKey { get; set; } = "";
    public EntityKind Kind { get; set; }
    public string DisplayName { get; set; } = "";
    public string? Path { get; set; }
    public int Score { get; set; }
    public int RawSum { get; set; }
    public bool AccumulationBonus { get; set; }
    public bool CriticalOverride { get; set; }
    public EntityLevel Level { get; set; }
    public Severity MaxSeverity { get; set; }
    public List<string> FindingIds { get; set; } = new();
    public List<string> AttackIds { get; set; } = new();

    // Tarjeta de 4 preguntas (08_UX_Explicaciones).
    public string WhatWeFound { get; set; } = "";
    public List<string> WhyItCaughtOurAttention { get; set; } = new();
    public string HowSerious { get; set; } = "";
    public string WhatToDo { get; set; } = "";
    public List<string> AvailableActions { get; set; } = new();
    public UserQuestion? PendingQuestion { get; set; }
}

public sealed class HealthReport
{
    /// <summary>buena | mejorable | mala</summary>
    public string Level { get; set; } = "buena";
    public string Summary { get; set; } = "";
    public List<SystemSetting> Items { get; set; } = new();
}

public sealed class CollectorStatus
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public bool Success { get; set; }
    public string? Error { get; set; }
    public TimeSpan Duration { get; set; }
    public int ItemCount { get; set; }
}
