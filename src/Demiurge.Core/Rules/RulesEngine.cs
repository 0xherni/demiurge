using Microsoft.Extensions.Logging;
using Demiurge.Core.Model;

namespace Demiurge.Core.Rules;

/// <summary>Evalúa las heurísticas habilitadas sobre el snapshot y genera Findings.</summary>
public sealed class RulesEngine
{
    private readonly ILogger _logger;

    public RulesEngine(ILogger logger) => _logger = logger;

    public List<Finding> Evaluate(RuleContext ctx)
    {
        foreach (var def in ctx.Rules.Heuristics.Where(h => h.Enabled))
        {
            if (!Heuristics.All.TryGetValue(def.Id, out var eval))
            {
                _logger.LogDebug("Heurística {Id} sin evaluador (definida sólo en YAML)", def.Id);
                continue;
            }
            try
            {
                eval(ctx, def);
            }
            catch (Exception ex)
            {
                // Una regla rota no tumba el análisis.
                _logger.LogError(ex, "Error evaluando {Id}", def.Id);
            }
        }
        return ctx.Findings;
    }
}
