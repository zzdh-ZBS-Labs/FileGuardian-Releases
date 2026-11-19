using System.Globalization;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using FileGuardian.Core;
using FileGuardian.Protocol;

namespace FileGuardian.Gui.ViewModels;

public sealed partial class CaptureItemViewModel : ObservableObject
{
    private readonly Dictionary<string, StoredAnalysis> _analyses = new(StringComparer.Ordinal);

    public CaptureItemViewModel(CaptureRecord record, IEnumerable<StoredAnalysis>? analyses = null, bool isLatest = true)
    {
        Record = record;
        _isLatest = isLatest;
        foreach (StoredAnalysis a in analyses ?? [])
            _analyses[a.PluginId] = a;
        Recompute();
    }

    public CaptureRecord Record { get; }
    public string CaptureId => Record.Metadata.CaptureId;
    public string SessionText => Record.Metadata.SessionId is null
        ? "Historical capture (no session ID)"
        : $"Session: {Record.Metadata.SessionId}; trigger: {Record.Metadata.Trigger}; observed UTC: {Record.Metadata.ObservedUtc:O}";
    public string Time => Record.Metadata.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.CurrentCulture);
    public string DisplayPath => TextSanitizer.ForDisplay(Record.DisplayPath, 512);
    public string FileName => TextSanitizer.ForDisplay(Path.GetFileName(Record.Metadata.RelativePath), 256);
    public string MirrorKey => Record.Metadata.MirrorPath ?? Record.Metadata.CaptureId;
    public string OriginalPath => TextSanitizer.ForDisplay(Record.Metadata.OriginalPath, 1024);
    public string Size => FormatBytes(Record.Metadata.CapturedLength);
    public string Sha256 => Record.Metadata.Sha256;
    public string Completeness => Record.Metadata.ReachedInitialLength
        ? "Complete"
        : $"Partial: source shrank ({Record.Metadata.CapturedLength} of {Record.Metadata.InitialLength} bytes)";
    public string StoredAt => SafePath(() => Record.ContentPath);
    public string LatestCopyText => IsLatest && Record.MirrorPath is not null
        ? $"Latest copy: {SafePath(() => Record.MirrorPath!)}"
        : "Older version (a newer capture of this file exists)";
    public string VersionLabel => IsLatest ? "latest" : "older";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LatestCopyText), nameof(VersionLabel))]
    private bool _isLatest;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsSuspicious), nameof(IsMalicious), nameof(IsInfo), nameof(IsClean))]
    private string _verdict = "";

    public bool IsSuspicious => Verdict == Verdicts.Suspicious;
    public bool IsMalicious => Verdict == Verdicts.Malicious;
    public bool IsInfo => Verdict == Verdicts.Info;
    public bool IsClean => Verdict == Verdicts.Clean;
    [ObservableProperty] private string _analysisText = "No analysis yet.";

    public void Apply(StoredAnalysis analysis)
    {
        _analyses[analysis.PluginId] = analysis;
        Recompute();
    }

    private void Recompute()
    {
        if (_analyses.Count == 0)
        {
            Verdict = "";
            AnalysisText = "No analysis yet.";
            return;
        }

        StoredAnalysis worst = _analyses.Values.MaxBy(a => Verdicts.Severity(a.Verdict))!;
        Verdict = worst.Verdict;

        var sb = new StringBuilder();
        foreach (StoredAnalysis a in _analyses.Values.OrderBy(a => a.PluginName, StringComparer.Ordinal))
        {
            sb.Append(a.PluginName).Append(": ").Append(a.Verdict);
            if (a.Summary is not null) sb.Append(" — ").Append(a.Summary);
            if (a.Tags.Count > 0) sb.Append("  [").Append(string.Join(", ", a.Tags)).Append(']');
            sb.AppendLine();
            foreach (var (k, v) in a.Fields)
                sb.Append("    ").Append(k).Append(" = ").AppendLine(v);
        }

        AnalysisText = sb.ToString().TrimEnd();
    }

    private static string SafePath(Func<string> resolve)
    {
        try { return TextSanitizer.ForDisplay(resolve(), 1024); }
        catch (InvalidDataException) { return "(invalid path in index)"; }
    }

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.0} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.0} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.00} GB"
    };
}
