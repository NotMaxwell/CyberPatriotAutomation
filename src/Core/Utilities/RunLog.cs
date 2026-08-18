using CyberPatriotAutomation.Core.Models;

namespace CyberPatriotAutomation.Core.Utilities;

/// <summary>
/// Records everything a run attempts, schedules and completes, and writes it to
/// a file when execution finishes.
/// </summary>
/// <remarks>
/// The console narrative already describes the run in full - which services were
/// queued for disabling, which users were created, which passwords were set -
/// but it scrolls away, and on a competition image there is rarely an
/// opportunity to read it as it goes. Lines are mirrored here with a timestamp
/// and flushed to disk at the end.
/// </remarks>
public static class RunLog
{
    private static readonly List<string> Entries = new();
    private static readonly Lock Gate = new();

    /// <summary>Append a line. Blank lines are dropped to keep the log dense.</summary>
    public static void Record(string text)
    {
        text = text.TrimEnd();
        if (text.Length == 0)
            return;
        Push($"[{DateTime.Now:HH:mm:ss}] {text}");
    }

    /// <summary>Append a section heading, mirroring a console rule.</summary>
    public static void RecordSection(string title)
    {
        title = title.Trim();
        if (title.Length == 0)
            return;
        Push(string.Empty);
        Push($"=== {title} ===");
    }

    /// <summary>Append a line with no timestamp, for structured blocks.</summary>
    public static void RecordRaw(string text) => Push(text);

    private static void Push(string line)
    {
        lock (Gate)
        {
            Entries.Add(line);
        }
    }

    /// <summary>Everything recorded so far.</summary>
    public static List<string> Snapshot()
    {
        lock (Gate)
        {
            return new List<string>(Entries);
        }
    }

    /// <summary>Discard everything recorded so far. Used by tests.</summary>
    public static void Clear()
    {
        lock (Gate)
        {
            Entries.Clear();
        }
    }

    /// <summary>
    /// Default log location: the desktop of the user running the tool.
    /// </summary>
    /// <remarks>
    /// The version is part of the file name so logs from different builds are
    /// distinguishable at a glance, without opening them.
    /// </remarks>
    public static string DefaultLogPath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"CyberPatriot_RunLog_v{AppConfig.Version}_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
        );

    /// <summary>Build the header written at the top of every log.</summary>
    public static IEnumerable<string> Header(string commandLine) =>
        new[]
        {
            new string('=', 79),
            "CyberPatriot Automation Tool - Run Log",
            $"Version:   {AppConfig.VersionString}",
            $"Started:   {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
            $"Command:   {commandLine}",
            new string('=', 79),
        };

    /// <summary>Append a structured, per-task record.</summary>
    /// <remarks>
    /// The narrative above says what happened as it happened; this block makes
    /// the outcome of each task greppable without reading the whole run.
    /// </remarks>
    public static void AppendResults(IEnumerable<TaskResult> results)
    {
        RecordRaw(string.Empty);
        RecordRaw(new string('=', 79));
        RecordRaw("TASK RESULTS");
        RecordRaw(new string('=', 79));

        foreach (var result in results)
        {
            RecordRaw(string.Empty);
            RecordRaw($"Task:       {result.TaskName}");
            RecordRaw($"Outcome:    {(result.Success ? "SUCCESS" : "FAILED")}");
            RecordRaw($"Verified:   {(result.Verified ? "yes" : "no")}");
            RecordRaw(
                $"Items:      {result.ItemsAttempted} attempted, {result.ItemsSucceeded} succeeded, "
                    + $"{result.ItemsSkipped} skipped"
            );
            RecordRaw($"Confidence: {result.ConfidencePercent}%");
            foreach (var line in (result.Message ?? string.Empty).Split('\n'))
                RecordRaw($"            {line}");
            if (!string.IsNullOrWhiteSpace(result.ErrorDetails))
            {
                RecordRaw("Issues:");
                foreach (var line in result.ErrorDetails.Split('\n'))
                    RecordRaw($"  - {line}");
            }
        }
    }

    /// <summary>
    /// Start mirroring everything Spectre.Console writes into the log.
    /// </summary>
    /// <remarks>
    /// Hooking the console once is far less error-prone than editing every one
    /// of the hundreds of MarkupLine call sites, and it cannot fall out of sync
    /// as tasks change. Spectre renders to an <see cref="IAnsiConsoleOutput"/>;
    /// wrapping that captures the rendered text, from which the markup has
    /// already been resolved, so the log holds exactly what the operator saw.
    /// </remarks>
    public static void AttachToConsole()
    {
        var original = Spectre.Console.AnsiConsole.Console;
        Spectre.Console.AnsiConsole.Console = Spectre.Console.AnsiConsole.Create(
            new Spectre.Console.AnsiConsoleSettings
            {
                Ansi = Spectre.Console.AnsiSupport.Detect,
                ColorSystem = Spectre.Console.ColorSystemSupport.Detect,
                Out = new LoggingConsoleOutput(original.Profile.Out),
            }
        );
    }

    /// <summary>Tees console output into the run log.</summary>
    private sealed class LoggingConsoleOutput : Spectre.Console.IAnsiConsoleOutput
    {
        private readonly Spectre.Console.IAnsiConsoleOutput _inner;
        private readonly System.Text.StringBuilder _pending = new();

        public LoggingConsoleOutput(Spectre.Console.IAnsiConsoleOutput inner) => _inner = inner;

        public TextWriter Writer => new TeeWriter(_inner.Writer, _pending);

        public bool IsTerminal => _inner.IsTerminal;
        public int Width => _inner.Width;
        public int Height => _inner.Height;

        public void SetEncoding(System.Text.Encoding encoding) => _inner.SetEncoding(encoding);

        private sealed class TeeWriter : TextWriter
        {
            private readonly TextWriter _inner;
            private readonly System.Text.StringBuilder _pending;

            public TeeWriter(TextWriter inner, System.Text.StringBuilder pending)
            {
                _inner = inner;
                _pending = pending;
            }

            public override System.Text.Encoding Encoding => _inner.Encoding;

            public override void Write(char value)
            {
                _inner.Write(value);

                // Buffer until a newline so each log entry is a whole line.
                if (value == '\n')
                {
                    Flush();
                    return;
                }
                if (value != '\r')
                    _pending.Append(value);
            }

            public override void Write(string? value)
            {
                if (value == null)
                    return;
                foreach (var c in value)
                    Write(c);
            }

            public override void Flush()
            {
                if (_pending.Length > 0)
                {
                    // Strip ANSI escapes so the log is plain text.
                    var text = System.Text.RegularExpressions.Regex.Replace(
                        _pending.ToString(),
                        "\\[[0-9;]*[A-Za-z]",
                        string.Empty
                    );
                    _pending.Clear();
                    Record(text);
                }
                _inner.Flush();
            }
        }
    }

    /// <summary>Write the log to <paramref name="path"/>.</summary>
    public static async Task WriteToAsync(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parent))
            Directory.CreateDirectory(parent);

        await File.WriteAllLinesAsync(path, Snapshot());
    }
}
