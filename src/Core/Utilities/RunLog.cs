using PinnacleCyPat.Core.Models;

namespace PinnacleCyPat.Core.Utilities;

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

    /// <summary>
    /// Record a diagnostic: something the operator does not need to see while the
    /// run is happening, but needs afterwards to work out why it did what it did.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The console narrative reports outcomes - "Failed to remove: CCleaner" -
    /// but not the evidence. When the reason string comes back empty, which is
    /// what happens whenever a tool reports failure only through an exit code,
    /// that line degrades to "Failed to remove: CCleaner ()" and there is
    /// nothing left to investigate with. Diagnostics carry the evidence: the
    /// exact command, its exit code, and what it printed.
    /// </para>
    /// <para>
    /// These go to the log only, never to the console. They exist to be read
    /// after the fact, and putting them on screen would bury the narrative that
    /// the operator does have to follow live.
    /// </para>
    /// </remarks>
    public static void Diagnostic(string category, string detail)
    {
        detail = detail.TrimEnd();
        if (detail.Length == 0)
            return;

        // Indented continuation lines keep a multi-line payload - a captured
        // stderr, say - visibly attached to its own entry rather than reading as
        // separate events.
        var lines = detail.Split('\n');
        Push($"[{DateTime.Now:HH:mm:ss}] [{category}] {lines[0].TrimEnd()}");
        foreach (var line in lines.Skip(1))
            Push($"                      {line.TrimEnd()}");
    }

    /// <summary>
    /// Record the outcome of an external command, with enough to reproduce it.
    /// </summary>
    /// <remarks>
    /// Output is captured only on failure, and truncated. A successful command's
    /// output is usually large and never interesting; a failure's first few lines
    /// are almost always the whole story, and an untruncated capture of, say, a
    /// Chocolatey log would bury every other entry in the file.
    /// </remarks>
    public static void RecordCommand(
        string program,
        string? arguments,
        int? exitCode,
        string output,
        string? error,
        TimeSpan elapsed
    )
    {
        var status = exitCode is null
            ? "no exit code (timed out or never ran)"
            : $"exit {exitCode}";
        Diagnostic("cmd", $"{program} {Redact(arguments ?? string.Empty)}".TrimEnd());
        Diagnostic("cmd", $"  -> {status} in {elapsed.TotalSeconds:F1}s");

        if (exitCode == 0)
            return;

        if (!string.IsNullOrWhiteSpace(error))
            Diagnostic("cmd", $"  stderr: {Truncate(error)}");
        if (!string.IsNullOrWhiteSpace(output))
            Diagnostic("cmd", $"  stdout: {Truncate(output)}");
    }

    /// <summary>Longest captured output kept per failed command.</summary>
    private const int MaxCapturedOutput = 2000;

    /// <summary>How much of a long capture to keep from each end.</summary>
    private const int TruncationEdge = MaxCapturedOutput / 2;

    /// <summary>
    /// Shorten a long capture, keeping both ends.
    /// </summary>
    /// <remarks>
    /// Keeping only the head loses the reason. A failed Chocolatey upgrade opens
    /// with pages of package boilerplate and states the actual error - "Error -
    /// hashes do not match" - at the very end, so a head-only cut recorded
    /// everything except the one line worth having.
    /// </remarks>
    private static string Truncate(string text)
    {
        text = text.Trim();
        if (text.Length <= MaxCapturedOutput)
            return text;

        var head = text[..TruncationEdge].TrimEnd();
        var tail = text[^TruncationEdge..].TrimStart();
        var omitted = text.Length - (2 * TruncationEdge);
        return $"{head}\n    ... [{omitted} chars omitted] ...\n    {tail}";
    }

    /// <summary>
    /// Blank out plaintext passwords before a command line reaches the log.
    /// </summary>
    /// <remarks>
    /// Account passwords are interpolated into <c>ConvertTo-SecureString</c>
    /// calls. The run log does deliberately record each generated password once,
    /// where the task announces it - but that is a considered disclosure in one
    /// place, not a reason to scatter the same secret through every command
    /// echo, where it would also survive into any log a competitor shares.
    /// </remarks>
    public static string Redact(string commandLine) =>
        System.Text.RegularExpressions.Regex.Replace(
            commandLine,
            @"(ConvertTo-SecureString\s+)'(?:[^']|'')*'",
            "$1'***'",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
        );

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
            $"PinnacleCyPat_RunLog_v{AppConfig.Version}_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
        );

    /// <summary>Build the header written at the top of every log.</summary>
    public static IEnumerable<string> Header(string commandLine) =>
        new[]
        {
            new string('=', 79),
            "PinnacleCyPat - Run Log",
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
