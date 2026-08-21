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
    private static readonly List<FixRecord> Fixes = new();
    private static readonly Lock Gate = new();
    private static string _currentTask = "(startup)";

    /// <summary>
    /// Name the task that subsequent <see cref="RecordFix"/> calls belong to.
    /// </summary>
    /// <remarks>
    /// The utilities that record a fix - <see cref="RegistryOps"/> and friends -
    /// are called from every task and are not told which one they are serving.
    /// Rather than thread a task name through every signature to carry something
    /// none of them otherwise need, the runner sets it here before each task.
    /// </remarks>
    public static void BeginTask(string name)
    {
        lock (Gate)
        {
            _currentTask = string.IsNullOrWhiteSpace(name) ? "(unnamed task)" : name.Trim();
        }
    }

    /// <summary>
    /// When true, the utilities record what they would have done and change
    /// nothing. Set from the runner's own dry-run flag.
    /// </summary>
    /// <remarks>
    /// Tasks generally return before reaching a write in dry-run mode, so this is
    /// a backstop rather than the primary guard - but it is the one that cannot
    /// be forgotten in a new task, and it makes a dry run produce a full ledger
    /// of intended changes rather than a silent one.
    /// </remarks>
    public static bool DryRun { get; set; }

    /// <summary>
    /// Record one attempted change, and mirror a one-line summary into the
    /// narrative so the log reads in order.
    /// </summary>
    public static void RecordFix(
        string target,
        string intent,
        string? before,
        string action,
        FixOutcome outcome,
        string evidence
    )
    {
        FixRecord record;
        lock (Gate)
        {
            record = new FixRecord(
                _currentTask,
                target,
                intent,
                before,
                action,
                outcome,
                evidence
            );
            Fixes.Add(record);
        }

        // Outside the lock: Record takes it again, and nesting it here would rely
        // on the reentrancy of the lock rather than on not needing it.
        Record($"[{record.Tag}] {target} - want {intent}; {evidence}");
    }

    /// <summary>Every change recorded so far.</summary>
    public static List<FixRecord> FixSnapshot()
    {
        lock (Gate)
        {
            return new List<FixRecord>(Fixes);
        }
    }

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
            Fixes.Clear();
            _currentTask = "(startup)";
            DryRun = false;
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

    /// <summary>
    /// Append the remediation ledger: every change this run wanted to make, what
    /// it did, and the read-back that proves it.
    /// </summary>
    /// <remarks>
    /// Grouped by task and written before the task results, so the summary at
    /// the bottom of the log can be read against the detail above it.
    /// </remarks>
    public static void AppendLedger()
    {
        var fixes = FixSnapshot();

        RecordRaw(string.Empty);
        RecordRaw(new string('=', 79));
        RecordRaw("REMEDIATION LEDGER");
        RecordRaw(new string('=', 79));
        RecordRaw("Every change this run wanted to make, what it did about it, and how it");
        RecordRaw("knows. \"Proof\" is a re-read of the real state taken after the write, not a");
        RecordRaw("restatement of what was attempted.");

        if (fixes.Count == 0)
        {
            RecordRaw(string.Empty);
            RecordRaw("No changes were attempted.");
            return;
        }

        foreach (var group in fixes.GroupBy(f => f.Task))
        {
            RecordRaw(string.Empty);
            RecordRaw($"--- {group.Key} ---");

            foreach (var fix in group)
            {
                RecordRaw(string.Empty);
                RecordRaw($"[{fix.Tag}] {fix.Target}");
                RecordRaw($"  Want:   {fix.Intent}");
                RecordRaw($"  Before: {fix.Before ?? "(could not read)"}");
                RecordRaw($"  Did:    {fix.Action}");
                RecordRaw($"  Proof:  {fix.Evidence}");
            }
        }

        RecordRaw(string.Empty);
        RecordRaw(LedgerTotals(fixes));
    }

    /// <summary>One line tallying the ledger by outcome.</summary>
    public static string LedgerTotals(IReadOnlyCollection<FixRecord> fixes)
    {
        int Count(FixOutcome outcome) => fixes.Count(f => f.Outcome == outcome);

        return $"Totals: {Count(FixOutcome.Fixed)} fixed, "
            + $"{Count(FixOutcome.AlreadyCompliant)} already compliant, "
            + $"{Count(FixOutcome.Failed)} failed, "
            + $"{Count(FixOutcome.Unverified)} unverified, "
            + $"{Count(FixOutcome.Skipped)} skipped";
    }

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
