using System.Text.RegularExpressions;
using System.Web;
using CyberPatriotAutomation.Core.Models;
using Spectre.Console;

namespace CyberPatriotAutomation.Core.Utilities;

/// <summary>
/// Parses CyberPatriot README HTML files to extract task requirements
/// </summary>
public class ReadmeParser
{
    // Common prohibited software patterns
    private static readonly string[] ProhibitedSoftwareKeywords = new[]
    {
        "hacking tools",
        "hacking tool",
        "non-work related media",
        "unauthorized software",
        "prohibited software",
        "games",
        "peer-to-peer",
        "p2p",
        "torrent",
        "crack",
        "keygen",
    };

    /// <summary>
    /// Parse a CyberPatriot README HTML file
    /// </summary>
    public static async Task<ReadmeData> ParseHtmlReadmeAsync(string filePath)
    {
        var data = new ReadmeData();

        try
        {
            if (!File.Exists(filePath))
            {
                AnsiConsole.MarkupLine($"[red]README file not found: {filePath}[/]");
                return data;
            }

            var content = await File.ReadAllTextAsync(filePath);

            // Decode HTML entities
            content = HttpUtility.HtmlDecode(content);

            // Extract title
            data.Title = ExtractTitle(content);

            // Detect OS
            data.OperatingSystem = DetectOperatingSystem(content);

            // Extract sections
            data.Sections = ExtractSections(content);

            // Parse authorized users and administrators
            ParseAuthorizedUsers(content, data);

            // Parse software requirements
            ParseSoftwareRequirements(content, data);

            // Parse services
            ParseServices(content, data);

            // Parse group requirements
            ParseGroupRequirements(content, data);

            // Parse users to create
            ParseUsersToCreate(content, data);

            // Parse actionable items from paragraph tags
            ParseActionableItems(content, data);

            // Parse guidelines
            ParseGuidelines(content, data);

            // Extract scenario
            data.Scenario = ExtractScenario(content);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error parsing README: {ex.Message}[/]");
            AnsiConsole.WriteException(ex);
        }

        return data;
    }

    /// <summary>
    /// Extract the title from the README
    /// </summary>
    private static string ExtractTitle(string content)
    {
        // Try to find <h1> tag
        var h1Match = Regex.Match(
            content,
            @"<h1[^>]*>(.*?)</h1>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );
        if (h1Match.Success)
        {
            return StripHtmlTags(h1Match.Groups[1].Value).Trim();
        }

        // Try to find <title> tag
        var titleMatch = Regex.Match(
            content,
            @"<title[^>]*>(.*?)</title>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );
        if (titleMatch.Success)
        {
            return StripHtmlTags(titleMatch.Groups[1].Value).Trim();
        }

        return "Unknown";
    }

    /// <summary>
    /// Detect the operating system from the README content
    /// </summary>
    /// <summary>
    /// Operating systems recognised in a README, most specific first.
    /// </summary>
    /// <remarks>
    /// Server editions precede the desktop entries so "Windows Server 2022" is
    /// not reported as a bare "Windows".
    /// </remarks>
    private static readonly (string Needle, string Label)[] OperatingSystems = new[]
    {
        ("windows server 2025", "Windows Server 2025"),
        ("windows server 2022", "Windows Server 2022"),
        ("windows server 2019", "Windows Server 2019"),
        ("windows server 2016", "Windows Server 2016"),
        ("windows server 2012", "Windows Server 2012"),
        ("windows 11", "Windows 11"),
        ("windows 10", "Windows 10"),
        ("windows 8.1", "Windows 8.1"),
        ("windows 7", "Windows 7"),
        ("ubuntu", "Ubuntu Linux"),
        ("debian", "Debian Linux"),
        ("fedora", "Fedora Linux"),
        ("linux", "Linux"),
    };

    /// <summary>
    /// Flatten markup and whitespace so OS names survive however they were typed.
    /// </summary>
    /// <remarks>
    /// Matching against raw HTML missed anything split by markup or a
    /// non-breaking space - <c>Windows&amp;nbsp;10</c> decodes to a U+00A0 that
    /// never equals the plain space being searched for, and
    /// <c>Windows &lt;b&gt;10&lt;/b&gt;</c> has a tag in the middle. Both are
    /// ordinary in hand-written READMEs and both produced "Unknown".
    /// </remarks>
    private static string NormalizeForOsMatch(string content) =>
        string.Join(
                ' ',
                StripHtmlTags(content).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            )
            .ToLowerInvariant();

    private static string? MatchOperatingSystem(string haystack)
    {
        foreach (var (needle, label) in OperatingSystems)
        {
            if (haystack.Contains(needle, StringComparison.Ordinal))
                return label;
        }
        return null;
    }

    private static string DetectOperatingSystem(string content)
    {
        // The title and first heading name the image on essentially every
        // official README ("Training Round Windows 10 README"). Consulting them
        // first avoids misreading prose such as "do not go back to Windows 10"
        // in a Windows 11 image, which a whole-document scan would match.
        var headlines = Regex.Matches(
            content,
            @"<(?:title|h1)[^>]*>(.*?)</(?:title|h1)>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );
        foreach (Match headline in headlines)
        {
            var match = MatchOperatingSystem(NormalizeForOsMatch(headline.Groups[1].Value));
            if (match != null)
                return match;
        }

        return MatchOperatingSystem(NormalizeForOsMatch(content)) ?? "Unknown";
    }

    /// <summary>
    /// Extract all sections (h2 headers and their content)
    /// </summary>
    private static Dictionary<string, string> ExtractSections(string content)
    {
        var sections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Match h2 tags and their content
        var h2Pattern = @"<h2[^>]*>(.*?)</h2>(.*?)(?=<h2|$)";
        var matches = Regex.Matches(
            content,
            h2Pattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        foreach (Match match in matches)
        {
            var header = StripHtmlTags(match.Groups[1].Value).Trim();
            var sectionContent = match.Groups[2].Value;
            sections[header] = sectionContent;
        }

        return sections;
    }

    /// <summary>
    /// Parse authorized administrators and users from the README
    /// </summary>
    private static void ParseAuthorizedUsers(string content, ReadmeData data)
    {
        // Find the Authorized Administrators/Users section
        var sectionPattern = @"Authorized\s+Administrators.*?(?=<h2|$)";
        var sectionMatch = Regex.Match(
            content,
            sectionPattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        if (!sectionMatch.Success)
        {
            // Try alternative pattern
            sectionPattern = @"<pre[^>]*>(.*?)</pre>";
            var preMatches = Regex.Matches(
                content,
                sectionPattern,
                RegexOptions.IgnoreCase | RegexOptions.Singleline
            );

            foreach (Match preMatch in preMatches)
            {
                var preContent = preMatch.Groups[1].Value;
                if (
                    preContent.ToLower().Contains("authorized")
                    || preContent.ToLower().Contains("administrator")
                    || preContent.ToLower().Contains("password")
                )
                {
                    ParseUserBlock(preContent, data);
                    return;
                }
            }
            return;
        }

        ParseUserBlock(sectionMatch.Value, data);
    }

    /// <summary>
    /// Parse a block of text containing user information
    /// </summary>
    private static void ParseUserBlock(string content, ReadmeData data)
    {
        // Turn line-breaking tags into newlines *before* stripping markup. Only a
        // <pre> block carries real newlines; a list written with <br> or one
        // <p>/<li> per user collapses to a single line once tags are removed, and
        // the whole block is then rejected as one over-long "username" - so such
        // a README yielded no users at all.
        var withBreaks = Regex.Replace(
            content,
            @"<\s*(?:br\s*/?|/p|/li|/div|/tr|/h[1-6])\s*>",
            "\n",
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        // Then strip the remaining HTML, preserving the line structure above.
        var cleanedContent = Regex.Replace(withBreaks, @"<[^>]+>", "");
        cleanedContent = HttpUtility.HtmlDecode(cleanedContent);

        var lines = cleanedContent.Split(
            new[] { '\r', '\n' },
            StringSplitOptions.RemoveEmptyEntries
        );

        bool inAdminSection = false;
        bool inUserSection = false;
        AuthorizedUser? currentUser = null;

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var lowerLine = line.ToLower();

            // Detect section changes
            if (
                lowerLine.Contains("authorized administrators")
                || lowerLine.Contains("authorized admins")
            )
            {
                inAdminSection = true;
                inUserSection = false;
                continue;
            }

            if (lowerLine.Contains("authorized users") || lowerLine.Contains("authorized user"))
            {
                inAdminSection = false;
                inUserSection = true;
                continue;
            }

            // Check for password line
            if (lowerLine.StartsWith("password:") || lowerLine.StartsWith("password :"))
            {
                if (currentUser != null)
                {
                    var password = line.Substring(line.IndexOf(':') + 1).Trim();
                    currentUser.Password = password;
                }
                continue;
            }

            // Check if this is a username line (not a password, not a section header)
            if (
                !lowerLine.StartsWith("password")
                && !lowerLine.Contains("authorized")
                && !string.IsNullOrWhiteSpace(line)
                && !line.StartsWith("<")
                && line.Length < 100
            ) // Usernames shouldn't be too long
            {
                // Check for "(you)" notation indicating primary user
                bool isPrimary = lowerLine.Contains("(you)");

                // READMEs annotate entries as "alice (you)" but also
                // "bob (Admin)". Stripping any parenthetical leaves the account
                // name to be validated on its own.
                var username = Regex.Replace(line, @"\s*\([^)]*\)\s*", "").Trim();

                if (!string.IsNullOrWhiteSpace(username) && IsValidUsername(username))
                {
                    currentUser = new AuthorizedUser
                    {
                        Username = username,
                        IsAdmin = inAdminSection,
                        IsPrimaryUser = isPrimary,
                    };

                    if (inAdminSection)
                    {
                        data.Administrators.Add(currentUser);
                    }
                    else if (inUserSection)
                    {
                        data.Users.Add(currentUser);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Check if a string looks like a valid username
    /// </summary>
    /// <summary>
    /// Characters Windows forbids in a local account name. Their presence is a
    /// reliable sign the line is prose rather than a username.
    /// </summary>
    private static readonly char[] InvalidUsernameChars =
    {
        '"',
        '/',
        '\\',
        '[',
        ']',
        ':',
        ';',
        '|',
        '=',
        ',',
        '+',
        '*',
        '?',
        '<',
        '>',
        '@',
        '.',
        '!',
    };

    private static bool IsValidUsername(string username)
    {
        username = username.Trim();

        if (string.IsNullOrWhiteSpace(username))
            return false;

        // Windows caps local account names at 20 characters. Allowing 50 let
        // whole sentences from the surrounding prose be recorded as users.
        if (username.Length > 20)
            return false;

        if (username.Contains("password", StringComparison.OrdinalIgnoreCase))
            return false;
        if (username.Contains("authorized", StringComparison.OrdinalIgnoreCase))
            return false;
        if (username.IndexOfAny(InvalidUsernameChars) >= 0)
            return false;

        // Windows does permit a space ("John Smith"), but a run of three or more
        // words is prose. Erring permissive here is deliberate: a real user
        // wrongly rejected is absent from the authorized set and would be
        // deleted, whereas a junk entry only ever protects an account.
        var words = username.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (words.Length > 2 || words.Any(IsCommonWord))
            return false;

        // Should contain at least one letter
        return username.Any(char.IsLetter);
    }

    /// <summary>
    /// Parse software requirements from the README
    /// </summary>
    private static void ParseSoftwareRequirements(string content, ReadmeData data)
    {
        var lowerContent = content.ToLower();

        // Check for prohibited software mentions
        foreach (var keyword in ProhibitedSoftwareKeywords)
        {
            if (lowerContent.Contains(keyword))
            {
                if (!data.ProhibitedSoftware.Contains(keyword, StringComparer.OrdinalIgnoreCase))
                {
                    data.ProhibitedSoftware.Add(keyword);
                }
            }
        }

        // Look for specific software requirements with more comprehensive patterns
        var softwarePatterns = new[]
        {
            // "latest stable version of Firefox"
            @"latest\s+(?:stable\s+)?version\s+of\s+([A-Za-z0-9]+)",
            // "access to the latest stable version of GIMP, Inkscape, and Tiled"
            @"access\s+to\s+(?:the\s+)?(?:latest\s+)?(?:stable\s+)?(?:version\s+of\s+)?([A-Za-z0-9,\s]+?)(?:\s+for\s+company|\s+for\s+use|\.)",
            // "should be using Firefox"
            @"should\s+(?:be\s+)?(?:using|have|install)\s+(?:the\s+)?(?:latest\s+)?(?:stable\s+)?(?:version\s+of\s+)?([A-Za-z0-9]+)",
            // "default browser ... should be ... Firefox"
            @"default\s+(?:web\s+)?browser.*?should\s+be\s+(?:the\s+)?(?:latest\s+)?(?:stable\s+)?(?:version\s+of\s+)?([A-Za-z0-9]+)",
        };

        var foundSoftware = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in softwarePatterns)
        {
            var matches = Regex.Matches(
                content,
                pattern,
                RegexOptions.IgnoreCase | RegexOptions.Singleline
            );
            foreach (Match match in matches)
            {
                var softwareList = match.Groups[1].Value.Trim();

                // Split by common delimiters: comma, "and", comma+and
                var softwareNames = Regex.Split(
                    softwareList,
                    @"\s*,\s*and\s+|\s*,\s*|\s+and\s+",
                    RegexOptions.IgnoreCase
                );

                // The phrase this match came from, used to decide "latest" below.
                var matchedPhrase = match.Value;

                foreach (var name in softwareNames)
                {
                    var cleanName = name.Trim().Trim(',', '.', ' ');

                    if (
                        string.IsNullOrWhiteSpace(cleanName)
                        || cleanName.Length < 2
                        || cleanName.Length > 50
                        || !IsPlausibleSoftwareName(cleanName)
                    )
                    {
                        continue;
                    }

                    if (!foundSoftware.Contains(cleanName))
                    {
                        foundSoftware.Add(cleanName);
                        data.RequiredSoftware.Add(
                            new SoftwareRequirement
                            {
                                Name = cleanName,
                                // Testing whether the *whole document* contained
                                // "latest" meant a single mention anywhere flagged
                                // every package as "Latest Stable".
                                ShouldBeLatest = matchedPhrase.Contains(
                                    "latest",
                                    StringComparison.OrdinalIgnoreCase
                                ),
                                IsRequired = true,
                            }
                        );
                    }
                }
            }
        }

        // Check for software that should NOT be installed (Microsoft Store restriction)
        if (
            lowerContent.Contains("should not be installed using the microsoft store")
            || lowerContent.Contains("not be installed using microsoft store")
        )
        {
            foreach (var software in data.RequiredSoftware)
            {
                software.Notes = (software.Notes ?? "") + " Do not install via Microsoft Store.";
            }
        }
    }

    /// <summary>
    /// Generic nouns that appear in these phrasings but never name a product.
    /// </summary>
    private static readonly HashSet<string> SoftwareNameNoise = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        "a",
        "an",
        "use",
        "company",
        "software",
        "program",
        "programs",
        "application",
        "applications",
        "app",
        "apps",
        "tool",
        "tools",
        "version",
        "versions",
        "access",
        "browser",
        "browsers",
        "system",
        "systems",
        "file",
        "files",
        "data",
        "internet",
    };

    /// <summary>
    /// Does this captured fragment plausibly name a piece of software?
    /// </summary>
    /// <remarks>
    /// The extraction patterns - notably the broad "access to ... ." one - happily
    /// capture ordinary prose, so "access to administrative tools." was recorded
    /// as required software named "administrative tools". Real product names are
    /// proper nouns, so require the fragment to start with an uppercase letter
    /// and not be an everyday word. This mirrors the check already applied to
    /// actionable software items.
    /// </remarks>
    private static bool IsPlausibleSoftwareName(string name)
    {
        if (name.Length == 0 || !char.IsUpper(name[0]))
            return false;
        if (IsCommonWord(name) || SoftwareNameNoise.Contains(name))
            return false;

        // Multi-word fragments are almost always prose rather than a product
        // name; every word would need to be capitalised to read as one.
        return name.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .All(w => w.Length > 0 && char.IsUpper(w[0]));
    }

    /// <summary>
    /// Parse service requirements from the README
    /// </summary>
    private static void ParseServices(string content, ReadmeData data)
    {
        var lowerContent = content.ToLower();

        // Look for Critical Services section
        var criticalPattern = @"Critical\s+Services:?\s*(.*?)(?:<h2|<\/ul>|$)";
        var criticalMatch = Regex.Match(
            content,
            criticalPattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        if (criticalMatch.Success)
        {
            var serviceContent = criticalMatch.Groups[1].Value;
            var cleanContent = StripHtmlTags(serviceContent).ToLower();

            // Check if it says "none" or similar
            if (cleanContent.Contains("none") || cleanContent.Contains("(none)"))
            {
                // No critical services
            }
            else
            {
                // Extract services from list items
                var liPattern = @"<li[^>]*>(.*?)</li>";
                var liMatches = Regex.Matches(
                    serviceContent,
                    liPattern,
                    RegexOptions.IgnoreCase | RegexOptions.Singleline
                );
                foreach (Match li in liMatches)
                {
                    var service = StripHtmlTags(li.Groups[1].Value).Trim();
                    if (
                        !string.IsNullOrWhiteSpace(service)
                        && !service.Equals("none", StringComparison.OrdinalIgnoreCase)
                        && !service.Contains("(none)")
                    )
                    {
                        data.CriticalServices.Add(service);
                    }
                }
            }
        }

        // Look for mentions of services that should be disabled
        // But NOT "do not disable" phrases
        // The original negative lookbehind only covered a literal "do not "
        // directly before "disable", so the very common competition phrasing
        // "do not stop or disable the X service" slipped through and queued a
        // critical service for disabling. Allow an intervening "<verb> or " and
        // the other negation forms READMEs use.
        var negated = new Regex(
            @"(?:do\s+not|do\s*n'?t|never|must\s+not|should\s+not)\s+(?:\w+\s+or\s+)?$",
            RegexOptions.IgnoreCase
        );

        // Collect first so every "do not disable" is registered as critical
        // before any prohibited entry is added.
        var toProhibit = new List<string>();
        foreach (
            Match match in Regex.Matches(
                content,
                @"disable\s+(?:the\s+)?([A-Za-z0-9\s]+?)\s+service",
                RegexOptions.IgnoreCase
            )
        )
        {
            var service = match.Groups[1].Value.Trim();
            if (negated.IsMatch(content[..match.Index]))
            {
                // "Do not disable X" means X is critical, not merely not-prohibited.
                AddCriticalService(service, data);
            }
            else
            {
                toProhibit.Add(service);
            }
        }

        foreach (
            Match match in Regex.Matches(
                content,
                @"([A-Za-z0-9\s]+?)\s+service\s+should\s+(?:be\s+)?disabled",
                RegexOptions.IgnoreCase
            )
        )
        {
            toProhibit.Add(match.Groups[1].Value.Trim());
        }

        foreach (var service in toProhibit)
        {
            AddProhibitedService(service, data);
        }

        // Check for CCS Client service warning (must be critical, not prohibited)
        if (lowerContent.Contains("do not stop") && lowerContent.Contains("ccs client"))
        {
            // Remove from prohibited if mistakenly added
            data.ProhibitedServices.RemoveAll(s =>
                s.Contains("CCS", StringComparison.OrdinalIgnoreCase)
            );

            if (!data.CriticalServices.Contains("CCS Client", StringComparer.OrdinalIgnoreCase))
            {
                data.CriticalServices.Add("CCS Client");
            }
        }

        // Final safety net: a service named as critical must never also be queued
        // for disabling, whichever pattern happened to match it first. Disabling a
        // scored critical service is one of the costliest mistakes in competition.
        data.ProhibitedServices.RemoveAll(p =>
            data.CriticalServices.Contains(p, StringComparer.OrdinalIgnoreCase)
        );
    }

    /// <summary>
    /// Record a service the README says must stay running, de-duplicated.
    /// </summary>
    private static void AddCriticalService(string service, ReadmeData data)
    {
        if (string.IsNullOrWhiteSpace(service) || service.Length >= 50)
            return;
        if (!data.CriticalServices.Contains(service, StringComparer.OrdinalIgnoreCase))
            data.CriticalServices.Add(service);
    }

    private static void AddProhibitedService(string service, ReadmeData data)
    {
        if (string.IsNullOrWhiteSpace(service) || service.Length >= 50)
            return;
        if (
            !data.ProhibitedServices.Contains(service, StringComparer.OrdinalIgnoreCase)
            && !data.CriticalServices.Contains(service, StringComparer.OrdinalIgnoreCase)
        )
        {
            data.ProhibitedServices.Add(service);
        }
    }

    /// <summary>
    /// Parse group requirements from the README
    /// </summary>
    private static void ParseGroupRequirements(string content, ReadmeData data)
    {
        // Pattern for "Make a new group called X and add ... users"
        var groupPattern =
            @"(?:make|create)\s+(?:a\s+)?(?:new\s+)?group\s+(?:called\s+)?[""']?(\w+)[""']?\s+and\s+add\s+(?:the\s+following\s+users?\s+to\s+(?:the\s+)?[""']?\w+[""']?\s+group:?\s*)?([^.]+)";
        // A single Regex.Match meant a README asking for two groups only ever
        // produced the first one. Iterate over every match.
        foreach (
            Match groupMatch in Regex.Matches(
                content,
                groupPattern,
                RegexOptions.IgnoreCase | RegexOptions.Singleline
            )
        )
        {
            var groupName = groupMatch.Groups[1].Value.Trim();
            var membersText = StripHtmlTags(groupMatch.Groups[2].Value);

            // Parse member names
            var members = Regex
                .Split(membersText, @"[,\s]+")
                .Select(m => m.Trim().Trim(',', '.'))
                .Where(m => !string.IsNullOrWhiteSpace(m) && IsValidUsername(m))
                .ToList();

            var alreadyPresent = data.GroupRequirements.Any(g =>
                g.GroupName.Equals(groupName, StringComparison.OrdinalIgnoreCase)
            );

            if (!string.IsNullOrWhiteSpace(groupName) && members.Count > 0 && !alreadyPresent)
            {
                data.GroupRequirements.Add(
                    new GroupRequirement { GroupName = groupName, Members = members }
                );
            }
        }
    }

    /// <summary>
    /// Parse users that need to be created
    /// </summary>
    private static void ParseUsersToCreate(string content, ReadmeData data)
    {
        // Pattern for "Make a new account named X"
        var patterns = new[]
        {
            @"(?:make|create)\s+(?:a\s+)?(?:new\s+)?(?:account|user)\s+(?:for\s+)?(?:this\s+employee\s+)?(?:named|called)\s+[""']?(\w+)[""']?",
            @"new\s+employee.*?(?:named|called)\s+[""']?(\w+)[""']?",
        };

        foreach (var pattern in patterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                var username = match.Groups[1].Value.Trim();
                if (
                    !string.IsNullOrWhiteSpace(username)
                    && IsValidUsername(username)
                    && username.Length >= 3
                    && !IsCommonWord(username)
                    && !data.UsersToCreate.Contains(username, StringComparer.OrdinalIgnoreCase)
                )
                {
                    data.UsersToCreate.Add(username);
                }
            }
        }
    }

    /// <summary>
    /// Check if a word is a common English word that shouldn't be a username
    /// </summary>
    private static bool IsCommonWord(string word)
    {
        var commonWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "this",
            "that",
            "user",
            "account",
            "the",
            "new",
            "for",
            "and",
            "not",
            "all",
            "any",
            "are",
            "was",
            "were",
            "been",
            "being",
            "have",
            "has",
            "had",
            "having",
            "does",
            "did",
            "doing",
            "should",
            "would",
            "could",
            "must",
            "will",
            "shall",
            "may",
            "might",
            "can",
            "need",
            "home",
            "employee",
            "named",
            "called",
            "following",
            "with",
            "from",
            "into",
        };
        return commonWords.Contains(word);
    }

    /// <summary>
    /// Parse actionable items from paragraph tags
    /// </summary>
    private static void ParseActionableItems(string content, ReadmeData data)
    {
        // Extract all paragraph tags
        var pPattern = @"<p[^>]*>(.*?)</p>";
        var pMatches = Regex.Matches(
            content,
            pPattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        foreach (Match pMatch in pMatches)
        {
            var paragraphHtml = pMatch.Groups[1].Value;
            var paragraphText = StripHtmlTags(paragraphHtml).Trim();

            if (string.IsNullOrWhiteSpace(paragraphText) || paragraphText.Length < 10)
                continue;

            var lowerText = paragraphText.ToLower();

            // Check for user creation patterns
            if (ContainsUserCreationPattern(lowerText))
            {
                var item = ParseUserCreationItem(paragraphText);
                if (item != null && !IsDuplicateActionItem(data, item))
                {
                    data.ActionableItems.Add(item);

                    // Also add to UsersToCreate if we found a username
                    if (
                        item.Details.TryGetValue("Username", out var username)
                        && !data.UsersToCreate.Contains(username, StringComparer.OrdinalIgnoreCase)
                    )
                    {
                        data.UsersToCreate.Add(username);
                    }
                }
            }

            // Check for group creation/management patterns
            if (ContainsGroupPattern(lowerText))
            {
                var item = ParseGroupItem(paragraphText);
                if (item != null && !IsDuplicateActionItem(data, item))
                {
                    data.ActionableItems.Add(item);
                }
            }

            // Check for service patterns
            if (ContainsServicePattern(lowerText))
            {
                var item = ParseServiceItem(paragraphText);
                if (item != null && !IsDuplicateActionItem(data, item))
                {
                    data.ActionableItems.Add(item);
                }
            }

            // Check for software installation/removal patterns
            if (ContainsSoftwarePattern(lowerText))
            {
                var item = ParseSoftwareItem(paragraphText);
                if (item != null && !IsDuplicateActionItem(data, item))
                {
                    data.ActionableItems.Add(item);
                }
            }

            // Check for security policy patterns
            if (ContainsSecurityPolicyPattern(lowerText))
            {
                var item = ParseSecurityPolicyItem(paragraphText);
                if (item != null && !IsDuplicateActionItem(data, item))
                {
                    data.ActionableItems.Add(item);
                }
            }

            // Check for file operation patterns
            if (ContainsFileOperationPattern(lowerText))
            {
                var item = ParseFileOperationItem(paragraphText);
                if (item != null && !IsDuplicateActionItem(data, item))
                {
                    data.ActionableItems.Add(item);
                }
            }
        }
    }

    #region Actionable Item Pattern Detection

    private static bool ContainsUserCreationPattern(string lowerText)
    {
        return lowerText.Contains("create")
                && (lowerText.Contains("user") || lowerText.Contains("account"))
            || lowerText.Contains("add") && lowerText.Contains("user")
            || lowerText.Contains("new employee")
            || lowerText.Contains("new user")
            || lowerText.Contains("new account");
    }

    private static bool ContainsGroupPattern(string lowerText)
    {
        return (lowerText.Contains("create") || lowerText.Contains("make"))
                && lowerText.Contains("group")
            || lowerText.Contains("add") && lowerText.Contains("to") && lowerText.Contains("group")
            || lowerText.Contains("remove")
                && lowerText.Contains("from")
                && lowerText.Contains("group")
            || lowerText.Contains("member") && lowerText.Contains("group");
    }

    private static bool ContainsServicePattern(string lowerText)
    {
        return (
                lowerText.Contains("enable")
                || lowerText.Contains("disable")
                || lowerText.Contains("start")
                || lowerText.Contains("stop")
                || lowerText.Contains("running")
                || lowerText.Contains("not running")
            ) && lowerText.Contains("service")
            || lowerText.Contains("should be running")
            || lowerText.Contains("must be running")
            || lowerText.Contains("should not be running");
    }

    private static bool ContainsSoftwarePattern(string lowerText)
    {
        return (
                lowerText.Contains("install")
                || lowerText.Contains("uninstall")
                || lowerText.Contains("remove")
                || lowerText.Contains("update")
            )
            && (
                lowerText.Contains("software")
                || lowerText.Contains("program")
                || lowerText.Contains("application")
                || lowerText.Contains("app")
            );
    }

    private static bool ContainsSecurityPolicyPattern(string lowerText)
    {
        return lowerText.Contains("password")
                && (
                    lowerText.Contains("policy")
                    || lowerText.Contains("require")
                    || lowerText.Contains("complexity")
                )
            || lowerText.Contains("firewall")
            || lowerText.Contains("audit") && lowerText.Contains("policy")
            || lowerText.Contains("security policy")
            || lowerText.Contains("local security")
            || lowerText.Contains("action center")
            || lowerText.Contains("windows defender")
            || lowerText.Contains("antivirus");
    }

    private static bool ContainsFileOperationPattern(string lowerText)
    {
        return (lowerText.Contains("delete") || lowerText.Contains("remove"))
                && (
                    lowerText.Contains("file")
                    || lowerText.Contains("folder")
                    || lowerText.Contains("directory")
                )
            || lowerText.Contains("prohibited") && lowerText.Contains("file")
            || lowerText.Contains("media file")
            || lowerText.Contains("unauthorized file");
    }

    #endregion

    #region Actionable Item Parsing

    private static ActionableItem? ParseUserCreationItem(string text)
    {
        var item = new ActionableItem { Type = ActionableItemType.CreateUser, RawText = text };

        // Try to extract username with strict patterns
        var patterns = new[]
        {
            @"(?:create|make)\s+(?:a\s+)?(?:new\s+)?(?:user\s+)?(?:account\s+)?(?:for\s+)?(?:this\s+employee\s+)?(?:named|called)\s+[""']?([a-zA-Z][a-zA-Z0-9_]+)[""']?",
            @"new\s+(?:employee|user|account)\s+(?:named|called)\s+[""']?([a-zA-Z][a-zA-Z0-9_]+)[""']?",
            @"add\s+(?:a\s+)?(?:new\s+)?(?:user|account)\s+(?:named|called)\s+[""']?([a-zA-Z][a-zA-Z0-9_]+)[""']?",
        };

        foreach (var pattern in patterns)
        {
            var match = Regex.Match(text, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                var username = match.Groups[1].Value.Trim();
                // Validate the username more strictly
                if (IsValidUsername(username) && username.Length >= 3 && !IsCommonWord(username))
                {
                    item.Details["Username"] = username;
                    item.Description = $"Create user account: {username}";
                    return item;
                }
            }
        }

        // Only return if we have meaningful text about creating a user
        if (
            text.ToLower().Contains("create")
            && (text.ToLower().Contains("account") || text.ToLower().Contains("user"))
            && text.ToLower().Contains("named")
        )
        {
            item.Description = "Create new user account (review text for details)";
            return item;
        }

        return null; // Don't return item if we can't extract meaningful info
    }

    private static ActionableItem? ParseGroupItem(string text)
    {
        var lowerText = text.ToLower();
        var item = new ActionableItem { RawText = text };

        // Determine if it's create, add to, or remove from
        if (lowerText.Contains("create") || lowerText.Contains("make"))
        {
            item.Type = ActionableItemType.CreateGroup;

            // Try to extract group name
            var groupPattern =
                @"(?:create|make)\s+(?:a\s+)?(?:new\s+)?group\s+(?:called\s+)?[""']?(\w+)[""']?";
            var match = Regex.Match(text, groupPattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                item.Details["GroupName"] = match.Groups[1].Value.Trim();
                item.Description = $"Create group: {item.Details["GroupName"]}";
            }
            else
            {
                item.Description = "Create new group (review text for details)";
            }
        }
        else if (
            lowerText.Contains("add")
            && lowerText.Contains("to")
            && lowerText.Contains("group")
        )
        {
            item.Type = ActionableItemType.AddUserToGroup;

            // Try to extract user and group
            var addPattern =
                @"add\s+(?:user\s+)?[""']?(\w+)[""']?\s+to\s+(?:the\s+)?[""']?(\w+)[""']?\s+group";
            var match = Regex.Match(text, addPattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                item.Details["Username"] = match.Groups[1].Value.Trim();
                item.Details["GroupName"] = match.Groups[2].Value.Trim();
                item.Description =
                    $"Add {item.Details["Username"]} to group {item.Details["GroupName"]}";
            }
            else
            {
                item.Description = "Add user to group (review text for details)";
            }
        }
        else if (
            lowerText.Contains("remove")
            && lowerText.Contains("from")
            && lowerText.Contains("group")
        )
        {
            item.Type = ActionableItemType.RemoveUserFromGroup;

            var removePattern =
                @"remove\s+(?:user\s+)?[""']?(\w+)[""']?\s+from\s+(?:the\s+)?[""']?(\w+)[""']?\s+group";
            var match = Regex.Match(text, removePattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                item.Details["Username"] = match.Groups[1].Value.Trim();
                item.Details["GroupName"] = match.Groups[2].Value.Trim();
                item.Description =
                    $"Remove {item.Details["Username"]} from group {item.Details["GroupName"]}";
            }
            else
            {
                item.Description = "Remove user from group (review text for details)";
            }
        }
        else
        {
            item.Type = ActionableItemType.CreateGroup;
            item.Description = "Group management task (review text for details)";
        }

        return item;
    }

    private static ActionableItem? ParseServiceItem(string text)
    {
        var lowerText = text.ToLower();
        var item = new ActionableItem { RawText = text };

        // Handle "do not stop or disable" patterns - these are NOT actionable (they're warnings)
        if (
            lowerText.Contains("do not disable")
            || lowerText.Contains("don't disable")
            || lowerText.Contains("do not stop")
            || lowerText.Contains("don't stop")
        )
        {
            // This is a warning to NOT disable something - extract the service name for critical services
            var criticalPattern =
                @"do\s+not\s+(?:stop|disable)\s+(?:or\s+\w+\s+)?(?:the\s+)?([A-Za-z0-9\s]+?)(?:\s+service|\s+process|\.|$)";
            var criticalMatch = Regex.Match(text, criticalPattern, RegexOptions.IgnoreCase);
            if (criticalMatch.Success)
            {
                var serviceName = criticalMatch.Groups[1].Value.Trim();
                if (
                    !string.IsNullOrWhiteSpace(serviceName)
                    && serviceName.Length > 2
                    && serviceName.Length < 50
                )
                {
                    item.Type = ActionableItemType.EnableService;
                    item.Details["ServiceName"] = serviceName;
                    item.Details["Warning"] = "Do NOT disable this service";
                    item.Description = $"Critical service (do NOT disable): {serviceName}";
                    return item;
                }
            }
            return null; // Don't return a generic item for "do not" warnings
        }

        // Check if it's enable or disable
        bool shouldEnable =
            lowerText.Contains("enable")
            || lowerText.Contains("start")
            || lowerText.Contains("should be running")
            || lowerText.Contains("must be running");
        bool shouldDisable =
            lowerText.Contains("disable")
            || lowerText.Contains("stop")
            || lowerText.Contains("should not be running")
            || lowerText.Contains("must not be running");

        // If neither enable nor disable is clearly indicated, skip
        if (!shouldEnable && !shouldDisable)
            return null;

        item.Type = shouldDisable
            ? ActionableItemType.DisableService
            : ActionableItemType.EnableService;

        // Try to extract service name with more specific patterns
        var servicePatterns = new[]
        {
            @"(?:enable|disable|start|stop)\s+(?:the\s+)?[""']?([A-Za-z][A-Za-z0-9\s]{2,30}?)[""']?\s+service",
            @"[""']?([A-Za-z][A-Za-z0-9\s]{2,30}?)[""']?\s+service\s+(?:should|must|needs)\s+(?:be\s+)?(?:enabled|disabled|started|stopped|running)",
        };

        foreach (var pattern in servicePatterns)
        {
            var match = Regex.Match(text, pattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                var serviceName = match.Groups[1].Value.Trim();
                if (
                    !string.IsNullOrWhiteSpace(serviceName)
                    && serviceName.Length >= 3
                    && serviceName.Length < 40
                    && !IsCommonWord(serviceName)
                )
                {
                    item.Details["ServiceName"] = serviceName;
                    item.Description = shouldDisable
                        ? $"Disable service: {serviceName}"
                        : $"Enable/ensure running: {serviceName}";
                    return item;
                }
            }
        }

        return null; // Don't return generic "review text" items for services
    }

    private static ActionableItem? ParseSoftwareItem(string text)
    {
        var lowerText = text.ToLower();
        var item = new ActionableItem { RawText = text };

        // Skip if this is about users/accounts, not software
        if (
            lowerText.Contains("user")
            || lowerText.Contains("account")
            || lowerText.Contains("home director")
        )
            return null;

        bool shouldInstall = lowerText.Contains("install") || lowerText.Contains("update");
        bool shouldRemove =
            lowerText.Contains("uninstall")
            || (
                lowerText.Contains("remove")
                && !lowerText.Contains("user")
                && !lowerText.Contains("account")
            );

        // Skip if neither install nor remove is clearly indicated
        if (!shouldInstall && !shouldRemove)
            return null;

        item.Type = shouldRemove
            ? ActionableItemType.RemoveSoftware
            : ActionableItemType.InstallSoftware;

        // Try to extract software name with more specific patterns
        var softwarePatterns = new[]
        {
            @"(?:install|uninstall|update)\s+(?:the\s+)?(?:latest\s+)?(?:version\s+of\s+)?[""']?([A-Z][A-Za-z0-9\s]{1,25})[""']?(?:\.|,|$|\s+for)",
            @"[""']?([A-Z][A-Za-z0-9]+)[""']?\s+(?:should|must|needs)\s+(?:be\s+)?(?:installed|removed|uninstalled|updated)",
        };

        foreach (var pattern in softwarePatterns)
        {
            var match = Regex.Match(text, pattern, RegexOptions.Singleline);
            if (match.Success)
            {
                var softwareName = match.Groups[1].Value.Trim();
                if (
                    !string.IsNullOrWhiteSpace(softwareName)
                    && softwareName.Length >= 2
                    && softwareName.Length < 30
                    && !IsCommonWord(softwareName)
                    && char.IsUpper(softwareName[0])
                ) // Software names typically start with uppercase
                {
                    item.Details["SoftwareName"] = softwareName;
                    item.Description = shouldRemove
                        ? $"Remove software: {softwareName}"
                        : $"Install/update software: {softwareName}";
                    return item;
                }
            }
        }

        return null; // Don't return generic items
    }

    private static ActionableItem? ParseSecurityPolicyItem(string text)
    {
        var lowerText = text.ToLower();
        var item = new ActionableItem { Type = ActionableItemType.SecurityPolicy, RawText = text };

        // Categorize the security policy type
        if (lowerText.Contains("password"))
        {
            item.Details["Category"] = "Password Policy";
            if (lowerText.Contains("complexity"))
                item.Description = "Configure password complexity requirements";
            else if (lowerText.Contains("length"))
                item.Description = "Configure password length requirements";
            else if (lowerText.Contains("history"))
                item.Description = "Configure password history policy";
            else if (lowerText.Contains("age") || lowerText.Contains("expir"))
                item.Description = "Configure password expiration policy";
            else
                item.Description = "Configure password policy";
        }
        else if (lowerText.Contains("firewall"))
        {
            item.Details["Category"] = "Firewall";
            item.Description = "Configure Windows Firewall settings";
        }
        else if (lowerText.Contains("audit"))
        {
            item.Details["Category"] = "Audit Policy";
            item.Description = "Configure audit policy settings";
        }
        else if (lowerText.Contains("action center"))
        {
            item.Details["Category"] = "Action Center";
            item.Description = "Configure Windows Action Center";
        }
        else if (lowerText.Contains("defender") || lowerText.Contains("antivirus"))
        {
            item.Details["Category"] = "Antivirus";
            item.Description = "Configure Windows Defender/Antivirus";
        }
        else
        {
            item.Details["Category"] = "General";
            item.Description = "Configure security policy (review text for details)";
        }

        return item;
    }

    private static ActionableItem? ParseFileOperationItem(string text)
    {
        var lowerText = text.ToLower();

        // Skip if this is about users/accounts
        if (lowerText.Contains("user") && lowerText.Contains("account"))
            return null;

        // Skip if this is a "do not remove" warning
        if (lowerText.Contains("do not remove") || lowerText.Contains("don't remove"))
            return null;

        var item = new ActionableItem { Type = ActionableItemType.FileOperation, RawText = text };

        if (
            (lowerText.Contains("delete") || lowerText.Contains("remove"))
            && (lowerText.Contains("file") || lowerText.Contains("media"))
        )
        {
            if (lowerText.Contains("media") && lowerText.Contains("prohibited"))
            {
                item.Description = "Remove prohibited media files";
                item.Details["FileType"] = "Media files";
                return item;
            }
            else if (lowerText.Contains("hacking") || lowerText.Contains("unauthorized"))
            {
                item.Description = "Remove unauthorized/hacking tool files";
                item.Details["FileType"] = "Unauthorized software/tools";
                return item;
            }
        }

        return null; // Don't return generic items
    }

    private static bool IsDuplicateActionItem(ReadmeData data, ActionableItem newItem)
    {
        return data.ActionableItems.Any(existing =>
            existing.Type == newItem.Type && existing.Description == newItem.Description
        );
    }

    #endregion

    /// <summary>
    /// Parse competition guidelines
    /// </summary>
    private static void ParseGuidelines(string content, ReadmeData data)
    {
        // Find Competition Guidelines section from pre-parsed sections first
        if (data.Sections.TryGetValue("Competition Guidelines", out var guidelinesContent))
        {
            ExtractGuidelinesFromHtml(guidelinesContent, data);
        }
        else
        {
            // Fallback: try to find guidelines directly in content
            var guidelinesPattern = @"Competition\s+Guidelines.*?<ul[^>]*>(.*?)</ul>";
            var match = Regex.Match(
                content,
                guidelinesPattern,
                RegexOptions.IgnoreCase | RegexOptions.Singleline
            );
            if (match.Success)
            {
                ExtractGuidelinesFromHtml(match.Groups[1].Value, data);
            }
        }
    }

    /// <summary>
    /// Extract guidelines from HTML content
    /// </summary>
    private static void ExtractGuidelinesFromHtml(string htmlContent, ReadmeData data)
    {
        var liPattern = @"<li[^>]*>(.*?)</li>";
        var liMatches = Regex.Matches(
            htmlContent,
            liPattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        foreach (Match li in liMatches)
        {
            var guideline = StripHtmlTags(li.Groups[1].Value).Trim();
            if (!string.IsNullOrWhiteSpace(guideline))
            {
                data.Guidelines.Add(guideline);
            }
        }
    }

    /// <summary>
    /// Extract the competition scenario
    /// </summary>
    private static string ExtractScenario(string content)
    {
        if (!content.Contains("Competition Scenario", StringComparison.OrdinalIgnoreCase))
            return string.Empty;

        var scenarioPattern = @"Competition\s+Scenario\s*</h2>\s*(.*?)(?=<h2|$)";
        var match = Regex.Match(
            content,
            scenarioPattern,
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        if (match.Success)
        {
            return StripHtmlTags(match.Groups[1].Value).Trim();
        }

        return string.Empty;
    }

    /// <summary>
    /// Remove HTML tags from a string
    /// </summary>
    private static string StripHtmlTags(string html)
    {
        if (string.IsNullOrEmpty(html))
            return string.Empty;

        // Remove script and style contents
        html = Regex.Replace(
            html,
            @"<script[^>]*>.*?</script>",
            "",
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );
        html = Regex.Replace(
            html,
            @"<style[^>]*>.*?</style>",
            "",
            RegexOptions.IgnoreCase | RegexOptions.Singleline
        );

        // Remove HTML tags
        html = Regex.Replace(html, @"<[^>]+>", " ");

        // Decode HTML entities
        html = HttpUtility.HtmlDecode(html);

        // Normalize whitespace
        html = Regex.Replace(html, @"\s+", " ");

        return html.Trim();
    }

    /// <summary>
    /// Display parsed README data in a formatted way
    /// </summary>
    public static void DisplayParsedData(ReadmeData data)
    {
        AnsiConsole.Write(new Rule($"[bold blue]{data.Title}[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        // OS Info
        AnsiConsole.MarkupLine($"[bold]Operating System:[/] [cyan]{data.OperatingSystem}[/]");
        AnsiConsole.WriteLine();

        // Scenario
        if (!string.IsNullOrWhiteSpace(data.Scenario))
        {
            AnsiConsole.Write(
                new Panel(data.Scenario)
                    .Header("[bold]Competition Scenario[/]")
                    .Border(BoxBorder.Rounded)
                    .BorderColor(Color.Grey)
            );
            AnsiConsole.WriteLine();
        }

        // Administrators
        if (data.Administrators.Count > 0)
        {
            var adminTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Red)
                .Title("[bold red]Authorized Administrators[/]")
                .AddColumn("[bold]Username[/]")
                .AddColumn("[bold]Password[/]")
                .AddColumn("[bold]Notes[/]");

            foreach (var admin in data.Administrators)
            {
                var notes = admin.IsPrimaryUser ? "[yellow](Primary User)[/]" : "";
                adminTable.AddRow(
                    $"[red]{admin.Username}[/]",
                    admin.Password ?? "[dim]N/A[/]",
                    notes
                );
            }
            AnsiConsole.Write(adminTable);
            AnsiConsole.WriteLine();
        }

        // Standard Users
        if (data.Users.Count > 0)
        {
            var userTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Green)
                .Title("[bold green]Authorized Users[/]")
                .AddColumn("[bold]Username[/]");

            foreach (var user in data.Users)
            {
                userTable.AddRow($"[green]{user.Username}[/]");
            }
            AnsiConsole.Write(userTable);
            AnsiConsole.WriteLine();
        }

        // Users to Create
        if (data.UsersToCreate.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold yellow]Users to Create:[/]");
            foreach (var user in data.UsersToCreate)
            {
                AnsiConsole.MarkupLine($"  [yellow]+ {user}[/]");
            }
            AnsiConsole.WriteLine();
        }

        // Group Requirements
        if (data.GroupRequirements.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold cyan]Group Requirements:[/]");
            foreach (var group in data.GroupRequirements)
            {
                AnsiConsole.MarkupLine($"  [cyan]Group: {group.GroupName}[/]");
                AnsiConsole.MarkupLine($"    Members: {string.Join(", ", group.Members)}");
            }
            AnsiConsole.WriteLine();
        }

        // Required Software
        if (data.RequiredSoftware.Count > 0)
        {
            var softwareTable = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Blue)
                .Title("[bold blue]Required Software[/]")
                .AddColumn("[bold]Software[/]")
                .AddColumn("[bold]Version[/]")
                .AddColumn("[bold]Notes[/]");

            foreach (var software in data.RequiredSoftware)
            {
                softwareTable.AddRow(
                    $"[blue]{software.Name}[/]",
                    software.ShouldBeLatest
                        ? "[green]Latest Stable[/]"
                        : (software.Version ?? "[dim]Any[/]"),
                    software.Notes ?? ""
                );
            }
            AnsiConsole.Write(softwareTable);
            AnsiConsole.WriteLine();
        }

        // Prohibited Software
        if (data.ProhibitedSoftware.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold red]Prohibited Software/Content:[/]");
            foreach (var software in data.ProhibitedSoftware)
            {
                AnsiConsole.MarkupLine($"  [red]✗ {software}[/]");
            }
            AnsiConsole.WriteLine();
        }

        // Critical Services
        if (data.CriticalServices.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold green]Critical Services (Do NOT disable):[/]");
            foreach (var service in data.CriticalServices)
            {
                AnsiConsole.MarkupLine($"  [green]● {service}[/]");
            }
            AnsiConsole.WriteLine();
        }

        // Prohibited Services
        if (data.ProhibitedServices.Count > 0)
        {
            AnsiConsole.MarkupLine("[bold red]Services to Disable:[/]");
            foreach (var service in data.ProhibitedServices)
            {
                AnsiConsole.MarkupLine($"  [red]○ {service}[/]");
            }
            AnsiConsole.WriteLine();
        }

        // Actionable Items
        if (data.ActionableItems.Count > 0)
        {
            AnsiConsole.Write(
                new Rule("[bold magenta]Actionable Items (from paragraphs)[/]").RuleStyle("magenta")
            );
            AnsiConsole.WriteLine();

            // Group by type for better display
            var groupedItems = data.ActionableItems.GroupBy(i => i.Type);

            foreach (var group in groupedItems)
            {
                var typeColor = group.Key switch
                {
                    ActionableItemType.CreateUser => "yellow",
                    ActionableItemType.CreateGroup
                    or ActionableItemType.AddUserToGroup
                    or ActionableItemType.RemoveUserFromGroup => "cyan",
                    ActionableItemType.EnableService or ActionableItemType.DisableService => "blue",
                    ActionableItemType.InstallSoftware or ActionableItemType.RemoveSoftware =>
                        "green",
                    ActionableItemType.SecurityPolicy => "red",
                    ActionableItemType.FileOperation => "orange3",
                    _ => "white",
                };

                var typeLabel = group.Key switch
                {
                    ActionableItemType.CreateUser => "👤 User Management",
                    ActionableItemType.CreateGroup => "👥 Group Creation",
                    ActionableItemType.AddUserToGroup => "👥 Add to Group",
                    ActionableItemType.RemoveUserFromGroup => "👥 Remove from Group",
                    ActionableItemType.EnableService => "⚙️ Enable Service",
                    ActionableItemType.DisableService => "⚙️ Disable Service",
                    ActionableItemType.InstallSoftware => "📦 Install Software",
                    ActionableItemType.RemoveSoftware => "📦 Remove Software",
                    ActionableItemType.SecurityPolicy => "🔒 Security Policy",
                    ActionableItemType.FileOperation => "📁 File Operation",
                    _ => "📋 Other",
                };

                AnsiConsole.MarkupLine($"[bold {typeColor}]{typeLabel}[/]");

                foreach (var item in group)
                {
                    AnsiConsole.MarkupLine(
                        $"  [{typeColor}]→ {Markup.Escape(item.Description)}[/]"
                    );

                    // Show details if available
                    if (item.Details.Count > 0)
                    {
                        foreach (var detail in item.Details)
                        {
                            AnsiConsole.MarkupLine(
                                $"    [dim]{detail.Key}: {Markup.Escape(detail.Value)}[/]"
                            );
                        }
                    }
                }
                AnsiConsole.WriteLine();
            }
        }

        // Guidelines
        if (data.Guidelines.Count > 0)
        {
            AnsiConsole.Write(
                new Rule("[bold yellow]Competition Guidelines[/]").RuleStyle("yellow")
            );
            foreach (var guideline in data.Guidelines)
            {
                AnsiConsole.MarkupLine($"  [yellow]•[/] {Markup.Escape(guideline)}");
            }
            AnsiConsole.WriteLine();
        }
    }

    /// <summary>
    /// Legacy method for backward compatibility - parses simple text-based README
    /// </summary>
    public static async Task<Dictionary<string, string>> ParseReadmeAsync(string filePath)
    {
        var tasks = new Dictionary<string, string>();

        try
        {
            if (!File.Exists(filePath))
                return tasks;

            var content = await File.ReadAllTextAsync(filePath);

            // Check if it's HTML
            if (
                content.Contains("<html", StringComparison.OrdinalIgnoreCase)
                || content.Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
            )
            {
                var data = await ParseHtmlReadmeAsync(filePath);

                // Convert to dictionary format for backward compatibility
                tasks["Title"] = data.Title;
                tasks["OperatingSystem"] = data.OperatingSystem;
                tasks["Scenario"] = data.Scenario;
                tasks["Administrators"] = string.Join(
                    ", ",
                    data.Administrators.Select(a => a.Username)
                );
                tasks["Users"] = string.Join(", ", data.Users.Select(u => u.Username));
                tasks["RequiredSoftware"] = string.Join(
                    ", ",
                    data.RequiredSoftware.Select(s => s.Name)
                );
                tasks["CriticalServices"] = string.Join(", ", data.CriticalServices);

                return tasks;
            }

            // Original text-based parsing
            var lines = content.Split(new[] { Environment.NewLine }, StringSplitOptions.None);

            string? currentTask = null;
            var description = new List<string>();

            foreach (var line in lines)
            {
                if (line.StartsWith("#") || line.StartsWith("##"))
                {
                    if (currentTask != null && description.Count > 0)
                        tasks[currentTask] = string.Join(" ", description).Trim();

                    currentTask = line.TrimStart('#').Trim();
                    description.Clear();
                }
                else if (!string.IsNullOrWhiteSpace(line) && currentTask != null)
                {
                    description.Add(line.Trim());
                }
            }

            if (currentTask != null && description.Count > 0)
                tasks[currentTask] = string.Join(" ", description).Trim();

            return tasks;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing README: {ex.Message}");
            return tasks;
        }
    }
}
