using System.Text;

namespace FileGuardian.Core;

/// <summary>
/// Makes untrusted text (file names, plugin output) safe to display.
/// Control, bidi-override and zero-width characters are shown as
/// "⟦U+202E⟧" so a name such as invoice[RLO]gpj.exe cannot pose as a
/// harmless file type. A literal "⟦" in a name is itself escaped, so a file
/// whose name merely contains the text "⟦U+202E⟧" (or "\u202E") always
/// looks different from one containing the real character.
/// </summary>
public static class TextSanitizer
{
    public static string ForDisplay(string? value, int maxLength = 2048)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var sb = new StringBuilder(Math.Min(value.Length, maxLength) + 16);

        foreach (char c in value)
        {
            if (sb.Length >= maxLength)
            {
                sb.Append('…');
                break;
            }

            if (char.IsControl(c) || IsBidiControl(c) || IsInvisible(c) || c == Open)
                sb.Append(Open).Append($"U+{(int)c:X4}").Append(Close);
            else
                sb.Append(c);
        }

        return sb.ToString();
    }

    public static string Truncate(string? value, int maxLength) =>
        value is null ? string.Empty
        : value.Length <= maxLength ? value
        : value[..maxLength];

    private const char Open = '\u27E6', Close = '\u27E7';

    private static bool IsInvisible(char c) =>
        c is >= '\u200B' and <= '\u200D' or '\u2060' or '\uFEFF' or '\u00AD';

    private static bool IsBidiControl(char c) =>
        c is >= '\u202A' and <= '\u202E'
          or >= '\u2066' and <= '\u2069'
          or '\u200E' or '\u200F' or '\u061C';
}
