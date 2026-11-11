using System.Text;

namespace SigV4.Core;

/// <summary>Encodes logical Unicode text once, using AWS's byte-level escaping rules.</summary>
public static class S3UriEncoder
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static string Encode(string value, bool preserveSlashes = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        var result = new StringBuilder();
        foreach (byte valueByte in StrictUtf8.GetBytes(value))
        {
            if (IsUnreserved(valueByte) || (preserveSlashes && valueByte == '/'))
            {
                result.Append((char)valueByte);
            }
            else
            {
                result.Append('%');
                result.Append(valueByte.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
        }

        return result.ToString();
    }

    private static bool IsUnreserved(byte value) =>
        value is >= (byte)'A' and <= (byte)'Z'
            or >= (byte)'a' and <= (byte)'z'
            or >= (byte)'0' and <= (byte)'9'
            or (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~';
}
