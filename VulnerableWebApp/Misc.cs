namespace VulnerableWebApplication
{
    public class Misc
    {
        public static string ScriptKiddiesFilter(string str)
        {
            return str.Replace("Framework", "")
                .Replace("Token", "")
                .Replace("cmd", "")
                .Replace("powershell", "")
                .Replace("http", "");

        }
    }
}
