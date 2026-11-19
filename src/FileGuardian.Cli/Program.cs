namespace FileGuardian.Cli;

internal static class Program
{
    public static Task<int> Main(string[] args) => CliApp.RunAsync(args, commandName: "FileGuardian.Cli");
}
