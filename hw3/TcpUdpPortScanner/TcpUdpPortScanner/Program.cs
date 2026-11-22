using System.CommandLine;
using System.Net;
using TcpUdpPortScanner;

public class Program
{
    public async static Task Main(string[] args)
    {
        var timeoutOption = new Option<double>("--timeout")
        {
            Description = "Таймаут ожидания ответа, с",
            DefaultValueFactory = _ => 2.0
        };
        var threadsOption = new Option<int>("--num-threads", "-j")
        {
            Description = "Число потоков",
            DefaultValueFactory = _ => Environment.ProcessorCount
        };
        var verboseOption = new Option<bool>("--verbose", "-v") { Description = "Подробный режим" };
        var guessOption   = new Option<bool>("--guess", "-g")   { Description = "Определять протокол" };
        var ipArgument = new Argument<string>("IP ADDRESS");
        var targetsArgument = new Argument<string[]>("targets")
        {
            Description = "tcp|udp[/PORT|PORT-PORT,...]",
            Arity = ArgumentArity.ZeroOrMore
        };
        var root = new RootCommand("TCP/UDP port scanner") { timeoutOption, threadsOption, verboseOption, guessOption, ipArgument, targetsArgument };
        
        root.SetAction(async (parse, cancelationToken) =>
        {
            var options = new ScanOptions(
                Timeout: TimeSpan.FromSeconds(parse.GetValue(timeoutOption)),
                Threads: parse.GetValue(threadsOption),
                Verbose: parse.GetValue(verboseOption),
                Guess:   parse.GetValue(guessOption));

            var ip = IPAddress.Parse(parse.GetValue(ipArgument)!);
            var targets = (parse.GetValue(targetsArgument) ?? [])
                .SelectMany(ParseTarget)
                .ToList();

            var scanner = new Scanner(options);
            await foreach (var result in scanner.Scan(ip, targets, cancelationToken))
                Console.WriteLine(result.Format(options));
        });
        
        await root.Parse(args).InvokeAsync();
    }

    private static IEnumerable<(string Protocol, int Port)> ParseTarget(string target)
    {
        var protocolPorts = target.Split('/');
        var protocol = protocolPorts[0];
        foreach (var ports in protocolPorts[1].Split(','))
        {
            if (ports.Contains('-'))
            {
                var startPort = int.Parse(ports.Split('-')[0]);
                var endPort = int.Parse(ports.Split('-')[1]);
                for (var port = startPort; port <= endPort; port++)
                    yield return (protocol, port);
            }
            yield return (protocol, int.Parse(ports));
        }
    }
}