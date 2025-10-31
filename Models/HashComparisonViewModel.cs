namespace PasswordHashingApp.Models;

public class HashComparisonViewModel
{
    public string InputPassword { get; set; } = string.Empty;
    public Dictionary<string, HashResult> Results { get; set; } = new();
    public List<HashAlgorithmInfo> AlgorithmInfos { get; set; } = new();
}

public class HashResult
{
    public string HashedValue { get; set; } = string.Empty;
    public long ExecutionTimeMs { get; set; }
    public int HashLength { get; set; }
    public string AlgorithmName { get; set; } = string.Empty;
}
