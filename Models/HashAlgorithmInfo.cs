namespace PasswordHashingApp.Models;

public class HashAlgorithmInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> Advantages { get; set; } = new();
    public List<string> Disadvantages { get; set; } = new();
    public string CodeExample { get; set; } = string.Empty;
    public string SecurityLevel { get; set; } = string.Empty;
    public string UseCase { get; set; } = string.Empty;
}
