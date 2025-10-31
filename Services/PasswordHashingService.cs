using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;
using Konscious.Security.Cryptography;

namespace PasswordHashingApp.Services;

public interface IPasswordHashingService
{
    (string hash, long timeMs) HashWithSHA256(string password);
    (string hash, long timeMs) HashWithSHA512(string password);
    (string hash, long timeMs) HashWithBCrypt(string password);
    (string hash, long timeMs) HashWithPBKDF2(string password);
    (string hash, long timeMs) HashWithArgon2(string password);
    List<Models.HashAlgorithmInfo> GetAlgorithmInfos();
}

public class PasswordHashingService : IPasswordHashingService
{
    public (string hash, long timeMs) HashWithSHA256(string password)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha256.ComputeHash(bytes);
        sw.Stop();
        return (Convert.ToBase64String(hash), sw.ElapsedMilliseconds);
    }

    public (string hash, long timeMs) HashWithSHA512(string password)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        using var sha512 = SHA512.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha512.ComputeHash(bytes);
        sw.Stop();
        return (Convert.ToBase64String(hash), sw.ElapsedMilliseconds);
    }

    public (string hash, long timeMs) HashWithBCrypt(string password)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        sw.Stop();
        return (hash, sw.ElapsedMilliseconds);
    }

    public (string hash, long timeMs) HashWithPBKDF2(string password)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        // Generate a random salt
        var salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        
        // Use PBKDF2 with SHA512
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA512);
        var hash = pbkdf2.GetBytes(64);
        sw.Stop();
        
        // Combine salt and hash for storage
        var combined = new byte[salt.Length + hash.Length];
        Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
        Buffer.BlockCopy(hash, 0, combined, salt.Length, hash.Length);
        
        return (Convert.ToBase64String(combined), sw.ElapsedMilliseconds);
    }

    public (string hash, long timeMs) HashWithArgon2(string password)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        
        // Generate a random salt
        var salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
        argon2.Salt = salt;
        argon2.DegreeOfParallelism = 2;
        argon2.MemorySize = 65536; // 64 MB
        argon2.Iterations = 4;
        
        var hash = argon2.GetBytes(32);
        sw.Stop();
        
        // Combine salt and hash for storage
        var combined = new byte[salt.Length + hash.Length];
        Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
        Buffer.BlockCopy(hash, 0, combined, salt.Length, hash.Length);
        
        return (Convert.ToBase64String(combined), sw.ElapsedMilliseconds);
    }

    public List<Models.HashAlgorithmInfo> GetAlgorithmInfos()
    {
        return new List<Models.HashAlgorithmInfo>
        {
            new Models.HashAlgorithmInfo
            {
                Name = "SHA-256",
                Description = "SHA-256 is a cryptographic hash function that produces a 256-bit hash value. It's part of the SHA-2 family designed by the NSA.",
                Advantages = new List<string>
                {
                    "Very fast computation",
                    "Widely supported and standardized",
                    "Deterministic output (same input always produces same hash)",
                    "Good for data integrity verification"
                },
                Disadvantages = new List<string>
                {
                    "NOT recommended for password storage",
                    "Vulnerable to rainbow table attacks",
                    "Too fast - allows brute force attacks",
                    "No built-in salt mechanism",
                    "Not designed for password hashing"
                },
                SecurityLevel = "Low for passwords",
                UseCase = "File integrity, digital signatures, certificates. NOT for passwords!",
                CodeExample = @"using System.Security.Cryptography;
using System.Text;

public string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var bytes = Encoding.UTF8.GetBytes(password);
    var hash = sha256.ComputeHash(bytes);
    return Convert.ToBase64String(hash);
}"
            },
            new Models.HashAlgorithmInfo
            {
                Name = "SHA-512",
                Description = "SHA-512 is a cryptographic hash function that produces a 512-bit hash value. It's more secure than SHA-256 but still not designed for passwords.",
                Advantages = new List<string>
                {
                    "Produces longer hash (512 bits vs 256 bits)",
                    "Fast computation",
                    "Widely supported",
                    "Better collision resistance than SHA-256"
                },
                Disadvantages = new List<string>
                {
                    "NOT recommended for password storage",
                    "Vulnerable to rainbow table attacks",
                    "Too fast - allows brute force attacks",
                    "No built-in salt mechanism",
                    "Not designed for password hashing"
                },
                SecurityLevel = "Low for passwords",
                UseCase = "File integrity, digital signatures. NOT for passwords!",
                CodeExample = @"using System.Security.Cryptography;
using System.Text;

public string HashPassword(string password)
{
    using var sha512 = SHA512.Create();
    var bytes = Encoding.UTF8.GetBytes(password);
    var hash = sha512.ComputeHash(bytes);
    return Convert.ToBase64String(hash);
}"
            },
            new Models.HashAlgorithmInfo
            {
                Name = "BCrypt",
                Description = "BCrypt is a password hashing function designed by Niels Provos and David Mazières. It's based on the Blowfish cipher and includes a salt to protect against rainbow table attacks.",
                Advantages = new List<string>
                {
                    "Designed specifically for password hashing",
                    "Built-in salt generation",
                    "Adaptive - can increase work factor over time",
                    "Resistant to rainbow table attacks",
                    "Well-tested and widely adopted",
                    "Cross-platform compatibility"
                },
                Disadvantages = new List<string>
                {
                    "Limited to 72 bytes password length",
                    "Uses less memory than modern alternatives",
                    "Slower than Argon2 for same security level",
                    "Maximum work factor is 31"
                },
                SecurityLevel = "High",
                UseCase = "General-purpose password hashing for web applications",
                CodeExample = @"using BCrypt.Net;

public string HashPassword(string password)
{
    // workFactor: higher = more secure but slower (default: 11)
    return BCrypt.HashPassword(password, workFactor: 12);
}

public bool VerifyPassword(string password, string hash)
{
    return BCrypt.Verify(password, hash);
}"
            },
            new Models.HashAlgorithmInfo
            {
                Name = "PBKDF2",
                Description = "Password-Based Key Derivation Function 2 (PBKDF2) applies a pseudorandom function to derive keys. It's standardized in PKCS #5 and used widely in encryption and password storage.",
                Advantages = new List<string>
                {
                    "NIST approved and FIPS compliant",
                    "Widely supported in many platforms",
                    "Configurable iteration count",
                    "Can use different underlying hash functions (SHA-256, SHA-512)",
                    "Good for regulatory compliance"
                },
                Disadvantages = new List<string>
                {
                    "CPU-intensive only (no memory hardness)",
                    "Vulnerable to GPU/ASIC attacks",
                    "Slower than BCrypt for same security",
                    "Requires high iteration count (100,000+)"
                },
                SecurityLevel = "Medium-High",
                UseCase = "Applications requiring FIPS compliance, key derivation",
                CodeExample = @"using System.Security.Cryptography;
using System.Text;

public string HashPassword(string password)
{
    // Generate random salt
    var salt = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }
    
    // Hash with PBKDF2
    using var pbkdf2 = new Rfc2898DeriveBytes(
        password, salt, 100000, HashAlgorithmName.SHA512);
    var hash = pbkdf2.GetBytes(64);
    
    // Store salt + hash
    var combined = new byte[salt.Length + hash.Length];
    Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
    Buffer.BlockCopy(hash, 0, combined, salt.Length, hash.Length);
    
    return Convert.ToBase64String(combined);
}"
            },
            new Models.HashAlgorithmInfo
            {
                Name = "Argon2",
                Description = "Argon2 is the winner of the Password Hashing Competition (2015). It provides both CPU and memory hardness, making it resistant to GPU and ASIC attacks. Argon2id is the recommended variant.",
                Advantages = new List<string>
                {
                    "Winner of Password Hashing Competition",
                    "Memory-hard algorithm (resistant to GPU/ASIC attacks)",
                    "Configurable memory, time, and parallelism",
                    "Three variants: Argon2d, Argon2i, Argon2id",
                    "Most secure option available",
                    "Recommended by OWASP"
                },
                Disadvantages = new List<string>
                {
                    "Relatively new (2015)",
                    "Not available in all frameworks by default",
                    "Higher memory requirements",
                    "More complex configuration",
                    "May be overkill for low-security applications"
                },
                SecurityLevel = "Very High",
                UseCase = "High-security applications, sensitive data protection",
                CodeExample = @"using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

public string HashPassword(string password)
{
    // Generate random salt
    var salt = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(salt);
    }
    
    using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
    argon2.Salt = salt;
    argon2.DegreeOfParallelism = 2;  // Threads
    argon2.MemorySize = 65536;       // 64 MB
    argon2.Iterations = 4;           // Time cost
    
    var hash = argon2.GetBytes(32);
    
    // Store salt + hash
    var combined = new byte[salt.Length + hash.Length];
    Buffer.BlockCopy(salt, 0, combined, 0, salt.Length);
    Buffer.BlockCopy(hash, 0, combined, salt.Length, hash.Length);
    
    return Convert.ToBase64String(combined);
}"
            }
        };
    }
}
