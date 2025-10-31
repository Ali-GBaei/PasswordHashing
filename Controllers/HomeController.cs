using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using PasswordHashingApp.Models;
using PasswordHashingApp.Services;

namespace PasswordHashingApp.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly IPasswordHashingService _hashingService;

    public HomeController(ILogger<HomeController> logger, IPasswordHashingService hashingService)
    {
        _logger = logger;
        _hashingService = hashingService;
    }

    public IActionResult Index()
    {
        var model = new HashComparisonViewModel
        {
            AlgorithmInfos = _hashingService.GetAlgorithmInfos()
        };
        return View(model);
    }

    [HttpPost]
    public IActionResult CompareHashes(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            ModelState.AddModelError("", "Please enter a password");
            var emptyModel = new HashComparisonViewModel
            {
                AlgorithmInfos = _hashingService.GetAlgorithmInfos()
            };
            return View("Index", emptyModel);
        }

        var model = new HashComparisonViewModel
        {
            InputPassword = password,
            AlgorithmInfos = _hashingService.GetAlgorithmInfos()
        };

        // Hash with SHA-256
        var sha256Result = _hashingService.HashWithSHA256(password);
        model.Results["SHA-256"] = new HashResult
        {
            AlgorithmName = "SHA-256",
            HashedValue = sha256Result.hash,
            ExecutionTimeMs = sha256Result.timeMs,
            HashLength = sha256Result.hash.Length
        };

        // Hash with SHA-512
        var sha512Result = _hashingService.HashWithSHA512(password);
        model.Results["SHA-512"] = new HashResult
        {
            AlgorithmName = "SHA-512",
            HashedValue = sha512Result.hash,
            ExecutionTimeMs = sha512Result.timeMs,
            HashLength = sha512Result.hash.Length
        };

        // Hash with BCrypt
        var bcryptResult = _hashingService.HashWithBCrypt(password);
        model.Results["BCrypt"] = new HashResult
        {
            AlgorithmName = "BCrypt",
            HashedValue = bcryptResult.hash,
            ExecutionTimeMs = bcryptResult.timeMs,
            HashLength = bcryptResult.hash.Length
        };

        // Hash with PBKDF2
        var pbkdf2Result = _hashingService.HashWithPBKDF2(password);
        model.Results["PBKDF2"] = new HashResult
        {
            AlgorithmName = "PBKDF2",
            HashedValue = pbkdf2Result.hash,
            ExecutionTimeMs = pbkdf2Result.timeMs,
            HashLength = pbkdf2Result.hash.Length
        };

        // Hash with Argon2
        var argon2Result = _hashingService.HashWithArgon2(password);
        model.Results["Argon2"] = new HashResult
        {
            AlgorithmName = "Argon2",
            HashedValue = argon2Result.hash,
            ExecutionTimeMs = argon2Result.timeMs,
            HashLength = argon2Result.hash.Length
        };

        return View("Index", model);
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
