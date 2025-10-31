# Password Hashing Comparison Tool

An ASP.NET Core MVC web application that compares different password hashing algorithms (SHA-256, SHA-512, BCrypt, PBKDF2, and Argon2) with detailed explanations, advantages, disadvantages, and code examples.

## Features

- **Interactive Comparison**: Enter any password and see how different algorithms hash it
- **Performance Metrics**: View execution time and hash length for each algorithm
- **Detailed Explanations**: Learn about each algorithm's strengths and weaknesses
- **Code Examples**: Copy-ready C# code examples for each hashing algorithm
- **Security Recommendations**: Clear guidance on which algorithms to use
- **Educational Purpose**: Visual comparison to help developers understand password hashing

## Supported Algorithms

1. **SHA-256** - Fast cryptographic hash (NOT recommended for passwords)
2. **SHA-512** - Longer cryptographic hash (NOT recommended for passwords)
3. **BCrypt** - Industry-standard password hashing (Recommended)
4. **PBKDF2** - NIST-approved key derivation function
5. **Argon2** - Winner of Password Hashing Competition 2015 (Best choice)

## Getting Started

### Prerequisites

- .NET 9.0 SDK or later

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Ali-GBaei/PasswordHashing.git
cd PasswordHashing
```

2. Restore dependencies:
```bash
dotnet restore
```

3. Run the application:
```bash
dotnet run
```

4. Open your browser and navigate to `https://localhost:5001` or `http://localhost:5000`

## Usage

1. Enter a password in the input field
2. Click "Compare All Hashing Algorithms"
3. View the results showing hashed values, execution times, and hash lengths
4. Explore the detailed information about each algorithm
5. Click "View Code Example" to see implementation code
6. Copy hashes or code using the copy buttons

## Technologies Used

- ASP.NET Core 9.0 MVC
- Bootstrap 5 for UI
- BCrypt.Net-Next for BCrypt hashing
- Konscious.Security.Cryptography.Argon2 for Argon2 hashing
- Built-in .NET cryptography libraries for SHA and PBKDF2

## Security Notes

⚠️ **Important**: This is an educational tool for demonstration purposes only.

- **Never use SHA-256 or SHA-512 for password storage** - They are too fast and vulnerable to brute force attacks
- **Use BCrypt or Argon2 for production applications** - They are specifically designed for password hashing
- **Always use proper password storage practices** in real applications
- Passwords entered in this tool are not stored anywhere

## Recommendations

- ✅ **Best Choice**: Argon2 - For new applications requiring maximum security
- ✅ **Good Choice**: BCrypt - For general-purpose web applications
- ❌ **Avoid**: SHA-256/512 - Do NOT use for password storage

## License

This project is for educational purposes only.

## Contributing

Feel free to submit issues and enhancement requests!
