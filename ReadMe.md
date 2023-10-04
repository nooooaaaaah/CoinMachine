# Token Service

This is a simple C# library that provides functionality for generating JSON Web Tokens (JWTs) using the `Microsoft.IdentityModel.Tokens` library.

You can download the source code and build the library yourself.

## Usage

To use this library, you can create an instance of the `TokenService` class and call its `GenerateToken` method, passing in an object that implements the `IUser` interface.

Here's an example of how to use the library:

```csharp
using TokenService;

List<string> possibleRoles = new() { "Admin", "User" };
string secretKey = "your-secret-key-with-16bytes";
string issuer = "your-issuer";
int expiryMinutes = 60;

TokenService tokenService = new(secretKey, issuer, expiryMinutes, possibleRoles);

IUser user = new TestUser();

string token = tokenService.GenerateToken(user);

Console.WriteLine($"Generated Token: {token}");
JwtSecurityTokenHandler jwtHandler = new();
Console.WriteLine($"token: {jwtHandler.ReadJwtToken(token)}");
```

## Contributing

If you would like to contribute to this library, feel free to fork the repository and submit a pull request with your changes.

## License

This library is licensed under the MIT License. See the `LICENSE` file for more information.

Feel free to customize this outline to fit your project's specific needs. Let me know if you have any questions!
