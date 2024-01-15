using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

// Gera par de chaves
using RSA rsa = RSA.Create();
// Assinatura do token com a chave privada
var token = GerarTokenAssinado(rsa);
// Verificação da assinatura com a chave publica
bool isValid = VerificarAssinatura(token, rsa);
Console.WriteLine($"Token valido: {isValid}");
    

static string GerarTokenAssinado(RSA rsa)
    {
     var tokenHandler = new JwtSecurityTokenHandler();
     var key = new RsaSecurityKey(rsa);
     var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("user", "exampleUser") }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature)
        };
     var token = tokenHandler.CreateToken(tokenDescriptor);
     return tokenHandler.WriteToken(token);
    }

static bool VerificarAssinatura(string token, RSA rsa)
    {
     var tokenHandler = new JwtSecurityTokenHandler();
     var validationParameters = new TokenValidationParameters
     {
        IssuerSigningKey = new RsaSecurityKey(rsa),
        ValidateIssuerSigningKey = true,
        ValidateIssuer = false,
        ValidateAudience = false 
     };

     try
        {
         SecurityToken validatedToken;
          tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
          return true;
        }
        catch (SecurityTokenException)
        {
            return false;
        }
    }

