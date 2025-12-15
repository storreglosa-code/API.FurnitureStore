using API.FornitureStore.Data;
using API.FurnitoreStore.API.Configuration;
using API.FurnitoreStore.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NLog;
using System.Text;
using NLog.Web;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("Init main");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Cargar configuración (COMPATIBLE CON RAILWAY)
    builder.Configuration
        .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
        .AddEnvironmentVariables(); // Railway carga todo desde acá

    // Add services to the container.
    builder.Services.AddControllers();

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo
        {
            Title = "Furniture_Store_API",
            Version = "v1",
        });
        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = @"JWT Authorization Header using Bearer Scheme. 
                          Example: 'Bearer 123lkj123lkj'"
        });
        c.AddSecurityRequirement(new OpenApiSecurityRequirement {
            {
                new OpenApiSecurityScheme {
                    Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id="Bearer"
                        }
                },
                new string [] { }
            }
        });
    });
    

    // ⚠ Cargar cadena de conexión: appsettings.json o variable Railway
    var connectionString =
        builder.Configuration.GetConnectionString("DefaultConnection") ??
        builder.Configuration["DefaultConnection"]; // <-- para Railway

    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseNpgsql(connectionString));

    // JWT
    var jwtConfigSection = builder.Configuration.GetSection("JWTConfig");

    // Email
    builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
    builder.Services.AddSingleton<IEmailSender, EmailService>();


 

    var debugSecret = jwtConfigSection["Secret"];

    if (string.IsNullOrEmpty(debugSecret))
    {
        debugSecret = builder.Configuration["JWTConfig:Secret"];
    }

    Console.WriteLine($"JWT SECRET LENGTH: {debugSecret?.Length ?? 0}");
    Console.WriteLine("=== ENV VAR CHECK ===");
    Console.WriteLine("JWTConfig__Secret raw: " + Environment.GetEnvironmentVariable("JWTConfig__Secret"));
    Console.WriteLine("JWTConfig:Secret via config: " + builder.Configuration["JWTConfig:Secret"]);

    // Llave JWT
    var key = Encoding.ASCII.GetBytes(debugSecret);

    var tokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidateAudience = true,
        RequireExpirationTime = false,
        ValidateLifetime = true,
        ValidAudience = builder.Configuration["JWTConfig:Audience"],
        ValidIssuer = builder.Configuration["JWTConfig:Issuer"]
    };

    builder.Services.AddSingleton(tokenValidationParameters);

    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(jwt =>
    {
        jwt.SaveToken = true;
        jwt.TokenValidationParameters = tokenValidationParameters;
    });

    builder.Services.AddDefaultIdentity<IdentityUser>(options =>
        options.SignIn.RequireConfirmedAccount = true)
        .AddEntityFrameworkStores<ApplicationDbContext>();

    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var allowedOrigins = new[] { "http://localhost:5500", "http://127.0.0.1:5500" };

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowLocalFrontend", policy =>
        {
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
    });

    var app = builder.Build();

    app.UseCors("AllowLocalFrontend");

    app.UseSwagger();
    app.UseSwaggerUI();

    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();

    app.Run();
}
catch (Exception e)
{
    logger.Error(e, "There has been an error");
    throw;
}
finally
{
    NLog.LogManager.Shutdown();
}
