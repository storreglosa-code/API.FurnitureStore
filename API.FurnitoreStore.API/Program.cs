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

    var host = "postgres.railway.internal";
    var port = "5432";
    var database = "railway";
    var username = "postgres";
    var password = "oBqrrgHjqhqXTmJdAZXnWBbMqakhATel";

    var connectionString = $"Host={host};Port={port};Database={database};Username={username};Password={password};SSL Mode=Require;Trust Server Certificate=true";

   Console.WriteLine($"Connection String: {connectionString}");

   if (string.IsNullOrWhiteSpace(connectionString))
   {
       throw new InvalidOperationException("DefaultConnection not found");
   }

   builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseNpgsql(connectionString));

    // Email
    builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
    builder.Services.AddSingleton<IEmailSender, EmailService>();


    // JWT
    var jwtConfigSection = builder.Configuration.GetSection("JWTConfig");

    // 1. Prioriza la lectura directa de la variable de entorno con el nombre Docker/Railway
    var secretFromEnv = Environment.GetEnvironmentVariable("JWT_SECRET_KEY");
    Console.WriteLine($"SECRET VIA ENV VAR: {secretFromEnv?.Length ?? 0}");

    // 2. Fallback a la lectura de la configuración de .NET (solo si la primera falla)
    if (string.IsNullOrEmpty(secretFromEnv))
    {
        secretFromEnv = builder.Configuration["JWTConfig:Secret"];
        Console.WriteLine($"SECRET VIA CONFIG: {secretFromEnv?.Length ?? 0}");
    }

    // 3. Chequeo de seguridad y asignación de la clave
    if (string.IsNullOrEmpty(secretFromEnv) || secretFromEnv.Length < 32)
    {
        Console.Error.WriteLine("FATAL ERROR: JWT Secret Key no encontrada o es demasiado corta (min 32 caracteres).");
        throw new InvalidOperationException("La clave 'JWTConfig__Secret' no se inyectó en el entorno del contenedor.");
    }

    var key = Encoding.ASCII.GetBytes(secretFromEnv);

    // --- FIN SECCIÓN DE LECTURA DE SECRETO JWT ---
   
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

    // --- Bloque para Aplicar Migraciones ---
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            var context = services.GetRequiredService<ApplicationDbContext>(); // Reemplaza con el nombre de tu DbContext

            Console.WriteLine("Applying migrations...");
            context.Database.Migrate(); // Aplica todas las migraciones pendientes
            Console.WriteLine("Migrations applied successfully.");

        }
        catch (Exception ex)
        {
            // Esto es crucial para debuggear si la conexión o la migración falla
            Console.Error.WriteLine($"An error occurred while migrating the database: {ex.Message}");
            // Opcional: registrar el error con un logger si lo tienes
            logger.Error(ex, "An error occurred while migrating the database.");
        }
    }
    // --- Fin del Bloque de Migraciones ---

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
