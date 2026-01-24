using API.FornitureStore.Data;
using API.FurnitoreStore.API.Configuration;
using API.FurnitoreStore.API.Services;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Application.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NLog;
using NLog.Web;
using System;
using System.Text;


//LOGGER
var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("Init main");


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

//DATABASE
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
var connectionString =
    builder.Configuration.GetConnectionString("DefaultConnection");

options.UseNpgsql(connectionString);
});

//DI
builder.Services.AddScoped<IClientsService, ClientsService>();

//IDENTITY
builder.Services.AddDefaultIdentity<IdentityUser>(options =>
options.SignIn.RequireConfirmedAccount = true)
.AddEntityFrameworkStores<ApplicationDbContext>();


// AUTHENTICATION JWT
builder.Services.Configure<JWTConfig>(builder.Configuration.GetSection("JWTConfig"));

var jwtConfig = builder.Configuration.GetSection("JWTConfig").Get<JWTConfig>();

var secret = jwtConfig.Secret;

if (string.IsNullOrWhiteSpace(secret))
    throw new Exception("JWT Secret not configured");

var key = Encoding.UTF8.GetBytes(secret);

var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = true,
    ValidIssuer = jwtConfig.Issuer,
    ValidAudience = jwtConfig.Audience
};
builder.Services.AddSingleton(tokenValidationParameters);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = tokenValidationParameters;
});

//SWAGGER
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

//CORS
var allowedOrigins = new[] { "http://localhost:5500", "http://127.0.0.1:5500", "https://talentotech-frontendjs-production.up.railway.app" };
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalFrontend", policy =>
    {
        policy.WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod();
    });
});

builder.Services.AddHealthChecks();

// Email
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddSingleton<IEmailSender, EmailService>();

builder.Logging.ClearProviders();
builder.Host.UseNLog();


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
    var context = services.GetRequiredService<ApplicationDbContext>(); 

    Console.WriteLine("Applying migrations...");

Console.WriteLine("--------------------------------------------------");
Console.WriteLine("EF CORE CONNECTION STRING:");
Console.WriteLine(context.Database.GetConnectionString());
Console.WriteLine("--------------------------------------------------");

context.Database.Migrate(); // Aplica todas las migraciones pendientes
    Console.WriteLine("Migrations applied successfully.");

}
catch (Exception ex)
{
    Console.Error.WriteLine($"An error occurred while migrating the database: {ex.Message}");
    logger.Error(ex, "An error occurred while migrating the database.");
}
}
// --- Fin del Bloque de Migraciones ---
app.UseRouting();
app.UseCors("AllowLocalFrontend");

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");


app.Run();
