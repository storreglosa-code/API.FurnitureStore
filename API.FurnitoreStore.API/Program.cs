using API.FornitureStore.Data;
using API.FurnitoreStore.API.Configuration;
using API.FurnitoreStore.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using NLog;
using NLog.Web;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("Init main");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.

    builder.Services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
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
            Description = $@"JWT Authorization Header using Bearer Scheme. 
                          Don't forget to enter prefix 'Bearer' and then your token. 
                          Example: 'Bearer 123lkj123lkj123lkj' "
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

    builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseSqlite(builder.Configuration.GetConnectionString("APIFurnitoreStoreContext")));

    builder.Services.Configure<JWTConfig>(builder.Configuration.GetSection("JWTConfig"));

    //Email
    builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
    builder.Services.AddSingleton<IEmailSender,EmailService>();

    var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JWTConfig:Secret").Value);

        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true, //False mientras estemos en DESARROLLO, sino TRUE
            ValidateAudience = true, //False mientras estemos en DESARROLLO, sino TRUE
            RequireExpirationTime = false,
            ValidateLifetime = true,
            ValidAudience = builder.Configuration.GetSection("JWTConfig:Audience").Value,
            ValidIssuer = builder.Configuration.GetSection("JWTConfig:Issuer").Value
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
    }
    );
    builder.Services.AddDefaultIdentity<IdentityUser>(options =>
    options.SignIn.RequireConfirmedAccount = true)  //Darle comportamiento por defecto, False mientras estemos en DESARROLLO, sino TRUE
        .AddEntityFrameworkStores<ApplicationDbContext>(); //El identity por default tiene que usar EF y ese DbContext para poder encontrar la tabla Usuarios.


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

    // Configure the HTTP request pipeline.
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

