using Bussines.Abstract;
using Bussines.Concrete;
using FluentValidation.AspNetCore;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.AppDBContext;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.FluentValidations.AuthDTOs;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Helper.EmailHelpers.Abstract;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Helper.EmailHelpers.Concrete;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Helper.Filters;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Security.Abstract;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Security.Concrete;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Globalization;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddDbContext<AppDBContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default"));
});
builder.Services.AddIdentity<User, Role>()
      .AddEntityFrameworkStores<AppDBContext>()
        .AddDefaultTokenProviders();
builder.Services.AddScoped<IAuthService, AuthManager>();
builder.Services.AddScoped<ITokenService, TokenManager>();
builder.Services.AddScoped<IEmailHelper, EmailHelper>();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(x =>
{
    x.SwaggerDoc("v1", new OpenApiInfo { Title = "KarlShoes", Version = "v1", Description = "Identity Service API swagger client." });
    x.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\"
    });
    x.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }

    });
});
builder.Services.AddAuthentication(auth =>
{
    auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    auth.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.TokenValidationParameters = new()
    {
        ValidateAudience = true,
        ValidateIssuer = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAudience = builder.Configuration["Token:Audience"],
        ValidIssuer = builder.Configuration["Token:Issuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Token:SecurityKey"])),
        LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
            expires != null ? expires > DateTime.Now : false,
        NameClaimType = ClaimTypes.Email
    };
});
builder.Services.AddControllers(options => options.Filters.Add<ValidationFilters>())
    .AddFluentValidation(configuration =>
    {
        configuration.RegisterValidatorsFromAssemblyContaining<RegisterDTOValidation>();
        configuration.DisableDataAnnotationsValidation = true;
        configuration.LocalizationEnabled = true;
        configuration.AutomaticValidationEnabled = false;
        configuration.DisableDataAnnotationsValidation = true;

        configuration.ValidatorOptions.LanguageManager.Culture = new CultureInfo("en");
    });
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
