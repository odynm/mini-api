using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MinimalApi.Data;
using MinimalApi.Models;
using MiniValidation;
using NetDevPack.Identity;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;

var builder = WebApplication.CreateBuilder(args);

#region Configure Services

builder.Services.AddDbContext<ContextDb>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Minimal API",
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Inser the JWT token: Bearer {token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
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
            new string[] {}
        }
    });
});

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseNpgsql(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly("MinimalApi")
    )
);

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DeletePlayerClaim",
        policy => policy.RequireClaim("DeletePlayerClaim")
    );
});

var app = builder.Build();

#endregion

#region Configure Pipeline

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthConfiguration();
app.UseHttpsRedirection();

MapActions(app);

app.Run();

#endregion

#region Actions

void MapActions(WebApplication app)
{
    app.MapPost("/registration", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        RegisterUser registerUser
    ) =>
    {
        if (registerUser == null)
            return Results.BadRequest("User not defined");

        if (!MiniValidator.TryValidate(registerUser, out var errors))
            return Results.ValidationProblem(errors);

        var user = new IdentityUser
        {
            UserName = registerUser.Email,
            Email = registerUser.Email,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(user, registerUser.Password);

        if (!result.Succeeded)
            return Results.BadRequest(result.Errors);

        var jwt = new JwtBuilder()
            .WithUserManager(userManager)
            .WithJwtSettings(appJwtSettings.Value)
            .WithEmail(user.Email)
            .WithJwtClaims()
            .WithUserClaims()
            .WithUserRoles()
            .BuildUserResponse();

        return Results.Ok(jwt);
    })
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("UserRegistration")
    .WithTags("User");

    app.MapPost("/login", [AllowAnonymous] async (
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOptions<AppJwtSettings> appJwtSettings,
        LoginUser loginUser
    ) =>
    {
        if (loginUser == null)
            return Results.BadRequest("User not defined");

        if (!MiniValidator.TryValidate(loginUser, out var errors))
            return Results.ValidationProblem(errors);

        var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

        if (result.IsLockedOut)
            return Results.BadRequest("User is blocked");

        if (!result.Succeeded)
            return Results.BadRequest("Invalid user name or password");

        var jwt = new JwtBuilder()
            .WithUserManager(userManager)
            .WithJwtSettings(appJwtSettings.Value)
            .WithEmail(loginUser.Email)
            .WithJwtClaims()
            .WithUserClaims()
            .WithUserRoles()
            .BuildUserResponse();

        return Results.Ok(jwt);
    })
        .ProducesValidationProblem()
        .Produces(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("UserLogin")
        .WithTags("User");

    app.MapGet("/player", [AllowAnonymous] async (ContextDb context) =>
        await context.Players.ToListAsync()
    )
        .WithName("GetPlayer")
        .WithTags("Player");

    app.MapGet("/player/{id}", [Authorize] async (Guid id, ContextDb context) =>
        await context.Players.FindAsync(id) is Player player
                ? Results.Ok(player)
                : Results.NotFound()
    )
        .Produces<Player>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status404NotFound)
        .WithName("GetPlayerById")
        .WithTags("Player");

    app.MapPost("/player", [Authorize] async (ContextDb context, Player player) =>
    {
        if (!MiniValidator.TryValidate(player, out var errors))
            return Results.ValidationProblem(errors);

        context.Players.Add(player);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.Created($"/player/{player.Id}", player)
            : Results.BadRequest("An error occurred while saving the changes");
    })
        .ProducesValidationProblem()
        .Produces<Player>(StatusCodes.Status201Created)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("PostPlayer")
        .WithTags("Player");

    app.MapPut("/player/{id}", [Authorize] async (Guid id, ContextDb context, Player player) =>
    {
        var playerDb = await context.Players.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id);
        if (playerDb == null) return Results.NotFound();

        if (!MiniValidator.TryValidate(player, out var errors))
            return Results.ValidationProblem(errors);

        context.Players.Update(player);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.NoContent()
            : Results.BadRequest("An error occurred while saving the changes");
    })
        .ProducesValidationProblem()
        .Produces<Player>(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status400BadRequest)
        .WithName("PutPlayer")
        .WithTags("Player");

    app.MapDelete("/player/{id}", [Authorize] async (Guid id, ContextDb context) =>
    {
        var playerDb = await context.Players.FindAsync(id);
        if (playerDb == null) return Results.NotFound();

        context.Players.Remove(playerDb);
        var result = await context.SaveChangesAsync();

        return result > 0
            ? Results.NoContent()
            : Results.BadRequest("An error occurred while saving the changes");
    })
        .Produces<Player>(StatusCodes.Status204NoContent)
        .Produces(StatusCodes.Status404NotFound)
        .Produces(StatusCodes.Status400BadRequest)
        .RequireAuthorization("DeletePlayerClaim")
        .WithName("DeletePlayer")
        .WithTags("Player");
}

#endregion