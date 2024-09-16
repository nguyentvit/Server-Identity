using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Identity.API;
using Identity.Application;
using Identity.Infrastructure;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);
{
    builder.Services
        .AddPresentation()
        .AddInfrastructure(builder.Configuration)
        .AddApplication();

}
var app = builder.Build();


//InitializeDatabase(app);
//Configure(app);

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "1.0");
    options.SwaggerEndpoint("/swagger/v2/swagger.json", "2.0");
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRateLimiter();

app.UseIdentityServer();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();



void InitializeDatabase(IApplicationBuilder app)
{
    using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
    {
        var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        // Kiểm tra và thêm role "Admin" nếu chưa có
        if (!roleManager.RoleExistsAsync("Admin").Result)
        {
            roleManager.CreateAsync(new IdentityRole("Admin")).Wait();
        }

        // Kiểm tra và thêm role "Customer" nếu chưa có
        if (!roleManager.RoleExistsAsync("Customer").Result)
        {
            roleManager.CreateAsync(new IdentityRole("Customer")).Wait();
        }

        serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

        var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        context.Database.Migrate();

        context.Clients.RemoveRange(context.Clients);
        context.IdentityResources.RemoveRange(context.IdentityResources);
        context.ApiScopes.RemoveRange(context.ApiScopes);
        context.SaveChanges();

        if (!context.Clients.Any())
        {
            foreach (var client in IdentityConfig.Get)
            {
                context.Clients.Add(client.ToEntity());
            }
            context.SaveChanges();
        }

        if (!context.IdentityResources.Any())
        {
            foreach (var resource in IdentityConfig.IdentityResources)
            {
                context.IdentityResources.Add(resource.ToEntity());
            }
            context.SaveChanges();
        }

        if (!context.ApiScopes.Any())
        {
            foreach (var resource in IdentityConfig.ApiScopes)
            {
                context.ApiScopes.Add(resource.ToEntity());
            }
            context.SaveChanges();
        }
    }
}

void Configure(IApplicationBuilder app)
{
    var connectionMultiplexer = app.ApplicationServices.GetRequiredService<IConnectionMultiplexer>();
    if (!connectionMultiplexer.IsConnected)
    {
        throw new Exception("Could not connect to Redis.");
    }

    // C?u h?nh ?ng d?ng...
}
