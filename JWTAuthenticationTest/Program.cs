using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
      .AddCookie(opts =>
      {
          opts.Cookie.Name = $".appname.auth";
          opts.AccessDeniedPath = "/AccessDenied";
          opts.LoginPath = "/Login";
          opts.SlidingExpiration = true;
      })
      .AddJwtBearer(options =>
      {
          options.RequireHttpsMetadata = false;
          options.SaveToken = true;
          options.TokenValidationParameters = new TokenValidationParameters
          {
              ValidateIssuer = false,
              ValidateAudience = false,
              ValidateLifetime = true,
              ValidateIssuerSigningKey = true,
              IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String("superSecretKey@345-superSecretKey@345_superSecretKey@345-superSecretKey@345?")),
              ClockSkew = TimeSpan.FromSeconds(5)
          };
      });

builder.Services.AddSession(options =>
{
    options.Cookie.Name = $"appname.session";
    options.IdleTimeout = TimeSpan.FromMinutes(180);
    options.Cookie.IsEssential = true;
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();