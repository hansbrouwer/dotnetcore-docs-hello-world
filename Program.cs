using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    var principalHeader = context.Request.Headers["X-MS-CLIENT-PRINCIPAL"].FirstOrDefault();
    if (string.IsNullOrEmpty(principalHeader))
    {
        // Not authenticated (shouldn't happen if "Require authentication" is on),
        // but just in case:
        context.Response.Redirect("/.auth/login/aad?post_login_redirect_uri=" +
                                  Uri.EscapeDataString(context.Request.GetDisplayUrl()));
        return;
    }

    // Decode and parse the claims from Easy Auth
    var json = Encoding.UTF8.GetString(Convert.FromBase64String(principalHeader));
    using var doc = JsonDocument.Parse(json);
    var claims = doc.RootElement.GetProperty("claims").EnumerateArray()
        .Select(c => new { typ = c.GetProperty("typ").GetString(), val = c.GetProperty("val").GetString() })
        .ToList();

    // Read config from App Settings
    var groupId = Environment.GetEnvironmentVariable("TARGET_GROUP_OBJECT_ID"); // e.g., "4f7e...-guid"
    var memberUrl = Environment.GetEnvironmentVariable("REDIRECT_MEMBER_URL");  // e.g., "/member"
    var nonMemberUrl = Environment.GetEnvironmentVariable("REDIRECT_NONMEMBER_URL"); // e.g., "/no-access"

    // Option A: groups claim (IDs)
    bool inGroup = claims.Any(c => c.typ == "groups" && string.Equals(c.val, groupId, StringComparison.OrdinalIgnoreCase));

    // Option B: roles claim
    // bool inRole = claims.Any(c => c.typ == "roles" && c.val == "MemberOfSpecialGroup");

    string target = inGroup ? memberUrl : nonMemberUrl;
    if (!string.IsNullOrEmpty(target))
    {
        context.Response.Redirect(target);
        return;
    }

    await next();
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
