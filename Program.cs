// https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-oauth2-auth-code-flow
// https://docs.microsoft.com/ja-jp/graph/auth-v2-user

using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// HttpClient
builder.Services.AddHttpClient("AzureAD", httpClient =>
{
    httpClient.BaseAddress = new Uri("https://login.microsoftonline.com/");
});
builder.Services.AddHttpClient("MicrosoftGraph", httpClient =>
{
    httpClient.BaseAddress = new Uri("https://graph.microsoft.com/");
});

// Session
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

var tenantId = app.Configuration["AzureAD:TenantId"].ToString();
var clientId = app.Configuration["AzureAD:ClientId"].ToString();
var clientSecret = app.Configuration["AzureAD:ClientSecret"].ToString();

// トップエンドポイント兼エラー応答エンドポイント
app.MapGet("/", async (HttpContext context) =>
{
    var error = context.Request.Query["error"].ToString();
    var description = context.Request.Query["error_description"].ToString();

    var response = new StringBuilder();
    response.Append("<html lang=\"ja\">");
    response.Append("<head>");
    response.Append("<meta charset=\"UTF-8\">");
    response.Append("</head>");
    response.Append("<body>");
    if (string.IsNullOrWhiteSpace(error) && string.IsNullOrWhiteSpace(description))
    {
        response.Append("<p><a href=\"/login\">Login</a></p>");
        response.Append($"<p><a href=\"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/logout\">Logout</a></p>");
    }
    else
    {
        response.Append("<dl>");
        response.Append($"<dt>Error</dt><dd>{error}</dd>");
        response.Append($"<dt>Error description</dt><dd>{description}</dd>");
        response.Append("</dl>");
    }
    response.Append("</body>");
    response.Append("</html>");
    await context.Response.WriteAsync(response.ToString());
});

// 承認コードの要求
app.MapGet("/login", async (HttpContext context) =>
{
    var redirectUri = Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}/auth-response");
    app.Logger.LogInformation("Redirect Uri: {redirectUri}", redirectUri);

    var scope = Uri.EscapeDataString("offline_access user.read");
    var state = 12345;
    var uri = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize?client_id={clientId}&response_type=code&redirect_uri={redirectUri}&response_mode=query&scope={scope}&state={state}";
    app.Logger.LogInformation("Uri: {uri}", uri);

    context.Session.SetString(nameof(state), state.ToString());
    context.Response.Redirect(uri, true);
    await context.Response.CompleteAsync();
});

// 認証応答エンドポイント
app.MapGet("/auth-response",
    async (
        HttpContext context,
        string code,
        string state,
        [FromQuery(Name = "session_state")] string sessionState) =>
{
    app.Logger.LogDebug("Code: {code}", code);
    app.Logger.LogDebug("State: {state}", state);
    app.Logger.LogDebug("Session state: {sessionState}", sessionState);

    context.Session.SetString(nameof(code), code);

    // var stateInSession = context.Session.GetString(nameof(state));
    // app.Logger.LogInformation("State in session: {stateInSession}", stateInSession);
    // if (!state.Equals(stateInSession, StringComparison.OrdinalIgnoreCase))
    // {
    //     await context.Response.WriteAsync("Invalid state");
    //     return;
    // }

    var response = new StringBuilder();
    response.Append("<html lang=\"ja\">");
    response.Append("<head>");
    response.Append("<meta charset=\"UTF-8\">");
    response.Append("</head>");
    response.Append("<body>");
    response.Append("<dl>");
    response.Append($"<dt>Code</dt><dd>{code}</dd>");
    response.Append($"<dt>State</dt><dd>{state}</dd>");
    response.Append($"<dt>Session state</dt><dd>{sessionState}</dd>");
    response.Append("</dl>");
    response.Append("<p><a href=\"/token\">Get a token</a></p>");
    response.Append("<p><a href=\"/\">Back to top</a></p>");
    response.Append("</body>");
    response.Append("</html>");
    await context.Response.WriteAsync(response.ToString());
});

// トークン管理エンドポイント
app.MapGet("/token",
    async (
        HttpContext context,
        [FromServices] IHttpClientFactory httpClientFactory) =>
{
    var code = context.Session.GetString("code") ?? string.Empty;
    var redirectUri = $"{context.Request.Scheme}://{context.Request.Host}/auth-response";
    var scope = Uri.EscapeDataString("user.read");
    var parameters = new Dictionary<string, string>
    {
        { "client_id", clientId },
        { "scope", scope },
        { "code", code },
        { "redirect_uri", redirectUri },
        { "grant_type", "authorization_code" },
        { "client_secret", clientSecret }
    };
    app.Logger.LogDebug("Parameters: {parameters}", parameters);

    var httpClient = httpClientFactory.CreateClient("AzureAD");
    var httpResponseMessage = await httpClient.PostAsync(
        $"{tenantId}/oauth2/v2.0/token",
        new FormUrlEncodedContent(parameters)
    );

    var response = new StringBuilder();
    response.Append("<html lang=\"ja\">");
    response.Append("<head>");
    response.Append("<meta charset=\"UTF-8\">");
    response.Append("</head>");
    response.Append("<body>");
    if (httpResponseMessage.IsSuccessStatusCode)
    {
        var token = await httpResponseMessage.Content.ReadFromJsonAsync<AzureAdToken>();
        app.Logger.LogDebug("Access token: {accessToken}", token?.access_token);
        app.Logger.LogDebug("Refresh token: {refreshToken}", token?.refresh_token);
        context.Session.SetString(nameof(AzureAdToken.access_token), token?.access_token ?? string.Empty);
        context.Session.SetString(nameof(AzureAdToken.refresh_token), token?.refresh_token ?? string.Empty);

        response.Append("<dl>");
        response.Append($"<dt>Access token</dt><dd>{token?.access_token ?? "(not found)"}</dd>");
        response.Append($"<dt>Refresh token</dt><dd>{token?.refresh_token ?? "(not found)"}</dd>");
        response.Append("</dl>");
        response.Append("<p><a href=\"/me\">Show me</a></p>");
    }
    else
    {
        var error = await httpResponseMessage.Content.ReadAsStringAsync();
        app.Logger.LogError("Could not get an access token. Error: {error}", error);

        response.Append("<dl>");
        response.Append($"<dt>Error</dt><dd>{error}</dd>");
        response.Append("</dl>");
    }
    response.Append("<p><a href=\"/\">Back to top</a></p>");
    response.Append("</body>");
    response.Append("</html>");
    await context.Response.WriteAsync(response.ToString());
});

// プロファイル取得エンドポイント
app.MapGet("/me", async (HttpContext context, [FromServices] IHttpClientFactory httpClientFactory) =>
{
    var accessToken = context.Session.GetString(nameof(AzureAdToken.access_token));
    app.Logger.LogDebug("Access token: {accessToken}", accessToken);

    var httpClient = httpClientFactory.CreateClient("MicrosoftGraph");
    var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "v1.0/me")
    {
        Headers =
        {
            { HeaderNames.Authorization, $"Bearer {accessToken}" }
        }
    };
    var httpResponseMessage = await httpClient.SendAsync(httpRequestMessage);

    var response = new StringBuilder();
    response.Append("<html lang=\"ja\">");
    response.Append("<head>");
    response.Append("<meta charset=\"UTF-8\">");
    response.Append("</head>");
    response.Append("<body>");
    if (httpResponseMessage.IsSuccessStatusCode)
    {
        var user = JsonSerializer.Deserialize<GraphUser>(await httpResponseMessage.Content.ReadAsStringAsync());
        response.Append("<dl>");
        response.Append($"<dt>ID</dt><dd>{user?.id ?? "(not found)"}</dd>");
        response.Append($"<dt>Display name</dt><dd>{user?.displayName ?? "(not found)"}</dd>");
        response.Append($"<dt>Mail</dt><dd>{user?.mail ?? "(not found)"}</dd>");
        response.Append($"<dt>User principal name</dt><dd>{user?.userPrincipalName ?? "(not found)"}</dd>");
        response.Append($"<dt>Given name</dt><dd>{user?.givenName ?? "(not found)"}</dd>");
        response.Append($"<dt>Surname</dt><dd>{user?.surname ?? "(not found)"}</dd>");
        response.Append("</dl>");
    }
    else
    {
        response.Append("<p>Who am I?</p>");
    }
    response.Append("<p><a href=\"/\">Back to top</a></p>");
    response.Append("</body>");
    response.Append("</html>");
    await context.Response.WriteAsync(response.ToString());
});

// Session
app.UseSession();

app.Run();

public class AzureAdToken
{
    public string? token_type { get; set; }
    public string? scope { get; set; }
    public int expires_in { get; set; }
    public int ext_expires_in { get; set; }
    public string? access_token { get; set; }
    public string? refresh_token { get; set; }
}

public class GraphUser
{
    public string? id { get; set; }
    public string? displayName { get; set; }
    public string? mail { get; set; }
    public string? userPrincipalName { get; set; }
    public string? givenName { get; set; }
    public string? surname { get; set; }
}