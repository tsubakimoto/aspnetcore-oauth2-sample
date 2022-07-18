# aspnetcore-oauth2-sample

## Run
```
git clone https://github.com/tsubakimoto/aspnetcore-oauth2-sample.git
cd aspnetcore-oauth2-sample
dotnet user-secrets set "AzureAD:TenantId" "put-your-azure-ad-tenant-id"
dotnet user-secrets set "AzureAD:ClientId" "put-your-azure-ad-client-id"
dotnet user-secrets set "AzureAD:ClientSecret" "put-your-azure-ad-client-secret"
dotnet run
```

## References
[Microsoft identity platform and OAuth 2.0 authorization code flow - Microsoft Entra | Microsoft Docs](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)

[Get access on behalf of a user - Microsoft Graph | Microsoft Docs](https://docs.microsoft.com/en-us/graph/auth-v2-user)
