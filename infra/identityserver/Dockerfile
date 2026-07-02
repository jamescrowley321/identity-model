FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY IdentityServer.csproj .
RUN dotnet restore IdentityServer.csproj
COPY . .
RUN dotnet publish IdentityServer.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# curl for the compose healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["dotnet", "IdentityServer.dll"]
