# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copiar archivos del repositorio
COPY . .

# Restaurar dependencias
RUN dotnet restore API.FurnitoreStore.API/API.FurnitoreStore.API.csproj

# Publicar en modo Release
RUN dotnet publish API.FurnitoreStore.API/API.FurnitoreStore.API.csproj -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish .

EXPOSE 8080
EXPOSE 80

ENTRYPOINT ["dotnet", "API.FurnitoreStore.API.dll"]