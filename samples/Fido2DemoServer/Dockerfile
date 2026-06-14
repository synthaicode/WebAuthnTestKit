# Independent WebAuthn verification server (Fido2NetLib) for integration tests.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Fido2DemoServer.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish Fido2DemoServer.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_URLS=http://+:8080
ENV FIDO_RPID=localhost
ENV FIDO_ORIGIN=https://localhost
EXPOSE 8080
ENTRYPOINT ["dotnet", "Fido2DemoServer.dll"]
