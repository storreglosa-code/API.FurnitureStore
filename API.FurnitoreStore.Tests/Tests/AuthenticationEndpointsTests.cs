using API.FurnitoreStore.Tests.Dtos.Auth;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;

namespace API.FurnitoreStore.Tests.Tests;
public class AuthenticationEndpointsTests
 : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public AuthenticationEndpointsTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Login_Returns_Token()
    {
        // Arrange
        var loginRequest = new UserLoginRequestDto
        {
            Email = "santi@gmail.com",
            Password = "Abcd1234!"
        };

        // Act
        var response = await _client.PostAsJsonAsync(
            "/api/Authentication/Login",
            loginRequest
        );

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var loginResponse = await response.Content
            .ReadFromJsonAsync<LoginResponse>();

        loginResponse.Should().NotBeNull();
        loginResponse!.Result.Should().BeTrue();
        loginResponse.Token.Should().NotBeNullOrWhiteSpace();
    }
}
