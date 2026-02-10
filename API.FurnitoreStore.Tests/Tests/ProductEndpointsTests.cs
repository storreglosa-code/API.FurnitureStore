using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using API.FurnitoreStore.Tests.Dtos.Auth;
using System.Net.Http.Headers;

namespace API.FurnitoreStore.Tests.Tests;
public class ProductEndpointsTests
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    private string _token;

    public ProductEndpointsTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
        Authenticate().GetAwaiter().GetResult();
    }

    private async Task Authenticate()
    {
        var loginRequest = new UserLoginRequestDto
        {
            Email = "santi@gmail.com",
            Password = "Abcd1234!"
        };

        var response = await _client.PostAsJsonAsync(
            "/api/Authentication/Login",
            loginRequest
        );

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var loginResponse = await response.Content
            .ReadFromJsonAsync<LoginResponse>();

        loginResponse.Should().NotBeNull();
        loginResponse!.Result.Should().BeTrue();

        _token = loginResponse.Token;

        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _token);
    }

    [Fact]
    public async Task Authenticated_Client_Can_Get_Products()
    {
        var response = await _client.GetAsync("/api/products");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

}
