using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net;

namespace API.FurnitoreStore.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ClientsController(IClientsService clientService) : ControllerBase //TODO: Add logging and call async methods
{

    [HttpGet]
    public async Task<IActionResult> GetClients ()
    {
        var clients = await clientService.GetAllAsync();
        return Ok(clients);
    }

    [HttpGet ("{id}")]
    public async Task<IActionResult> GetDetails(int id) 
    {
        var client = await clientService.GetByIdAsync(id);
        if (client == null) return NotFound(); 
        return Ok(client);
    }

    [HttpPost]
    public async Task<IActionResult> Post (Client client) 
    {
        await clientService.CreateAsync(client);
        return CreatedAtAction("Post", client.Id, client);
    }

    [HttpPut]
    public async Task<IActionResult> Update(Client client)
    { 
        await clientService.UpdateAsync(client);
        return NoContent();
    }

    [HttpDelete]
    public async Task<IActionResult> Delete(int id)
    { 
        await clientService.DeleteAsync(id);
        return NoContent();
    }
}
