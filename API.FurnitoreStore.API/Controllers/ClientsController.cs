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
public class ClientsController(IClientsService clientService) : ControllerBase
{
    [HttpGet]
    public async Task<IEnumerable<Client>> GetClients ()
    {
        return clientService.GetAll();
    }

    [HttpGet ("{id}")]
    public async Task<IActionResult> GetDetails(int id) 
    {
        var client = clientService.GetById(id);
        if (client == null) return NotFound(); 
        return Ok(client);
    }

    [HttpPost]
    public async Task<IActionResult> Post (Client client) 
    {
        clientService.Create(client);
        return CreatedAtAction("Post", client.Id, client);
    }

    [HttpPut]
    public async Task<IActionResult> Put(Client client)
    { 
        clientService.Update(client);
        return NoContent();
    }

    [HttpDelete]
    public async Task<IActionResult> Delete(int id)
    { 
        clientService.Delete(id);
        return NoContent();
    }
}
