using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Application.Dtos.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.FurnitoreStore.API.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ClientsController(IClientsService _clientsService) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<ReadClientDto>>> GetClients()
    {
        var clients = await _clientsService.GetAllAsync();
        return Ok(clients);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<ReadClientDto>> GetDetails(int id)
    {
        var client = await _clientsService.GetByIdAsync(id);
        if (client == null) return NotFound();
        return Ok(client);
    }

    [HttpPost]
    public async Task<ActionResult<ReadClientDto>> Post(CreateClientDto createDto)
    {
        if (createDto == null) return BadRequest();

        var created = await _clientsService.CreateAsync(createDto);
        return CreatedAtAction(nameof(GetDetails), new { id = created.Id }, created);
    }

    [HttpPut]
    public async Task<IActionResult> Update(UpdateClientDto updateDto)
    {
        if (updateDto == null) return BadRequest();

        await _clientsService.UpdateAsync(updateDto);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        if (id <= 0) return BadRequest();

        await _clientsService.DeleteAsync(id);
        return NoContent();
    }
}
