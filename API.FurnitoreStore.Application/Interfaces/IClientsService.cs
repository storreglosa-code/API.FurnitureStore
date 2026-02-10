using System.Collections.Generic;
using System.Threading.Tasks;
using API.FurnitoreStore.Application.Dtos.Client;

namespace API.FurnitoreStore.Application.Interfaces;

public interface IClientsService //TODO: Add logging 
{
    Task<IEnumerable<ReadClientDto>> GetAllAsync();
    Task<ReadClientDto?> GetByIdAsync(int id);

    Task<ReadClientDto> CreateAsync(CreateClientDto dto);

    Task UpdateAsync(UpdateClientDto dto);

    Task DeleteAsync(int id);
}
