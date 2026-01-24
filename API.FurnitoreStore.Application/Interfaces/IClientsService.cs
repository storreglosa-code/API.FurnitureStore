using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Interfaces;

public interface IClientsService //TODO: Add logging 
{
    Task<IEnumerable<Client>> GetAllAsync();
    Task<Client> GetByIdAsync(int id);

    Task CreateAsync(Client client);

    Task UpdateAsync(Client client);

    Task DeleteAsync(int id);
}
