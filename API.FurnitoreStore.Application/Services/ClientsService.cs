using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using API.FornitureStore.Data;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitoreStore.Application.Services;

public class ClientsService(ApplicationDbContext context) : IClientsService //TODO: Add logging and async methods

{
    public async Task<IEnumerable<Client>> GetAllAsync()
    {
        try
        {
            var clients = await context.Clients
                                       .AsNoTracking()
                                       .ToListAsync();
            return clients;
        }
        catch (Exception ex)
        {
            throw new Exception("Error al traer la información", ex);
        }
    }

    public async Task<Client> GetByIdAsync(int id)
    {
        try
        {
            Client? client = await context.Clients
                                          .AsNoTracking()
                                          .FirstOrDefaultAsync(c => c.Id == id);
            return client;
        }
        catch (Exception ex)
        {
            throw new Exception("Error al traer la información", ex);
        }
    }

    public async Task CreateAsync(Client client) 
    {
        try
        {
            await context.Clients.AddAsync(client);
            await context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error al crear cliente",ex);
        }
    }

    public async Task DeleteAsync(int id)
    {
        try
        {
            Client? client = await context.Clients.FindAsync(id);
            if (client == null)
            {
                throw new Exception("Error al encontrar cliente");
            }
            context.Remove(client);
            await context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error al intentar eliminar cliente",ex);
        }
    }

  
    public async Task UpdateAsync (Client client)
    {
        try
        {
            Client? clientToUpdate = await context.Clients.FindAsync(client.Id);
            if (clientToUpdate == null)
            {
                throw new Exception("Client not found");
            }
            clientToUpdate.BirthDate = client.BirthDate;
            clientToUpdate.Phone = client.Phone;
            clientToUpdate.Address = client.Address;
            clientToUpdate.FirstName = client.FirstName;
            clientToUpdate.LastName = client.LastName;
            await context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            throw new Exception("Error al actualizar cliente", ex);
        }
    }
}
