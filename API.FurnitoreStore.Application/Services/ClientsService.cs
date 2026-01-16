using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using API.FornitureStore.Data;

namespace API.FurnitoreStore.Application.Services;

public class ClientsService(ApplicationDbContext context) : IClientsService

{
    public bool Create(Client client)
    {
        try
        {
            context.Clients.Add(client);
            context.SaveChanges();
            return true;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public bool Delete(int id)
    {
        try
        {
            Client client = context.Clients.Find(id);
            if (client == null)
            {
                return false;
            }
            context.Remove(client);
            context.SaveChanges();
            return true;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public IEnumerable<Client> GetAll()
    {
        try
        {
            var clients = context.Clients.ToList();
            return clients;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public Client GetById(int id)
    {
        try
        {
            var client = context.Clients.Where(c => c.Id == id).FirstOrDefault();
            return client;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public Client Update(Client client)
    {
        try
        {
            var updatedClient = context.Clients.Where(c => c.Id == client.Id).FirstOrDefault();
            if (updatedClient == null)
            {
                throw new Exception("Client not found");
            }
            updatedClient.FirstName = client.FirstName;
            updatedClient.LastName = client.LastName;
            updatedClient.BirthDate = client.BirthDate;
            updatedClient.Phone = client.Phone;
            updatedClient.Address = client.Address;
            context.SaveChanges();
            return updatedClient;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }
}
